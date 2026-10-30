package fuzz

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"golang.org/x/net/html"
)

// Preflight and postflight (-preflight FILE, -postflight FILE) are ffuf's:
// raw request files sent before and after each fuzzing request, with values
// read from their answers (a CSRF token, a session) put into the request. The
// design and the variable sources follow ffuf's runner (MIT licence).
//
// Unlike ffuf there is no way to let a captured value choose the host: the
// answers come from the target, and the request carries its credentials. A
// value that would change the scheme, host or port of a request is refused,
// and every flight request is held to the scope, the budget and the pace.

// VarSources are the places -preflight-var-auto reads a value from, in the
// order "auto" tries them.
var VarSources = []string{"form", "meta", "cookie", "header"}

// FlightVar is a value to read from a flight's answer and the name that
// stands for it in later requests: the first group of Regex (searched in the
// body, then the headers), or the form field, meta tag, cookie or header Key.
type FlightVar struct {
	Name   string
	Regex  *regexp.Regexp
	Source string // "auto" or one of VarSources; empty with Regex
	Key    string
}

// FlightStep is one request file and what is read from its answer.
type FlightStep struct {
	File string
	Vars []FlightVar
	req  flightRequest
}

type flightRequest struct {
	method, path, host string
	headers            map[string]string
	body               []byte
}

// ParseFlightVar reads "NAME:regex" (auto false) or "NAME:key" and
// "NAME:[source]key" (auto true), splitting at the first colon.
func ParseFlightVar(spec string, auto bool) (FlightVar, error) {
	i := strings.IndexByte(spec, ':')
	if i <= 0 || i == len(spec)-1 {
		return FlightVar{}, fmt.Errorf("%q: want NAME:%s with a name and a value", spec, map[bool]string{true: "key or NAME:[form|meta|cookie|header]key", false: "regex"}[auto])
	}
	v := FlightVar{Name: spec[:i]}
	rest := spec[i+1:]
	if !auto {
		re, err := regexp.Compile(rest)
		if err != nil {
			return v, fmt.Errorf("%q: %v", spec, err)
		}
		if re.NumSubexp() < 1 {
			return v, fmt.Errorf("%q: the regexp needs a group (...) around the value to keep", spec)
		}
		v.Regex = re
		return v, nil
	}
	v.Source, v.Key = "auto", rest
	if strings.HasPrefix(rest, "[") {
		end := strings.IndexByte(rest, ']')
		if end < 0 {
			return v, fmt.Errorf("%q: unterminated source, want [form|meta|cookie|header]key", spec)
		}
		v.Source, v.Key = rest[1:end], rest[end+1:]
		if !contains(VarSources, v.Source) {
			return v, fmt.Errorf("%q: unknown source %q, want one of %s", spec, v.Source, strings.Join(VarSources, ", "))
		}
	}
	if v.Key == "" {
		return v, fmt.Errorf("%q: the key is empty", spec)
	}
	return v, nil
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// Flights are the requests around each fuzzing request.
type Flights struct {
	Pre, Post []FlightStep
	PerThread bool // -preflight-mode per-thread: the preflights run once for each thread, not for each request
	Ignore    bool // -preflight-error ignore: a failed flight is noted and the request goes on without its values
}

// Load reads the request files, so a file that cannot be read is found
// before the first request. main is the template: headers it sets (-H, -b)
// are sent with each flight request too, as in ffuf, except those holding a
// keyword, which have no value outside a fuzzing request.
func (f *Flights) Load(main Template, keywords []string) error {
	for _, steps := range [][]FlightStep{f.Pre, f.Post} {
		for i := range steps {
			r, err := readFlightRequest(steps[i].File)
			if err != nil {
				return err
			}
			steps[i].req = r
			for _, v := range steps[i].Vars {
				if contains(keywords, v.Name) {
					return fmt.Errorf("the variable %s is also a wordlist keyword", v.Name)
				}
			}
		}
	}
	return nil
}

func readFlightRequest(path string) (flightRequest, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return flightRequest{}, fmt.Errorf("%s: %v", path, err)
	}
	r := bufio.NewReader(bytes.NewReader(raw))
	line, _ := r.ReadString('\n')
	parts := strings.SplitN(strings.TrimSpace(line), " ", 3)
	if len(parts) < 2 {
		return flightRequest{}, fmt.Errorf("%s: the first line is not METHOD PATH HTTP/1.1", path)
	}
	fr := flightRequest{method: parts[0], path: parts[1], headers: map[string]string{}}
	for {
		l, err := r.ReadString('\n')
		l = strings.TrimRight(l, "\r\n")
		if l == "" {
			break
		}
		if k, v, ok := strings.Cut(l, ":"); ok {
			k, v = strings.TrimSpace(k), strings.TrimSpace(v)
			switch {
			case strings.EqualFold(k, "content-length"):
			case strings.EqualFold(k, "host"):
				fr.host = v
			default:
				fr.headers[textproto.CanonicalMIMEHeaderKey(k)] = v
			}
		}
		if err != nil {
			break
		}
	}
	body, _ := io.ReadAll(r)
	fr.body = bytes.TrimRight(body, "\r\n")
	return fr, nil
}

// Exchanger sends one HTTP request as the run's own: scope aside, it is
// counted, paced and in the ledger.
type Exchanger interface {
	Exchange(ctx context.Context, req *http.Request) (*http.Response, error)
}

type lane struct {
	init bool
	vars map[string]string
}

type flightSender struct {
	Sender
	fl       *Flights
	ex       Exchanger
	template Template
	keywords []string
	allow    func(host string) bool
	lanes    sync.Pool

	mu     sync.Mutex
	failed int
	first  string
	ran    atomic.Int64
	pins   sync.Map // *FlightVar -> source an "auto" variable resolved to
}

// WithFlights makes s send each request with its flights around it. s must
// also be an Exchanger. allow says whether a host is in scope.
func WithFlights(s Sender, fl *Flights, main Template, keywords []string, allow func(string) bool) (Sender, error) {
	ex, ok := s.(Exchanger)
	if !ok {
		return nil, fmt.Errorf("this sender cannot send flights")
	}
	return &flightSender{Sender: s, fl: fl, ex: ex, template: main, keywords: keywords, allow: allow}, nil
}

// Replay passes on to the wrapped sender.
func (f *flightSender) Replay(ctx context.Context, req *Request) error {
	if r, ok := f.Sender.(Replayer); ok {
		return r.Replay(ctx, req)
	}
	return nil
}

// FlightStats says how many flight requests failed, and the first error.
func FlightStats(s Sender) (ran int64, failed int, first string) {
	f, ok := s.(*flightSender)
	if !ok {
		return 0, 0, ""
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.ran.Load(), f.failed, f.first
}

func (f *flightSender) fail(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failed++
	if f.first == "" {
		f.first = err.Error()
	}
}

func (f *flightSender) Send(ctx context.Context, req *Request, keepBody bool) (*Response, error) {
	var applied map[string]string
	if len(f.fl.Pre) > 0 {
		vars, release, err := f.preflights(ctx)
		defer release()
		if err != nil {
			f.fail(err)
			return nil, fmt.Errorf("preflight: %w", err)
		}
		if len(vars) > 0 {
			if err := f.apply(req, vars); err != nil {
				f.fail(err)
				return nil, err
			}
			applied = vars
		}
	}
	resp, err := f.Sender.Send(ctx, req, keepBody)
	if err == nil && len(f.fl.Post) > 0 {
		if _, perr := f.chain(ctx, f.fl.Post, applied); perr != nil {
			f.fail(perr) // the answer stands; the failure is said in the summary
		}
	}
	return resp, err
}

func (f *flightSender) preflights(ctx context.Context) (map[string]string, func(), error) {
	if !f.fl.PerThread {
		v, err := f.chain(ctx, f.fl.Pre, nil)
		return v, func() {}, err
	}
	l, _ := f.lanes.Get().(*lane)
	if l == nil {
		l = &lane{}
	}
	release := func() { f.lanes.Put(l) }
	if !l.init {
		v, err := f.chain(ctx, f.fl.Pre, nil)
		if err != nil {
			return nil, release, err
		}
		l.vars, l.init = v, true
	}
	return l.vars, release, nil
}

// apply puts the variables into the request's URL, header values and body,
// and refuses it when that moved the request to another scheme, host or port.
func (f *flightSender) apply(req *Request, vars map[string]string) error {
	rep := varsReplacer(vars)
	before, _ := authority(req.URL)
	hostBefore := hostHeaderOf(req)
	req.URL = rep.Replace(req.URL)
	req.Data = rep.Replace(req.Data)
	for i := range req.Headers {
		req.Headers[i].Value = rep.Replace(req.Headers[i].Value)
	}
	if after, _ := authority(req.URL); after != before || hostHeaderOf(req) != hostBefore {
		return fmt.Errorf("a value read from the target's answer would change the request's host (%s to %s): refused; a captured value cannot choose where requests go", before, after)
	}
	return nil
}

func authority(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	return u.Scheme + "://" + u.Host, nil
}

func varsReplacer(vars map[string]string) *strings.Replacer {
	names := make([]string, 0, len(vars))
	for k := range vars {
		names = append(names, k)
	}
	sort.Slice(names, func(i, j int) bool {
		if len(names[i]) != len(names[j]) {
			return len(names[i]) > len(names[j])
		}
		return names[i] < names[j]
	})
	pairs := make([]string, 0, 2*len(names))
	for _, n := range names {
		pairs = append(pairs, n, vars[n])
	}
	return strings.NewReplacer(pairs...)
}

// chain sends the steps in order, each with what the earlier ones gave.
func (f *flightSender) chain(ctx context.Context, steps []FlightStep, seed map[string]string) (map[string]string, error) {
	vars := make(map[string]string, len(seed))
	for k, v := range seed {
		vars[k] = v
	}
	for _, st := range steps {
		err := f.step(ctx, st, vars)
		if err != nil {
			if f.fl.Ignore && ctx.Err() == nil {
				f.fail(err)
				return vars, nil
			}
			return nil, err
		}
	}
	return vars, nil
}

func (f *flightSender) step(ctx context.Context, st FlightStep, vars map[string]string) error {
	hr, err := f.build(ctx, st, vars)
	if err != nil {
		return err
	}
	f.ran.Add(1)
	resp, err := f.ex.Exchange(ctx, hr)
	if err != nil {
		return fmt.Errorf("%s: %w", st.File, err)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxBody+1))
	resp.Body.Close()
	if err != nil {
		return fmt.Errorf("%s: reading the answer: %w", st.File, err)
	}
	fr := &flightAnswer{body: body, header: resp.Header}
	for i := range st.Vars {
		v := &st.Vars[i]
		val, err := f.extract(v, fr)
		if err != nil {
			return fmt.Errorf("%s: variable %s: %w", st.File, v.Name, err)
		}
		if strings.ContainsAny(val, "\r\n\x00") {
			return fmt.Errorf("%s: variable %s holds a control character: refused", st.File, v.Name)
		}
		vars[v.Name] = val
	}
	return nil
}

// build makes the HTTP request of a step: the main template's headers, then
// the file's, variables put in, held to the destination the file names.
func (f *flightSender) build(ctx context.Context, st FlightStep, vars map[string]string) (*http.Request, error) {
	r := st.req
	method, path, host, body := r.method, r.path, r.host, string(r.body)
	headers := map[string]string{}
	for _, h := range f.template.Headers {
		if strings.EqualFold(h.Name, "Host") || hasKeyword(h.Name+h.Value, f.keywords) {
			continue
		}
		headers[textproto.CanonicalMIMEHeaderKey(h.Name)] = h.Value
	}
	for k, v := range r.headers {
		headers[k] = v
	}
	scheme0, auth0 := f.destination(path, host)
	if len(vars) > 0 {
		rep := varsReplacer(vars)
		method, path, host, body = rep.Replace(method), rep.Replace(path), rep.Replace(host), rep.Replace(body)
		for k, v := range headers {
			headers[k] = rep.Replace(v)
		}
	}
	scheme, auth := f.destination(path, host)
	if scheme != scheme0 || auth != auth0 {
		return nil, fmt.Errorf("%s: a value read from the target's answer would move this request from %s://%s to %s://%s: refused; a captured value cannot choose where requests go", st.File, scheme0, auth0, scheme, auth)
	}
	var raw string
	if strings.HasPrefix(path, "http") {
		raw = path
	} else {
		tu, err := url.Parse(f.template.URL)
		if err != nil || tu.Scheme == "" {
			scheme = "https"
		} else {
			scheme = tu.Scheme
			if host == "" {
				host = tu.Host
			}
		}
		if hasKeyword(host, f.keywords) {
			return nil, fmt.Errorf("%s: its host %q holds a wordlist keyword: give the file a Host header or an absolute URL", st.File, host)
		}
		raw = scheme + "://" + host + path
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("%s: %q is not a URL", st.File, raw)
	}
	if f.allow != nil && !f.allow(u.Hostname()) {
		return nil, fmt.Errorf("%s: %s is outside the scope: not sent (-allow adds it)", st.File, u.Hostname())
	}
	hr, err := http.NewRequestWithContext(ctx, method, raw, strings.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("%s: %v", st.File, err)
	}
	if host != "" {
		hr.Host = host
	}
	for k, v := range headers {
		hr.Header.Set(k, v)
	}
	return hr, nil
}

// destination is the scheme and host a flight request goes to, as its file
// and the template say.
func (f *flightSender) destination(path, host string) (scheme, auth string) {
	if strings.HasPrefix(path, "http") {
		u, err := url.Parse(path)
		if err != nil {
			return "", ""
		}
		return u.Scheme, u.Host
	}
	scheme = "https"
	if tu, err := url.Parse(f.template.URL); err == nil && tu.Scheme != "" {
		scheme = tu.Scheme
		if host == "" {
			host = tu.Host
		}
	}
	return scheme, host
}

func hasKeyword(s string, keywords []string) bool {
	for _, k := range keywords {
		if strings.Contains(s, k) {
			return true
		}
	}
	return false
}

// flightAnswer is what a variable is read from.
type flightAnswer struct {
	body   []byte
	header http.Header
	doc    *html.Node
	parsed bool
}

func (a *flightAnswer) document() *html.Node {
	if !a.parsed {
		a.doc, _ = html.Parse(bytes.NewReader(a.body))
		a.parsed = true
	}
	return a.doc
}

func (f *flightSender) extract(v *FlightVar, a *flightAnswer) (string, error) {
	if v.Regex != nil {
		m := v.Regex.FindSubmatch(a.body)
		if len(m) < 2 {
			var hb bytes.Buffer
			a.header.Write(&hb)
			m = v.Regex.FindSubmatch(hb.Bytes())
		}
		if len(m) < 2 {
			return "", fmt.Errorf("the regexp %q did not capture a value in the answer's body or headers", v.Regex)
		}
		return string(m[1]), nil
	}
	source := v.Source
	if source == "auto" {
		if p, ok := f.pins.Load(v); ok {
			source = p.(string)
		}
	}
	if source != "auto" {
		if val, ok := a.lookup(source, v.Key); ok {
			return val, nil
		}
		return "", fmt.Errorf("[%s]%s is not in the answer", source, v.Key)
	}
	var picked, val string
	for _, s := range VarSources {
		x, ok := a.lookup(s, v.Key)
		if !ok {
			continue
		}
		if picked == "" {
			picked, val = s, x
		} else if x != val {
			return "", fmt.Errorf("%q is in both [%s] and [%s] with different values: pin one with NAME:[%s]%s", v.Key, picked, s, picked, v.Key)
		}
	}
	if picked == "" {
		return "", fmt.Errorf("%q is in no form, meta tag, cookie or header of the answer", v.Key)
	}
	f.pins.Store(v, picked)
	return val, nil
}

func (a *flightAnswer) lookup(source, key string) (string, bool) {
	switch source {
	case "header":
		if vs := a.header.Values(key); len(vs) > 0 {
			return vs[0], true
		}
	case "cookie":
		val, found := "", false
		for _, c := range (&http.Response{Header: a.header}).Cookies() {
			if c.Name == key {
				val, found = c.Value, c.MaxAge >= 0
			}
		}
		return val, found
	case "form":
		return formValue(a.document(), key)
	case "meta":
		return metaValue(a.document(), key)
	}
	return "", false
}

func attr(n *html.Node, name string) (string, bool) {
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, name) {
			return a.Val, true
		}
	}
	return "", false
}

func walk(n *html.Node, f func(*html.Node) bool) bool {
	if n == nil {
		return false
	}
	if n.Type == html.ElementNode && !f(n) {
		return false
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if !walk(c, f) {
			return false
		}
	}
	return true
}

func textOf(n *html.Node) string {
	var b strings.Builder
	var rec func(*html.Node)
	rec = func(n *html.Node) {
		if n.Type == html.TextNode {
			b.WriteString(n.Data)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			rec(c)
		}
	}
	rec(n)
	return b.String()
}

// formValue is what a browser would submit for the first control called key:
// an input's value (an unchecked radio or checkbox is skipped), a textarea's
// text, a select's selected or first option.
func formValue(doc *html.Node, key string) (val string, found bool) {
	walk(doc, func(n *html.Node) bool {
		if name, _ := attr(n, "name"); name != key {
			return true
		}
		switch n.Data {
		case "input":
			t, _ := attr(n, "type")
			t = strings.ToLower(t)
			if _, checked := attr(n, "checked"); (t == "radio" || t == "checkbox") && !checked {
				return true
			}
			val, _ = attr(n, "value")
		case "textarea":
			val = textOf(n)
		case "select":
			var first, sel *html.Node
			walk(n, func(o *html.Node) bool {
				if o.Data == "option" {
					if first == nil {
						first = o
					}
					if _, s := attr(o, "selected"); s && sel == nil {
						sel = o
					}
				}
				return true
			})
			if sel == nil {
				sel = first
			}
			if sel != nil {
				if v, ok := attr(sel, "value"); ok {
					val = v
				} else {
					val = strings.TrimSpace(textOf(sel))
				}
			}
		default:
			return true
		}
		found = true
		return false
	})
	return val, found
}

// metaValue is the content of the first <meta name=key> (Rails, Laravel and
// Spring publish their CSRF token so).
func metaValue(doc *html.Node, key string) (val string, found bool) {
	walk(doc, func(n *html.Node) bool {
		if n.Data != "meta" {
			return true
		}
		if name, _ := attr(n, "name"); strings.EqualFold(name, key) {
			val, _ = attr(n, "content")
			found = true
			return false
		}
		return true
	})
	return val, found
}
