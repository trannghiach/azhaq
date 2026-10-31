package main

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mfonda/simhash"

	"github.com/trannghiach/azhaq/engine"
	"github.com/trannghiach/azhaq/internal/collectors/httpcol"
	"github.com/trannghiach/azhaq/internal/egress"
	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/internal/fingerprint"
	"github.com/trannghiach/azhaq/internal/normalize"
	"github.com/trannghiach/azhaq/internal/probefilter"
	"github.com/trannghiach/azhaq/types"
)

// probeOut prints web services as azhaq-http reports them, like httpx.
type probeOut struct {
	w    *writer
	c    *common
	pf   *probeFlags
	set  *probefilter.Set
	spec *httpcol.Spec

	mu       sync.Mutex
	cdn      map[string][2]string
	cnames   map[string][]string
	seen     map[string]bool
	input    map[string][]string // seed key → the targets as given (two lines can be one seed)
	order    []string            // the targets as given, in order
	answered map[string]bool     // target as given → a row was printed or dropped by a filter
	dropped  int                 // rows a matcher or filter left out
	condErr  error               // the first condition that could not be evaluated
	condErrs int
	sums     []uint64       // simhashes of the rows printed, for -fd
	sent     map[string]int // methods other than GET sent, rows answered
	cut      int            // redirects not followed because they leave the site
	asns     sync.Map       // address → *asnInfo
	extra    []rowSink      // -oa
	store    *respStore
	held     []heldRow                 // rows kept until the run ends (-ss)
	shots    map[string]map[string]any // screenshots by URL
	displays bool                      // a display flag was given
}

type heldRow struct {
	row map[string]any
	r   engine.ProbeRow
	ev  *httpcol.Evidence
}

// rowSink gets every row printed, in its own format.
type rowSink struct {
	w      io.Writer
	format string // text, json, csv, md
	cw     *csv.Writer
}

// displayed says a flag chose what the text line holds.
func (p *probeFlags) displayed() bool {
	return p.sc || p.cl || p.ct || p.location || p.title || p.td || p.server || p.ws || p.method || p.ip || p.cname ||
		p.asn || p.cdn || p.rt || p.lc || p.wc || p.tlsGrab || p.jarm || p.http2 || p.pipeline || p.vhost ||
		p.hash != "" || p.preview > 0 || len(p.extractRe) > 0 || p.extractPreset != ""
}

func (p *probeOut) see(ent types.Entity, o types.Observation) {
	switch o.Collector {
	case "azhaq-dns":
		m := payloadOf(o)
		fqdn, _ := m["fqdn"].(string)
		name, _ := m["cdn"].(string)
		kind, _ := m["cdn_type"].(string)
		p.mu.Lock()
		if fqdn != "" && name != "" {
			p.cdn[fqdn] = [2]string{name, kind}
		}
		if cn := strs(m["cnames"]); len(cn) > 0 && fqdn != "" {
			p.cnames[fqdn] = cn
		}
		p.mu.Unlock()
	case "azhaq-http":
		r, ok := engine.ProbeRowOf(o)
		if !ok {
			return
		}
		m := payloadOf(o)
		p.mu.Lock()
		seenKey := ent.Key + "\x00" + o.Source // two inputs that reach one URL each report it
		dup := p.seen[seenKey]
		p.seen[seenKey] = true
		host := normalize.HostFromURL(r.URL)
		c, known := p.cdn[host]
		cn := p.cnames[host]
		p.mu.Unlock()
		if dup {
			return
		}
		var addrs []string
		if net.ParseIP(host) == nil {
			addrs = egress.Resolve(context.Background(), host) // the answer HTTP connected with
		}
		if !known {
			for _, a := range append([]string{r.IP}, addrs...) {
				if name, kind := fingerprint.Network(net.ParseIP(a)); name != "" {
					c = [2]string{name, kind}
					break
				}
			}
		}
		r.CDN, r.CDNType = c[0], c[1]
		ins := p.input[ent.Key]
		if len(ins) == 0 {
			ins = []string{ent.Key}
		}
		ev, _ := httpcol.TakeEvidence(o.Source)
		// A row for each line that gave this seed (http://h and http://h/).
		for _, in := range ins {
			row := p.row(r, m, in, addrs, cn, ev)
			p.mu.Lock()
			p.answered[in] = true
			p.mu.Unlock()
			if !p.keep(row, r, ev) {
				continue
			}
			if p.pf.ss {
				p.mu.Lock()
				p.held = append(p.held, heldRow{row, r, ev})
				p.mu.Unlock()
				continue
			}
			p.emit(row, r, ev)
		}
	case "azhaq-shots":
		if o.Kind == "screenshot" {
			p.mu.Lock()
			p.shots[ent.Key] = payloadOf(o)
			if u, _ := payloadOf(o)["url"].(string); u != "" {
				p.shots[u] = payloadOf(o)
			}
			p.mu.Unlock()
		}
	}
}

// flushHeld prints the rows kept for -ss, each with its screenshot.
func (p *probeOut) flushHeld() {
	for _, h := range p.held {
		for _, k := range []string{fmt.Sprint(h.row["url"]), h.r.URL, h.r.URL + "/", fmt.Sprint(h.row["input"]), fmt.Sprint(h.row["host"])} {
			if sh := p.shots[k]; sh != nil {
				if f, _ := sh["file"].(string); f != "" {
					abs, _ := filepath.Abs(f)
					h.row["screenshot_path"] = abs
					if rel, err := filepath.Rel(filepath.Join(probeDir(p.pf.srd), "screenshot"), f); err == nil {
						h.row["screenshot_path_rel"] = rel
					}
				}
				break
			}
		}
		p.emit(h.row, h.r, h.ev)
	}
	p.held = nil
}

// row is the httpx -json row of an answer.
func (p *probeOut) row(r engine.ProbeRow, m map[string]any, input string, addrs, cnames []string, ev *httpcol.Evidence) map[string]any {
	status := r.Status
	chainCodes := hopStatuses(m)
	if p.pf.follow && r.FinalStatus != 0 {
		status = r.FinalStatus
	}
	u, _ := url.Parse(r.URL)
	host, port, scheme, path := "", "", "", "/"
	if u != nil {
		host, scheme = u.Hostname(), u.Scheme
		port = u.Port()
		if port == "" {
			port = map[string]string{"http": "80", "https": "443"}[scheme]
		}
		if path = u.RequestURI(); path == "" {
			path = "/"
		}
	}
	if input == "" {
		input = host
	}
	// Through a proxy no connection reaches the target, so no remote address
	// is known: a literal IP is its own, a name's is the one it resolves to.
	if r.IP == "" {
		if net.ParseIP(host) != nil {
			r.IP = host
		} else if len(addrs) > 0 {
			r.IP = addrs[0]
		}
	}
	if len(addrs) == 0 && r.IP != "" {
		addrs = []string{r.IP}
	}
	var a, aaaa []string
	for _, ip := range addrs {
		if strings.Contains(ip, ":") {
			aaaa = append(aaaa, ip)
		} else {
			a = append(a, ip)
		}
	}
	method, _ := m["method"].(string)
	if method == "" {
		method = "GET"
	}
	elapsed := time.Duration(r.MS) * time.Millisecond
	if ns, ok := m["elapsed_ns"].(float64); ok {
		elapsed = time.Duration(ns)
	}
	shown := r.URL
	if given, ok := urlAsGiven(input, r.URL); ok {
		shown = given // httpx prints a URL input as it was given: slash, query and fragment
	} else if u != nil && u.Path == "/" && u.RawQuery == "" {
		shown = strings.TrimSuffix(r.URL, "/") // a bare host: httpx prints the front page without its slash
	}
	if u != nil && p.pf.ldp && u.Port() == "" {
		shown = strings.Replace(shown, "://"+u.Host, "://"+net.JoinHostPort(u.Hostname(), port), 1)
	}
	out := map[string]any{
		"timestamp": time.Now().Format(time.RFC3339Nano), "url": shown, "input": input,
		"host": host, "host_ip": r.IP, "port": port, "scheme": scheme, "path": path, "method": method,
		"status_code": status, "content_length": r.Length, "words": r.Words, "lines": r.Lines,
		"time": elapsed.String(), "a": a, "failed": false,
	}
	if len(aaaa) > 0 {
		out["aaaa"] = aaaa
	}
	for k, v := range map[string]string{"title": r.Title, "webserver": r.Server, "content_type": part(r.ContentType), "location": part(r.Location)} {
		if v != "" {
			out[k] = v
		}
	}
	if len(r.Tech) > 0 {
		out["tech"] = r.Tech
	}
	if r.Favicon != "" {
		out["favicon"] = r.Favicon
		for _, k := range []string{"favicon_md5", "favicon_path", "favicon_url"} {
			if v, _ := m[k].(string); v != "" {
				out[k] = v
			}
		}
	}
	if r.CDN != "" {
		out["cdn"], out["cdn_name"], out["cdn_type"] = r.CDNType != "cloud", r.CDN, r.CDNType
	}
	if len(cnames) > 0 {
		out["cname"] = cnames
	}
	if probePool != nil {
		out["resolvers"] = probePool.Resolvers()
	}
	if p.pf.follow && len(chainCodes) > 0 {
		if hops, _ := m["hops"].([]any); len(hops) > 0 {
			if h, ok := hops[len(hops)-1].(map[string]any); ok && h["location"] != nil && h["location"] != "" {
				if st := numOf(h["status"]); st >= 300 && st < 400 {
					p.mu.Lock()
					p.cut++
					p.mu.Unlock()
				}
			}
		}
	}
	if len(chainCodes) > 1 {
		out["chain_status_codes"] = chainCodes
		if r.FinalURL != "" {
			out["final_url"] = r.FinalURL
		}
	}
	for _, k := range []string{"tls", "hash", "body_preview", "extracts", "jarm_hash", "websocket", "http2", "pipeline", "vhost", "sni", "cpe", "wordpress", "knowledgebase", "csp", "body_fqdn", "body_domains"} {
		if v, ok := m[k]; ok {
			out[k] = v
		}
	}
	if p.pf.asn {
		if as := p.asn(r.IP); as != nil {
			out["asn"] = as
		}
	}
	if r.CatchAll {
		out["catchall"] = true
	}
	if ev != nil {
		p.evidence(out, ev, chainCodes)
	}
	return out
}

// numOf is a number held as any, whether it came from JSON or from Go.
func numOf(v any) int {
	switch x := v.(type) {
	case int:
		return x
	case int64:
		return int(x)
	case float64:
		return int(x)
	}
	return 0
}

// hopStatuses are the statuses of a redirect chain, empty without one.
func hopStatuses(m map[string]any) []int {
	hops, _ := m["hops"].([]any)
	var out []int
	for _, h := range hops {
		if hm, ok := h.(map[string]any); ok {
			out = append(out, numOf(hm["status"]))
		}
	}
	return out
}

// part is a header's value up to its first ";": httpx's text/html for
// text/html; charset=utf-8.
func part(v string) string {
	if i := strings.Index(v, ";"); i >= 0 {
		v = v[:i]
	}
	return strings.TrimSpace(v)
}

// evidence adds the fields that hold the response as it came.
func (p *probeOut) evidence(out map[string]any, ev *httpcol.Evidence, codes []int) {
	pf := p.pf
	hdr := parseHead(ev.Head)
	cond := p.set != nil && (p.set.MatchExpr != nil || p.set.FilterExpr != nil) // httpx adds these to a row it judges by a condition
	if pf.irh || pf.irr || pf.irrb || cond {
		out["header"], out["raw_header"] = normalizeHeaders(hdr), ev.Head
	}
	if pf.irr || cond {
		out["request"], out["body"] = string(ev.Request), string(ev.Data)
	}
	if pf.irrb {
		out["header"], out["raw_header"] = normalizeHeaders(hdr), base64.StdEncoding.EncodeToString([]byte(ev.Head))
		out["request"], out["body"] = base64.StdEncoding.EncodeToString(ev.Request), base64.StdEncoding.EncodeToString(ev.Data)
	}
	if pf.includeChain && len(codes) > 1 {
		var chain []map[string]any
		for i, h := range ev.Hops {
			item := map[string]any{"request-url": h.URL, "status_code": h.Status}
			if h.Location != "" {
				if u, err := url.Parse(h.URL); err == nil {
					if l, err := u.Parse(h.Location); err == nil {
						item["location"] = l.String()
					}
				}
			}
			if i < len(ev.Chain) {
				item["request"], item["response"] = ev.Chain[i].Request, ev.Chain[i].Response
			}
			chain = append(chain, item)
		}
		out["chain"] = chain
	}
}

func parseHead(head string) http.Header {
	resp, err := http.ReadResponse(bufio.NewReader(strings.NewReader(head+"\r\n")), nil)
	if err != nil {
		return http.Header{}
	}
	resp.Body.Close()
	return resp.Header
}

func normalizeHeaders(h http.Header) map[string]any {
	out := make(map[string]any, len(h))
	for k, v := range h {
		out[strings.ReplaceAll(strings.ToLower(k), "-", "_")] = strings.Join(v, ", ")
	}
	return out
}

// keep applies the matchers and filters; a row they drop is counted.
func (p *probeOut) keep(row map[string]any, r engine.ProbeRow, ev *httpcol.Evidence) bool {
	if p.pf.fpt != "" || p.pf.fep {
		kinds := splitList(strings.ToLower(p.pf.fpt))
		if p.pf.fep && len(kinds) == 0 {
			kinds = []string{"error"}
		}
		if kb, ok := row["knowledgebase"].(map[string]any); ok {
			if t, _ := kb["PageType"].(string); slices.Contains(kinds, strings.ToLower(t)) {
				p.mu.Lock()
				p.dropped++
				p.mu.Unlock()
				return false
			}
		}
	}
	if p.set.Empty() && !p.pf.fd {
		return true
	}
	fr := probefilter.Row{Status: numOf(row["status_code"]), Length: r.Length, Lines: r.Lines, Words: r.Words, Favicon: r.Favicon, CDN: r.CDN}
	fr.Time, _ = time.ParseDuration(fmt.Sprint(row["time"]))
	if ev != nil {
		fr.Raw = ev.Head + string(ev.Body)
	}
	if p.set != nil && (p.set.MatchExpr != nil || p.set.FilterExpr != nil) {
		vars := make(map[string]any, len(row)+6)
		for k, v := range row {
			vars[k] = v
		}
		if ev != nil {
			vars["body"], vars["raw_header"], vars["request"] = string(ev.Data), ev.Head, string(ev.Request)
			vars["header"] = normalizeHeaders(parseHead(ev.Head))
		}
		if h, ok := row["hash"].(map[string]any); ok {
			for k, v := range h {
				vars[k] = v
			}
		}
		for _, k := range []string{"title", "webserver", "content_type", "location", "favicon", "cdn_name", "cdn_type", "final_url"} {
			if _, ok := vars[k]; !ok {
				vars[k] = ""
			}
		}
		fr.Vars = vars
	}
	ok, err := p.set.Keep(fr)
	p.mu.Lock()
	defer p.mu.Unlock()
	if err != nil {
		p.condErrs++
		if p.condErr == nil {
			p.condErr = err
		}
	}
	if ok && p.pf.fd && ev != nil {
		h := simhash.Simhash(simhash.NewWordFeatureSet(ev.Data))
		for _, s := range p.sums {
			if simhash.Compare(h, s) <= 3 {
				ok = false
				break
			}
		}
		if ok {
			p.sums = append(p.sums, h)
		}
	}
	if !ok {
		p.dropped++
	}
	return ok
}

// emit prints the row in the format asked for and stores the response.
func (p *probeOut) emit(row map[string]any, r engine.ProbeRow, ev *httpcol.Evidence) {
	if ev != nil && (p.pf.debug || p.pf.debugReq) {
		p.mu.Lock()
		fmt.Fprintf(os.Stderr, "Dumped HTTP request for %v\n\n%s\n", row["url"], ev.Request)
		p.mu.Unlock()
	}
	if ev != nil && (p.pf.debug || p.pf.debugResp) {
		p.mu.Lock()
		fmt.Fprintf(os.Stderr, "Dumped HTTP response for %v\n\n%s%s\n", row["url"], ev.Head, ev.Body)
		p.mu.Unlock()
	}
	if p.store != nil && ev != nil {
		row["stored_response_path"] = p.store.save(row, ev, p.pf)
	}
	if m, _ := row["method"].(string); m != "" && m != "GET" {
		p.mu.Lock()
		p.sent[m]++
		p.mu.Unlock()
	}
	for _, f := range strings.Split(p.pf.eof, ",") {
		delete(row, strings.TrimSpace(f))
	}
	for _, s := range p.extra {
		s.write(p, row, r)
	}
	switch {
	case p.w.json:
		p.w.obj(row)
	case p.pf.csv:
		p.w.line(csvRow(row))
	case p.pf.md:
		p.w.line(mdRow(row))
	default:
		p.w.line(p.text(row, r, "SUCCESS"))
	}
}

func (s rowSink) write(p *probeOut, row map[string]any, r engine.ProbeRow) {
	switch s.format {
	case "json":
		raw, _ := json.Marshal(row)
		fmt.Fprintf(s.w, "%s\n", raw)
	case "csv":
		fmt.Fprintf(s.w, "%s\n", csvRow(row))
	case "md":
		fmt.Fprintf(s.w, "%s\n", mdRow(row))
	default:
		fmt.Fprintf(s.w, "%s\n", p.text(row, r, "SUCCESS"))
	}
}

// urlAsGiven is the input itself when it is a URL and url is that URL
// asked, not a redirect, another path or the other scheme.
func urlAsGiven(input, url string) (string, bool) {
	input = strings.TrimSpace(input)
	if !strings.Contains(input, "://") {
		return "", false
	}
	if n, err := normalize.URL(input); err != nil || n != url {
		return "", false
	}
	return input, true
}

// lastTried is the URL a bare input (host, IP or host:port) was asked
// last: httpx tries the likelier scheme and then the other, and a target
// that answered neither is named by the second try, with its error.
func (p *probeOut) lastTried(input string) string {
	host, port := strings.Trim(input, "[]"), ""
	if h, pt, err := net.SplitHostPort(input); err == nil {
		host, port = h, pt
	}
	ps := httpcol.PortSpec{}
	switch n, err := strconv.Atoi(port); {
	case err == nil:
		ps.Port = n
	case len(p.spec.Ports) > 0:
		ps = p.spec.Ports[0]
	default:
		h := host
		if strings.Contains(h, ":") {
			h = "[" + h + "]"
		}
		return "http://" + h + "/"
	}
	h := host
	if strings.Contains(h, ":") {
		h = "[" + h + "]"
	}
	group := httpcol.PortGroup(h, ps)
	return group[len(group)-1]
}

// failedRow is the row of a target that got no answer.
func (p *probeOut) failedRow(input, why string) {
	u := input
	if !strings.Contains(u, "://") {
		u = p.lastTried(input)
	}
	shown := strings.TrimSuffix(u, "/")
	if strings.Contains(input, "://") {
		shown = strings.TrimSpace(input) // a URL input is printed as given
	}
	row := map[string]any{
		"timestamp": time.Now().Format(time.RFC3339Nano), "url": shown, "input": input,
		"failed": true, "error": why,
	}
	if pu, err := url.Parse(u); err == nil {
		row["host"], row["scheme"] = pu.Hostname(), pu.Scheme
		if pt := pu.Port(); pt != "" {
			row["port"] = pt
		}
	}
	for _, s := range p.extra {
		if s.format == "json" {
			s.write(p, row, engine.ProbeRow{})
		}
	}
	switch {
	case p.w.json:
		p.w.obj(row)
	case p.pf.probe && !p.pf.csv && !p.pf.md:
		p.w.line(fmt.Sprintf("%s [FAILED]", row["url"]))
	}
}

// text is the row as one line: azhaq's own by default, httpx's bracket
// style for the fields the display flags chose.
func (p *probeOut) text(row map[string]any, r engine.ProbeRow, status string) string {
	pf := p.pf
	if !p.displays {
		var line string
		switch {
		case p.c.silent && !pf.probe:
			return fmt.Sprint(row["url"])
		default:
			line = r.Line()
		}
		if pf.probe {
			line = strings.Replace(line, " ", " [SUCCESS] ", 1)
			if !strings.Contains(line, "[SUCCESS]") {
				line += " [SUCCESS]"
			}
		}
		return line
	}
	// The brackets come in httpx's order.
	var b strings.Builder
	b.WriteString(fmt.Sprint(row["url"]))
	add := func(s string) { fmt.Fprintf(&b, " [%s]", s) }
	if pf.probe {
		add(status)
	}
	if pf.sc {
		codes := intList(row["chain_status_codes"])
		if len(codes) == 0 {
			codes = []int{numOf(row["status_code"])}
		}
		var s []string
		for _, c := range codes {
			s = append(s, strconv.Itoa(c))
		}
		add(strings.Join(s, ","))
	}
	if pf.location {
		add(fmt.Sprint(probeOrEmpty(row["location"])))
	}
	if pf.method {
		add(fmt.Sprint(row["method"]))
	}
	if pf.cl {
		add(fmt.Sprint(row["content_length"]))
	}
	if pf.ct {
		add(fmt.Sprint(probeOrEmpty(row["content_type"])))
	}
	if pf.title {
		if t, _ := row["title"].(string); t != "" {
			add(t)
		}
	}
	if pf.preview > 0 {
		add(fmt.Sprint(probeOrEmpty(row["body_preview"])))
	}
	if pf.server {
		add(fmt.Sprint(probeOrEmpty(row["webserver"])))
	}
	for _, f := range [...]struct {
		on        bool
		key, name string
	}{{pf.vhost, "vhost", "vhost"}, {pf.ws, "websocket", "websocket"}, {pf.pipeline, "pipeline", "pipeline"}, {pf.http2, "http2", "http2"}} {
		if v, _ := row[f.key].(bool); f.on && v {
			add(f.name)
		}
	}
	if as, ok := row["asn"].(*asnInfo); ok && pf.asn {
		add(fmt.Sprintf("%s, %s, %s", as.Number, as.Name, as.Country))
	}
	if pf.ip || pf.probeAllIPs {
		add(fmt.Sprint(row["host_ip"]))
	}
	if cn, _ := row["cname"].([]string); pf.cname && len(cn) > 0 {
		add(cn[0])
	}
	if n, ok := row["cdn_name"].(string); pf.cdn && ok && row["cdn"] == true {
		add(n)
	}
	if pf.rt {
		add(fmt.Sprint(row["time"]))
	}
	if ex, ok := row["extracts"].(map[string][]string); ok {
		keys := make([]string, 0, len(ex))
		for k := range ex {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			add(strings.Join(ex[k], ","))
		}
	}
	if fu, ok := row["final_url"].(string); ok && pf.location {
		add(fu)
	}
	if f, _ := row["favicon"].(string); f != "" {
		add(f)
	}
	if h, ok := row["hash"].(map[string]any); ok {
		var s []string
		for _, k := range strings.Split(strings.ToLower(pf.hash), ",") {
			if v, ok := h["body_"+strings.TrimSpace(k)]; ok {
				s = append(s, fmt.Sprint(v))
			}
		}
		add(strings.Join(s, ","))
	}
	if pf.lc {
		add(fmt.Sprint(row["lines"]))
	}
	if pf.jarm {
		add(fmt.Sprint(probeOrEmpty(row["jarm_hash"])))
	}
	if pf.wc {
		add(fmt.Sprint(row["words"]))
	}
	if t, _ := row["tech"].([]string); pf.td && len(t) > 0 {
		add(strings.Join(t, ","))
	}
	if pf.tlsGrab {
		if t, ok := row["tls"].(map[string]any); ok {
			add(fmt.Sprintf("%v %v", t["tls_version"], t["subject_cn"]))
		}
	}
	return b.String()
}

func probeOrEmpty(v any) any {
	if v == nil {
		return ""
	}
	return v
}

func intList(v any) []int {
	switch x := v.(type) {
	case []int:
		return x
	}
	return nil
}

// csvColumns are httpx's CSV columns, in its order.
var csvColumns = []string{"timestamp", "link_request", "extract_regex", "cdn_name", "cdn_type", "sni", "port", "url", "input", "location", "title", "scheme", "error", "webserver", "body_preview", "content_type", "method", "host", "host_ip", "path", "favicon", "favicon_md5", "favicon_path", "favicon_url", "final_url", "time", "jarm_hash", "chain_status_codes", "a", "aaaa", "cname", "tech", "words", "lines", "status_code", "content_length", "failed", "vhost", "websocket", "cdn", "http2", "pipeline", "headless_body", "screenshot_bytes", "stored_response_path", "screenshot_path", "screenshot_path_rel", "resolvers", "body_fqdn", "body_domains", "cpe", "wordpress"}

func probeCell(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case []string:
		return strings.Join(x, ",")
	case []int:
		s := make([]string, len(x))
		for i, n := range x {
			s[i] = strconv.Itoa(n)
		}
		return strings.Join(s, ",")
	case bool:
		return strconv.FormatBool(x)
	}
	return fmt.Sprint(v)
}

func csvHeader() string { return strings.Join(csvColumns, ",") }

// csvRow is the row as one CSV line; a cell that a spreadsheet would run
// as a formula starts with a quote, as httpx does.
func csvRow(row map[string]any) string {
	var b strings.Builder
	w := csv.NewWriter(&b)
	rec := make([]string, len(csvColumns))
	for i, c := range csvColumns {
		v := row[c]
		if v == nil && csvBools[c] {
			v = false
		}
		s := probeCell(v)
		if s != "" && strings.ContainsRune("=+-@", rune(s[0])) {
			s = "'" + s
		}
		rec[i] = s
	}
	_ = w.Write(rec)
	w.Flush()
	return strings.TrimSpace(b.String())
}

func mdHeader() string {
	return "| " + strings.Join(csvColumns, " | ") + " |\n|" + strings.Repeat("---|", len(csvColumns))
}

var csvBools = map[string]bool{"failed": true, "vhost": true, "websocket": true, "cdn": true, "http2": true, "pipeline": true}

func mdRow(row map[string]any) string {
	rep := strings.NewReplacer("|", `\|`, "\n", " ")
	var b strings.Builder
	b.WriteString("|")
	for _, c := range csvColumns {
		v := row[c]
		if v == nil && csvBools[c] {
			v = false
		}
		fmt.Fprintf(&b, " %s |", strings.TrimSpace(rep.Replace(probeCell(v))))
	}
	return b.String()
}

// respStore keeps the responses of -sr as httpx does: DIR/response/HOST/SHA1.txt.
type respStore struct {
	mu    sync.Mutex
	dir   string
	index *os.File
}

func newRespStore(dir string) (*respStore, error) {
	rd := filepath.Join(dir, "response")
	if err := os.MkdirAll(rd, 0o755); err != nil {
		return nil, err
	}
	f, err := os.Create(filepath.Join(rd, "index.txt"))
	if err != nil {
		return nil, err
	}
	return &respStore{dir: rd, index: f}, nil
}

func (s *respStore) close() {
	if s != nil && s.index != nil {
		s.index.Close()
	}
}

// save writes one response and returns its path.
func (s *respStore) save(row map[string]any, ev *httpcol.Evidence, pf *probeFlags) string {
	u, _ := url.Parse(fmt.Sprint(row["url"]))
	host := ""
	if u != nil {
		host = strings.ReplaceAll(u.Host, ":", "_")
	}
	sum := sha1.Sum([]byte(ev.Method + ":" + fmt.Sprint(row["url"])))
	base := hex.EncodeToString(sum[:])
	raw := ev.Head
	if !pf.ob {
		raw += string(ev.Body)
	}
	if pf.rsts > 0 && len(raw) > pf.rsts {
		raw = raw[:pf.rsts]
	}
	data := string(ev.Request)
	if pf.storeChain && len(ev.Chain) > 1 {
		data += "\n"
		for i := 0; i < len(ev.Chain)-1; i++ {
			data += ev.Chain[i].Response + ev.Chain[i+1].Request
		}
	}
	data += raw + "\n\n\n" + fmt.Sprint(row["url"])
	s.mu.Lock()
	defer s.mu.Unlock()
	dir := filepath.Join(s.dir, host)
	_ = os.MkdirAll(dir, 0o755)
	path := filepath.Join(dir, base+".txt")
	for i := 1; ; i++ {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err == nil {
			_, _ = f.WriteString(data)
			f.Close()
			break
		}
		if !os.IsExist(err) {
			return ""
		}
		path = filepath.Join(dir, fmt.Sprintf("%s_%d.txt", base, i))
	}
	abs, _ := filepath.Abs(path)
	st := numOf(row["status_code"])
	fmt.Fprintf(s.index, "%s %s (%d %s)\n", abs, row["url"], st, http.StatusText(st))
	return abs
}

// asnInfo is httpx's asn object.
type asnInfo struct {
	Number  string   `json:"as_number"`
	Name    string   `json:"as_name"`
	Country string   `json:"as_country"`
	Range   []string `json:"as_range"`
}

// asn looks up the autonomous system of a public address at RIPEstat: one
// third-party request per new prefix, not one to a target.
func (p *probeOut) asn(ip string) *asnInfo {
	a, err := netip.ParseAddr(ip)
	if err != nil || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsUnspecified() {
		return nil
	}
	if v, ok := p.asns.Load(ip); ok {
		info, _ := v.(*asnInfo)
		return info
	}
	info := ripeASN(ip)
	p.asns.Store(ip, info)
	return info
}

func ripeASN(ip string) *asnInfo {
	cl := egress.SourceClient(egress.SourceOptions{Timeout: 15 * time.Second})
	get := func(path string, v any) bool {
		req, err := http.NewRequest(http.MethodGet, "https://stat.ripe.net"+path+"&sourceapp=azhaq", nil)
		if err != nil {
			return false
		}
		req.Header.Set("User-Agent", fetch.ToolAgent)
		resp, err := cl.Do(req)
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		return resp.StatusCode == 200 && json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(v) == nil
	}
	var ov struct {
		Data struct {
			Resource string `json:"resource"`
			ASNs     []struct {
				ASN    int    `json:"asn"`
				Holder string `json:"holder"`
			} `json:"asns"`
		} `json:"data"`
	}
	if !get("/data/prefix-overview/data.json?resource="+ip, &ov) || len(ov.Data.ASNs) == 0 {
		return nil
	}
	as := ov.Data.ASNs[0]
	info := &asnInfo{Number: fmt.Sprintf("AS%d", as.ASN), Name: as.Holder, Range: []string{ov.Data.Resource}}
	var rir struct {
		Data struct {
			Located []struct {
				Location string `json:"location"`
			} `json:"located_resources"`
		} `json:"data"`
	}
	if get(fmt.Sprintf("/data/rir-stats-country/data.json?resource=AS%d", as.ASN), &rir) && len(rir.Data.Located) > 0 {
		info.Country = rir.Data.Located[0].Location
	}
	if name, _, ok := strings.Cut(info.Name, " - "); ok {
		info.Name = name
	}
	return info
}
