package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/trannghiach/azhaq/internal/collectors/paramcol"
	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/internal/ledger"
	"github.com/trannghiach/azhaq/internal/normalize"
	"github.com/trannghiach/azhaq/types"
)

// paramsRow is one page's result, as the command prints and saves it.
type paramsRow struct {
	URL    string
	Method string
	Params []string
	Why    map[string]any
	Values map[string]any
}

// cmdParams is arjun: query parameters the pages read, from a list, with
// the names the pages themselves hold asked first. GET by default; -X POST,
// JSON and XML send names in a body, which may change data, so they are
// opt-in. The pages given are the scope.
func cmdParams(args []string) error {
	fs := newFlags("params")
	var c common
	c.register(fs)
	var urls stringsFlag
	fs.Var(&urls, "u", "page URL (repeatable)")
	list := fs.String("l", "", "file of page URLs (- for stdin)")
	imp := fs.String("i", "", "import pages: a file of URLs, a Burp Suite XML export (HTML, JSON and XML items) or a raw HTTP request (GET or POST)")
	words := fs.String("w", "large", "parameter names: a file, one per line, or small (1,000 names), medium (3,000) or large (6,500, the default)")
	method := fs.String("X", "GET", "how names are sent: GET (query), POST (form body), JSON or XML. A body sends requests that may change data on the target, and needs -allow or -scope, or a single page")
	threads := fs.Int("t", 5, "requests in flight per page (arjun -t)")
	chunk := fs.Int("c", 0, "names per request (0: 250 in a query, 500 in a body; fewer where the server refuses a long query)")
	delay := fs.Float64("d", 0, "seconds to wait before each request, one at a time (arjun -d)")
	stable := fs.Bool("stable", false, "one request at a time, 3 to 9 s apart, and 30 s wait after a refused connection (arjun --stable)")
	timeout := fs.Float64("T", 15, "seconds to wait for each request; one that times out is asked again with 5 s more, up to 20 s (arjun -T)")
	include := fs.String("include", "", "sent with every request: a query (a=1&b=2) for GET; for a body a form, a JSON object, or XML, or a template with $arjun$ where the names go")
	casing := fs.String("casing", "", "write the names in one style: snake (like_this), camel (likeThis) or lower (likethis)")
	passive := fs.Bool("passive", false, "also try the query names the archives (Wayback Machine, Common Crawl, OTX) hold for the pages' domains")
	outJSON := fs.String("oJ", "", "write results to this file as JSON: {\"URL\": {\"params\": [...], \"method\": \"GET\", \"headers\": {...}}}")
	outText := fs.String("oT", "", "write results to this file as text, one request per line: URL?name=1234&other=5678")
	outBurp := fs.String("oB", "", "send each page with the names found through this proxy, HOST:PORT (Burp), after the search")
	given := inherit(fs, "rate=params-rate", "H=header", "cookie", "all-gets", "max-requests", "timeout", "v", "scope", "program", "allow", "deny", "ledger", "kill-file", "urls-timeout")
	if err := parse(fs, args); err != nil {
		return err
	}
	m := strings.ToUpper(*method)
	switch m {
	case "GET", "POST", "JSON", "XML":
	default:
		return usagef("-X %q: use GET, POST, JSON or XML", *method)
	}
	var imported map[string]paramcol.Target
	rep := newReport("params")
	rep.what = "pages with parameters"
	var targets []string
	if *imp == "" || len(urls) > 0 || *list != "" {
		var err error
		if targets, err = inputs(urls, *list); err != nil {
			return err
		}
	}
	if *imp != "" {
		got, notes, err := importPages(*imp)
		if err != nil {
			return err
		}
		imported = map[string]paramcol.Target{}
		for _, g := range got {
			targets = append(targets, g.URL)
			if g.Target.Method != "" || g.Target.Include != "" || len(g.Target.Header) > 0 {
				imported[pageOf(g.URL)] = g.Target
			}
		}
		rep.Notes = append(rep.Notes, notes...)
	}
	if len(targets) == 0 {
		return usagef("give -u URL, -l FILE, -i FILE or URLs on stdin")
	}
	extra := given()
	writes := m != "GET"
	for _, t := range imported {
		if mm := strings.ToUpper(t.Method); mm != "" && mm != "GET" {
			writes = true
		}
	}
	if writes && !hasFlag(extra, "allow", "scope") && len(targets) != 1 {
		return usagef("sending names in a body may change data on the targets: name them with -allow or -scope, or give a single page")
	}
	// The list: a file or a built-in one, in the style asked for, with the
	// names the archives hold for the domains first.
	var run []string
	listFile := *words
	if _, ok := paramcol.Builtin(*words); !ok || *casing != "" || *passive {
		ws, ok := paramcol.Builtin(*words)
		if !ok {
			var err error
			if ws, err = loadLines(*words); err != nil {
				return err
			}
		}
		if *casing != "" {
			var err error
			if ws, err = paramcol.Recase(ws, *casing); err != nil {
				return usagef("%v", err)
			}
		}
		if *passive {
			first, err := passiveNames(&c, targets, extra, rep)
			if err != nil {
				return err
			}
			ws = append(first, ws...)
		}
		path, rm, err := tempList(ws)
		if err != nil {
			return err
		}
		defer rm()
		listFile = path
	}
	if len(*words) > 0 && listFile == *words {
		if _, ok := paramcol.Builtin(*words); !ok {
			return usagef("%s is neither a file nor small, medium or large", *words)
		}
	}
	path, rm, err := tempList(targets)
	if err != nil {
		return err
	}
	defer rm()
	w, err := newWriter(&c)
	if err != nil {
		return err
	}
	var rows []paramsRow
	var mu sync.Mutex
	see := func(_ types.Entity, o types.Observation) {
		if o.Collector != "azhaq-params" {
			return
		}
		p := payloadOf(o)
		u, _ := p["url"].(string)
		names := strs(p["params"])
		if len(names) == 0 {
			return
		}
		meth, _ := p["method"].(string)
		why, _ := p["why"].(map[string]any)
		vals, _ := p["values"].(map[string]any)
		mu.Lock()
		rows = append(rows, paramsRow{URL: u, Method: meth, Params: names, Why: why, Values: vals})
		mu.Unlock()
		if w.json {
			row := map[string]any{"url": u, "method": meth, "params": names, "why": why}
			if len(vals) > 0 {
				row["values"] = vals
			}
			w.obj(row)
		} else {
			w.line(u + " " + strings.Join(names, ","))
		}
	}
	run = []string{"-list", path, "-depth", "1", "-no-tech", "-no-favicon", "-skip", skipAllBut("azhaq-dns", "azhaq-http", "azhaq-params"),
		"-params", listFile, "-params-per-host", fmt.Sprint(len(targets)), "-params-threads", fmt.Sprint(*threads), "-params-method", m,
		"-params-timeout", fmt.Sprintf("%gs", *timeout)}
	if *chunk > 0 {
		run = append(run, "-params-chunk", fmt.Sprint(*chunk))
	}
	if *delay > 0 {
		run = append(run, "-params-delay", fmt.Sprintf("%gs", *delay))
	}
	if *stable {
		run = append(run, "-params-stable")
	}
	if *include != "" {
		if err := checkInclude(m, *include); err != nil {
			return usagef("%v", err)
		}
		run = append(run, "-params-include", *include)
	}
	if writes {
		run = append(run, "-params-writes")
	}
	if len(imported) > 0 {
		tf, err := os.CreateTemp("", "azhaq-targets-")
		if err != nil {
			return err
		}
		raw, _ := json.Marshal(imported)
		_, werr := tf.Write(raw)
		tf.Close()
		defer os.Remove(tf.Name())
		if werr != nil {
			return werr
		}
		run = append(run, "-params-targets", tf.Name())
	}
	if !hasFlag(extra, "allow", "scope") {
		// The pages given are the scope.
		for _, t := range targets {
			if u, err := url.Parse(t); err == nil {
				run = append(run, "-allow", u.Hostname())
			}
		}
	}
	_, done, err := runPreset(&c, append(run, extra...), rep, see)
	if err != nil {
		return err
	}
	defer done()
	if err := w.close(); err != nil {
		return err
	}
	rep.Results = w.count()
	sort.Slice(rows, func(i, j int) bool { return rows[i].URL < rows[j].URL })
	headers := headerMap(fs)
	if *outJSON != "" {
		if err := writeParamsJSON(*outJSON, rows, headers); err != nil {
			return err
		}
	}
	if *outText != "" {
		if err := writeParamsText(*outText, rows); err != nil {
			return err
		}
	}
	if *outBurp != "" {
		rate := 0.0
		if f := fs.Lookup("rate"); f != nil {
			fmt.Sscan(f.Value.String(), &rate)
		}
		if note := replayToProxy(*outBurp, rows, rate); note != "" {
			rep.Notes = append(rep.Notes, note)
		}
	}
	return rep.finish(c.json, c.silent)
}

// pageOf is scheme, host and path of raw: the key a page is searched under.
func pageOf(raw string) string {
	if n, err := normalize.URL(raw); err == nil {
		raw = n
	}
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	return u.Scheme + "://" + u.Host + u.Path
}

// headerMap is the headers the run sends: -H and -cookie.
func headerMap(fs *flag.FlagSet) map[string]string {
	out := map[string]string{}
	for _, name := range []string{"H", "cookie"} {
		f := fs.Lookup(name)
		if f == nil {
			continue
		}
		sf, ok := f.Value.(*stringsFlag)
		if !ok {
			continue
		}
		for _, v := range *sf {
			if name == "cookie" {
				out["Cookie"] = v
			} else if k, val, ok := strings.Cut(v, ":"); ok {
				out[strings.TrimSpace(k)] = strings.TrimSpace(val)
			}
		}
	}
	return out
}

// checkInclude refuses an -include that its method cannot send.
func checkInclude(method, include string) error {
	inc := strings.TrimSpace(include)
	switch method {
	case "JSON":
		probe := strings.Replace(inc, "$arjun$", `"x":"y"`, 1)
		var v any
		if err := json.Unmarshal([]byte(probe), &v); err != nil {
			return fmt.Errorf("-include is not JSON (an object, or a template with $arjun$ where the names go): %v", err)
		}
	case "XML":
		probe := strings.Replace(inc, "$arjun$", "<x>y</x>", 1)
		d := xml.NewDecoder(strings.NewReader(probe))
		for {
			_, err := d.Token()
			if err == io.EOF {
				break
			}
			if err != nil {
				return fmt.Errorf("-include is not XML (a document, or a template with $arjun$ where the names go): %v", err)
			}
		}
	}
	return nil
}

// importedPage is a page taken from an -i file, with how it is asked.
type importedPage struct {
	URL    string
	Target paramcol.Target
}

// importPages reads pages from a file: a Burp Suite XML export, a raw HTTP
// request, or lines of URLs. What it leaves out it says in notes.
func importPages(path string) ([]importedPage, []string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	trim := bytes.TrimSpace(raw)
	switch {
	case bytes.HasPrefix(trim, []byte("<?xml")) || bytes.HasPrefix(trim, []byte("<items")):
		return importBurp(raw)
	case rawRequestLine.Match(firstLine(trim)):
		pg, err := importRaw(raw, "")
		if err != nil {
			return nil, nil, fmt.Errorf("-i %s: %w", path, err)
		}
		return []importedPage{pg}, nil, nil
	}
	lines, err := readLines(bytes.NewReader(raw))
	if err != nil {
		return nil, nil, err
	}
	var out []importedPage
	for _, l := range lines {
		out = append(out, importedPage{URL: l})
	}
	return out, nil, nil
}

func firstLine(b []byte) []byte {
	if i := bytes.IndexByte(b, '\n'); i >= 0 {
		return bytes.TrimRight(b[:i], "\r")
	}
	return b
}

var rawRequestLine = regexp.MustCompile(`^[A-Z]+ \S+ HTTP/\d`)

// burpItems is a Burp Suite "save items" export.
type burpItems struct {
	Items []struct {
		URL      string `xml:"url"`
		Method   string `xml:"method"`
		Mimetype string `xml:"mimetype"`
		Request  struct {
			Base64 string `xml:"base64,attr"`
			Data   string `xml:",chardata"`
		} `xml:"request"`
	} `xml:"item"`
}

func importBurp(raw []byte) ([]importedPage, []string, error) {
	var items burpItems
	// Burp writes XML 1.1, which Go's parser refuses; nothing else differs.
	raw = bytes.Replace(raw, []byte(`version="1.1"`), []byte(`version="1.0"`), 1)
	if err := xml.Unmarshal(raw, &items); err != nil {
		return nil, nil, fmt.Errorf("-i: not a Burp export: %w", err)
	}
	var out []importedPage
	seen := map[string]bool{}
	skipped, dup, other := 0, 0, 0
	for _, it := range items.Items {
		switch strings.ToLower(it.Mimetype) {
		case "", "html", "json", "xml", "text":
		default:
			skipped++ // a script, an image, a stylesheet: not a page to search
			continue
		}
		var pg importedPage
		data := []byte(strings.TrimSpace(it.Request.Data))
		if it.Request.Base64 == "true" {
			if d, err := base64.StdEncoding.DecodeString(string(data)); err == nil {
				data = d
			}
		}
		if len(data) > 0 && rawRequestLine.Match(firstLine(data)) {
			var err error
			if pg, err = importRaw(data, it.URL); err != nil {
				other++
				continue
			}
		} else {
			pg = importedPage{URL: strings.TrimSpace(it.URL)}
			if strings.EqualFold(it.Method, "POST") {
				pg.Target.Method = "POST"
			}
		}
		if pg.URL == "" {
			continue
		}
		if m := strings.ToUpper(it.Method); m != "" && m != "GET" && m != "POST" {
			other++ // a method the search does not use
			continue
		}
		key := pageOf(pg.URL)
		if seen[key] {
			dup++
			continue
		}
		seen[key] = true
		out = append(out, pg)
	}
	var notes []string
	if skipped > 0 {
		notes = append(notes, fmt.Sprintf("-i: %d Burp items were not HTML, JSON or XML and were left out", skipped))
	}
	if dup > 0 {
		notes = append(notes, fmt.Sprintf("-i: %d Burp items repeated a page already taken (a page is searched once, with its first request)", dup))
	}
	if other > 0 {
		notes = append(notes, fmt.Sprintf("-i: %d Burp items were left out: a method other than GET and POST, or a request that could not be read", other))
	}
	if len(out) == 0 {
		return nil, notes, fmt.Errorf("-i: no page to search in the Burp export")
	}
	return out, notes, nil
}

// importRaw reads a raw HTTP request: the page it names, its headers, and
// for a POST the way its body is sent. urlHint is the full URL when the
// request line holds only a path.
func importRaw(raw []byte, urlHint string) (importedPage, error) {
	text := strings.ReplaceAll(string(raw), "\r\n", "\n")
	head, body, _ := strings.Cut(text, "\n\n")
	lines := strings.Split(head, "\n")
	parts := strings.Fields(lines[0])
	if len(parts) < 2 {
		return importedPage{}, fmt.Errorf("not an HTTP request: %q", lines[0])
	}
	method, target := strings.ToUpper(parts[0]), parts[1]
	if method != "GET" && method != "POST" {
		return importedPage{}, fmt.Errorf("a %s request: only GET and POST are searched", method)
	}
	var pg importedPage
	host, ctype := "", ""
	for _, l := range lines[1:] {
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch strings.ToLower(k) {
		case "host":
			host = v
		case "content-type":
			ctype = strings.ToLower(v)
		case "content-length", "connection", "accept-encoding", "proxy-connection", "upgrade-insecure-requests":
		default:
			pg.Target.Header = append(pg.Target.Header, k+": "+v)
		}
	}
	switch {
	case strings.Contains(target, "://"):
		pg.URL = target
	case urlHint != "":
		pg.URL = urlHint
	case host != "":
		scheme := "http"
		if strings.HasSuffix(host, ":443") {
			scheme = "https"
		}
		pg.URL = scheme + "://" + host + target
	default:
		return importedPage{}, fmt.Errorf("the request names no host (no Host header)")
	}
	if method == "POST" {
		pg.Target.Method = "POST"
		body = strings.TrimSpace(body)
		switch {
		case strings.Contains(ctype, "json"):
			pg.Target.Method = "JSON"
		case strings.Contains(ctype, "xml"):
			pg.Target.Method = "XML"
		}
		pg.Target.Include = body
	}
	return pg, nil
}

// passiveNames are the query names the archives hold for the domains of
// pages, the ones on the pages' own hosts first. What the sources could not
// answer is said in rep.
func passiveNames(c *common, pages, extra []string, rep *report) ([]string, error) {
	hosts := map[string]bool{}
	var domains []string
	for _, p := range pages {
		if u, err := url.Parse(p); err == nil && u.Hostname() != "" && !hosts[u.Hostname()] {
			hosts[u.Hostname()] = true
			domains = append(domains, u.Hostname())
		}
	}
	f, err := os.CreateTemp("", "azhaq-urls-")
	if err != nil {
		return nil, err
	}
	f.Close()
	defer os.Remove(f.Name())
	pc := common{json: c.json, silent: c.silent}
	urep := newReport("urls")
	run := []string{"-passive", "-depth", "0", "-skip", skipAllBut("azhaq-urls"), "-urls", f.Name()}
	for _, d := range domains {
		run = append(run, "-domain", d)
	}
	var keep []string
	for _, a := range extra {
		// Only the pace and the time of the sources apply; the pages' scope does not.
		if hasFlag([]string{a}, "urls-timeout", "timeout", "v") {
			keep = append(keep, a)
		}
	}
	_, done, err := runPreset(&pc, append(run, keep...), urep, nil)
	if err != nil {
		return nil, err
	}
	defer done()
	lines, err := loadLines(f.Name())
	if err != nil {
		return nil, err
	}
	// A source that failed leaves the list shorter: it is said.
	rep.Failed = append(rep.Failed, urep.Failed...)
	rep.Degraded = rep.Degraded || urep.Degraded
	rep.Notes = append(rep.Notes, urep.Notes...)
	var own, rest []string
	seen := map[string]bool{}
	for _, l := range lines {
		u, err := url.Parse(strings.SplitN(l, "\t", 2)[0])
		if err != nil {
			continue
		}
		for k := range u.Query() {
			if k == "" || seen[k] || len(k) > 60 {
				continue
			}
			seen[k] = true
			if hosts[u.Hostname()] {
				own = append(own, k)
			} else {
				rest = append(rest, k)
			}
		}
	}
	sort.Strings(own)
	sort.Strings(rest)
	rep.Notes = append(rep.Notes, fmt.Sprintf("-passive: %d query names from %d archived URLs of %s", len(seen), len(lines), strings.Join(domains, ", ")))
	return append(own, rest...), nil
}

// writeParamsJSON writes arjun's file: one object, a key per page.
func writeParamsJSON(path string, rows []paramsRow, headers map[string]string) error {
	out := map[string]any{}
	for _, r := range rows {
		out[r.URL] = map[string]any{"params": r.Params, "method": r.Method, "headers": headers}
	}
	raw, err := json.MarshalIndent(out, "", "    ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o644)
}

// requestOf is how a page with the names found would be asked: the URL
// for GET; for a body method the URL and the body.
func requestOf(r paramsRow) (target, body, ctype string) {
	switch r.Method {
	case "POST", "JSON", "XML":
		var b strings.Builder
		switch r.Method {
		case "JSON":
			m := map[string]string{}
			for i, n := range r.Params {
				m[n] = fmt.Sprint(1234 + i)
			}
			raw, _ := json.Marshal(m)
			return r.URL, string(raw), "application/json"
		case "XML":
			b.WriteString("<root>")
			for i, n := range r.Params {
				fmt.Fprintf(&b, "<%s>%d</%s>", n, 1234+i, n)
			}
			b.WriteString("</root>")
			return r.URL, b.String(), "application/xml"
		}
		for i, n := range r.Params {
			if i > 0 {
				b.WriteByte('&')
			}
			fmt.Fprintf(&b, "%s=%d", url.QueryEscape(n), 1234+i)
		}
		return r.URL, b.String(), "application/x-www-form-urlencoded"
	}
	var b strings.Builder
	for i, n := range r.Params {
		if i > 0 {
			b.WriteByte('&')
		}
		fmt.Fprintf(&b, "%s=%d", url.QueryEscape(n), 1234+i)
	}
	return r.URL + "?" + b.String(), "", ""
}

// writeParamsText writes one request per line: the URL with the names for
// GET; for a body method the URL, a tab, and the body.
func writeParamsText(path string, rows []paramsRow) error {
	var b strings.Builder
	for _, r := range rows {
		t, body, _ := requestOf(r)
		if body != "" {
			t += "\t" + body
		}
		b.WriteString(t + "\n")
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

// replayToProxy sends each page with the names found through a proxy, so
// that a tool listening there (Burp) has the requests. They are counted in
// the budget, paced, and in the ledger. It returns what to say about it.
func replayToProxy(hostport string, rows []paramsRow, rate float64) string {
	pu, err := url.Parse("http://" + strings.TrimPrefix(hostport, "http://"))
	if err != nil || pu.Host == "" {
		return fmt.Sprintf("-oB %q is not HOST:PORT: nothing was replayed", hostport)
	}
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: ledger.Wrap(&http.Transport{
			Proxy:           http.ProxyURL(pu),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12},
		}),
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	sent, failed := 0, 0
	var last error
	for _, r := range rows {
		target, body, ctype := requestOf(r)
		method := http.MethodGet
		if body != "" {
			method = http.MethodPost
		}
		req, err := http.NewRequest(method, target, strings.NewReader(body))
		if err != nil {
			failed++
			last = err
			continue
		}
		if ctype != "" {
			req.Header.Set("Content-Type", ctype)
		}
		fetch.ApplyHeaders(req)
		if err := fetch.Spend(context.Background()); err != nil {
			return fmt.Sprintf("-oB: %d of %d pages were sent through %s; the rest were not: %v", sent, len(rows), hostport, err)
		}
		if rate > 0 {
			time.Sleep(time.Duration(float64(time.Second) / rate))
		}
		resp, err := client.Do(req)
		if err != nil {
			failed++
			last = err
			continue
		}
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		sent++
	}
	if failed > 0 {
		return fmt.Sprintf("-oB: %d of %d pages were sent through %s, %d failed (%v)", sent, len(rows), hostport, failed, last)
	}
	return fmt.Sprintf("-oB: %d pages with their names were sent through %s", sent, hostport)
}
