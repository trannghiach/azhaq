package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"maps"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/trannghiach/azhaq/catalog"
	"github.com/trannghiach/azhaq/collectors"
	"github.com/trannghiach/azhaq/engine"
	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/internal/fingerprint"
	"github.com/trannghiach/azhaq/internal/normalize"
	"github.com/trannghiach/azhaq/store"
	"github.com/trannghiach/azhaq/types"
)

// The drop-in commands are run with a preset: one job, results on stdout
// one per line (or JSONL) as they come, a summary and progress on stderr,
// input from flags, a file or stdin. They fit where subfinder, httpx,
// katana, gau and dnsx sit in a pipeline.

// common holds the flags every drop-in command takes.
type common struct {
	json, silent bool
	out          string
	db           string
	appendOut    bool // -o appends and makes its directory (subs, as subfinder)
}

func (c *common) register(fs *flag.FlagSet) {
	fs.BoolVar(&c.json, "json", false, "JSONL output, and the summary as one JSON object on stderr")
	fs.BoolVar(&c.silent, "silent", false, "results only: no progress; the summary only when something failed")
	fs.StringVar(&c.out, "o", "", "also write results to this file")
	fs.StringVar(&c.db, "db", "", "keep the graph in this database for query, show, export and diff (default: a temporary one)")
}

// runFlags is run's flag set, read once, for the commands that pass
// flags on to it.
var runFlags = sync.OnceValue(func() *flag.FlagSet { return flagsOf("run") })

// inherit gives fs run's flags of these names, with run's types, defaults
// and help. A name may be "local=run-name" (dirs -e is run's -dirs-ext).
// The function returned lists the ones given, as run flags.
func inherit(fs *flag.FlagSet, specs ...string) func() []string {
	type pair struct{ local, remote string }
	var ps []pair
	renamed := map[string]string{}
	for _, spec := range specs {
		local, remote, ok := strings.Cut(spec, "=")
		if !ok {
			remote = local
		}
		ps = append(ps, pair{local, remote})
		renamed[remote] = local
	}
	for _, p := range ps {
		f := runFlags().Lookup(p.remote)
		if f == nil {
			panic("azhaq: run has no -" + p.remote)
		}
		// The help names run's flags; here they go by their local names
		// (dirs -rate says -t, not -dirs-threads).
		usage := flagName.ReplaceAllStringFunc(f.Usage, func(m string) string {
			if local, ok := renamed[m[1:]]; ok {
				return "-" + local
			}
			return m
		})
		if _, ok := f.Value.(*stringsFlag); ok {
			fs.Var(new(stringsFlag), p.local, usage)
		} else {
			var v any
			if g, ok := f.Value.(flag.Getter); ok {
				v = g.Get()
			}
			switch d := v.(type) {
			case bool:
				fs.Bool(p.local, d, usage)
			case int:
				fs.Int(p.local, d, usage)
			case int64:
				fs.Int64(p.local, d, usage)
			case float64:
				fs.Float64(p.local, d, usage)
			case time.Duration:
				fs.Duration(p.local, d, usage)
			default:
				fs.String(p.local, f.DefValue, usage)
			}
		}
	}
	return func() []string {
		given := map[string]bool{}
		fs.Visit(func(f *flag.Flag) { given[f.Name] = true })
		var out []string
		for _, p := range ps {
			if !given[p.local] {
				continue
			}
			f := fs.Lookup(p.local)
			if sf, ok := f.Value.(*stringsFlag); ok {
				for _, v := range *sf {
					out = append(out, "-"+p.remote, v)
				}
				continue
			}
			out = append(out, "-"+p.remote+"="+f.Value.String())
		}
		return out
	}
}

// flagName is a flag a help text names: -dirs-threads, not the -empty of
// non-empty.
var flagName = regexp.MustCompile(`\B-[a-z][a-z0-9-]*[a-z0-9]`)

// targetFlags are the flags of every command that sends requests to
// targets: scope, pace, budget, time, session.
var targetFlags = []string{"scope", "program", "allow", "deny", "rate", "max-requests", "timeout", "H=header", "cookie", "v", "ledger", "kill-file"}

// inputs gathers targets from repeatable flags, a file ("-" for stdin),
// or stdin when it is a pipe and nothing else was given.
func inputs(values []string, file string) ([]string, error) {
	out := append([]string(nil), values...)
	switch {
	case file == "-":
		lines, err := readLines(os.Stdin)
		if err != nil {
			return nil, err
		}
		out = append(out, lines...)
	case file != "":
		lines, err := loadLines(file)
		if err != nil {
			return nil, err
		}
		out = append(out, lines...)
	case len(out) == 0 && stdinPiped():
		lines, err := readLines(os.Stdin)
		if err != nil {
			return nil, err
		}
		out = append(out, lines...)
	}
	return out, nil
}

func stdinPiped() bool {
	fi, err := os.Stdin.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice == 0
}

// allCollectors names every built-in collector, for -skip lists.
func allCollectors() []string {
	cat := catalog.New()
	collectors.Register(cat, collectors.Options{})
	return cat.Names()
}

func skipAllBut(keep ...string) string {
	k := map[string]bool{}
	for _, n := range keep {
		k[n] = true
	}
	var skip []string
	for _, n := range allCollectors() {
		if !k[n] {
			skip = append(skip, n)
		}
	}
	return strings.Join(skip, ",")
}

// runPreset maps with args into c.db or a temporary database, with the
// map off (stdout is the command's), and opens the database for reading.
// see, when set, gets every observation as it is stored.
func runPreset(c *common, args []string, rep *report, see func(types.Entity, types.Observation)) (*store.Store, func(), error) {
	db, dir := c.db, ""
	if db == "" {
		d, err := os.MkdirTemp("", "azhaq-")
		if err != nil {
			return nil, nil, err
		}
		dir, db = d, filepath.Join(d, "run.db")
	}
	if c.silent || c.json {
		args = append(args, "-quiet")
	}
	observer = see
	out := runOut{embedded: true, scratch: dir != ""}
	err := mapTarget(append(args, "-db", db), rep, &out)
	observer = nil
	if dir != "" {
		rep.DB = "" // gone when the command ends
		if rep.Resume != "" {
			rep.Resume = ""
			rep.Notes = append(rep.Notes, "the database was temporary: give -db FILE to be able to resume a stopped run")
		}
	}
	if err != nil {
		if dir != "" {
			os.RemoveAll(dir)
		}
		return nil, nil, err
	}
	st, err := store.OpenExisting(db)
	if err != nil {
		return nil, nil, err
	}
	if runs, err := st.Runs(); err == nil && len(runs) > 0 {
		st.UseRun(runs[len(runs)-1].ID)
	}
	return st, func() {
		st.Close()
		if dir != "" {
			os.RemoveAll(dir)
		}
	}, nil
}

// writer prints results to stdout and, with -o, to a file, a line at a
// time: commands print from the goroutines that find the results.
type writer struct {
	mu   sync.Mutex
	w    *bufio.Writer
	f    *os.File
	json bool
	n    int
}

func newWriter(c *common) (*writer, error) {
	var dst io.Writer = os.Stdout
	var f *os.File
	if c.out != "" {
		if st, err := os.Stat(c.out); err == nil && st.IsDir() {
			return nil, usagef("-o %s is a directory: -o names the file the results are written to", c.out)
		}
		var err error
		if c.appendOut {
			if err = os.MkdirAll(filepath.Dir(c.out), 0o755); err != nil {
				return nil, err
			}
			f, err = os.OpenFile(c.out, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		} else {
			f, err = os.Create(c.out)
		}
		if err != nil {
			return nil, err
		}
		dst = io.MultiWriter(os.Stdout, f)
	}
	return &writer{w: bufio.NewWriter(dst), f: f, json: c.json}, nil
}

func (w *writer) line(s string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.w.WriteString(s + "\n")
	w.w.Flush()
	w.n++
}

func (w *writer) obj(v any) {
	raw, _ := json.Marshal(v)
	w.mu.Lock()
	defer w.mu.Unlock()
	w.w.Write(append(raw, '\n'))
	w.w.Flush()
	w.n++
}

func (w *writer) count() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.n
}

func (w *writer) close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	err := w.w.Flush()
	if w.f != nil {
		if cerr := w.f.Close(); err == nil {
			err = cerr
		}
	}
	return err
}

func tempList(lines []string) (string, func(), error) {
	f, err := os.CreateTemp("", "azhaq-list-")
	if err != nil {
		return "", nil, err
	}
	_, err = f.WriteString(strings.Join(lines, "\n") + "\n")
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return f.Name(), func() { os.Remove(f.Name()) }, err
}

func payloads(st *store.Store, collector string) []map[string]any {
	obs, _ := st.Observations()
	var out []map[string]any
	for _, o := range obs {
		if o.Collector != collector || o.Kind == "error" {
			continue
		}
		var p map[string]any
		if json.Unmarshal(o.Payload, &p) == nil {
			out = append(out, p)
		}
	}
	return out
}

// liveNames maps each name azhaq-dns resolved (wildcard answers left out)
// to its payload.
func liveNames(st *store.Store) map[string]map[string]any {
	out := map[string]map[string]any{}
	obs, _ := st.Observations()
	for _, o := range obs {
		if o.Collector != "azhaq-dns" && o.Kind != "dns" {
			continue // dnsx and httpx answers taken in with ingest count too
		}
		var p map[string]any
		if json.Unmarshal(o.Payload, &p) != nil {
			continue
		}
		if name, _ := p["fqdn"].(string); live(p) && name != "" && out[name] == nil {
			out[name] = p
		}
	}
	return out
}

// dnsFields puts a live name's answer on its row with dnsx's names: the
// IPv4 addresses in a, the IPv6 ones in aaaa, the CNAME chain in cname,
// and the CDN or WAF in front.
func dnsFields(row, p map[string]any) {
	var a, aaaa []string
	for _, ip := range strs(p["ips"]) {
		if strings.Contains(ip, ":") {
			aaaa = append(aaaa, ip)
		} else {
			a = append(a, ip)
		}
	}
	row["a"] = a
	if len(aaaa) > 0 {
		row["aaaa"] = aaaa
	}
	if cn := strs(p["cnames"]); len(cn) > 0 {
		row["cname"] = cn
	}
	if cdn, _ := p["cdn"].(string); cdn != "" {
		row["cdn"] = cdn
	}
}

// live: a DNS payload with addresses that are not a wildcard's.
func live(p map[string]any) bool {
	ips, ok := p["ips"].([]any)
	return ok && len(ips) > 0 && p["wildcard"] == nil
}

func strs(v any) []string {
	xs, _ := v.([]any)
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		out = append(out, fmt.Sprint(x))
	}
	return out
}

// intOf reads a JSON number as an int (1048576, not 1.048576e+06).
func intOf(v any) int {
	f, _ := v.(float64)
	return int(f)
}

func payloadOf(o types.Observation) map[string]any {
	var p map[string]any
	_ = json.Unmarshal(o.Payload, &p)
	return p
}

// apexOf is the domain of apexes that name is under.
func apexOf(name string, apexes []string) string {
	for _, a := range apexes {
		if name == a || strings.HasSuffix(name, "."+a) {
			return a
		}
	}
	return ""
}

// probeOut prints web services as azhaq-http reports them, like httpx.
type probeOut struct {
	w     *writer
	c     *common
	mu    sync.Mutex
	cdn   map[string][2]string
	seen  map[string]bool
	input map[string]string // seed key → the target as given
}

func (p *probeOut) see(ent types.Entity, o types.Observation) {
	switch o.Collector {
	case "azhaq-dns":
		m := payloadOf(o)
		fqdn, _ := m["fqdn"].(string)
		name, _ := m["cdn"].(string)
		kind, _ := m["cdn_type"].(string)
		if fqdn != "" && name != "" {
			p.mu.Lock()
			p.cdn[fqdn] = [2]string{name, kind}
			p.mu.Unlock()
		}
	case "azhaq-http":
		r, ok := engine.ProbeRowOf(o)
		if !ok {
			return
		}
		p.mu.Lock()
		dup := p.seen[r.URL]
		p.seen[r.URL] = true
		host := normalize.HostFromURL(r.URL)
		c, known := p.cdn[host]
		p.mu.Unlock()
		if dup {
			return
		}
		var addrs []string
		if net.ParseIP(host) == nil {
			addrs = fetch.Resolve(context.Background(), host) // the answer HTTP connected with
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
		switch {
		case p.w.json:
			in := p.input[ent.Key]
			if in == "" {
				in = ent.Key
			}
			p.w.obj(httpxRow(r, in, addrs))
		case p.c.silent:
			p.w.line(r.URL)
		default:
			p.w.line(r.Line())
		}
	}
}

// cmdProbe is httpx: one line per web service, as each answers.
func cmdProbe(args []string) error {
	fs := newFlags("probe")
	var c common
	c.register(fs)
	var urls stringsFlag
	fs.Var(&urls, "u", "target: URL, host, host:port or IP (repeatable)")
	list := fs.String("l", "", "file of targets (- for stdin)")
	given := inherit(fs, append([]string{"web-ports", "parallel", "host-parallel", "delay", "no-follow", "no-tech", "resolvers"}, targetFlags...)...)
	favicon := fs.Bool("favicon", false, "also hash each front page's favicon (one or two more requests per service)")
	if err := parse(fs, args); err != nil {
		return err
	}
	targets, err := inputs(urls, *list)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return usagef("give -u TARGET, -l FILE or targets on stdin")
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
	// httpx's input field is the line as given, not the URL it became.
	input := map[string]string{}
	for _, t := range targets {
		if s, err := listSeed(t); err == nil {
			input[normalize.Seed(s).Key()] = t
		}
	}
	out := &probeOut{w: w, c: &c, cdn: map[string][2]string{}, seen: map[string]bool{}, input: input}
	rep := newReport("probe")
	rep.what = "web services"
	run := append([]string{"-list", path, "-probe"}, given()...)
	if !*favicon {
		run = append(run, "-no-favicon")
	}
	st, done, err := runPreset(&c, run, rep, out.see)
	if err != nil {
		return err
	}
	defer done()
	if err := w.close(); err != nil {
		return err
	}
	rep.Results, rep.Counts = w.count(), nil
	if quiet := silentHosts(st); len(quiet) > 0 {
		rep.Counts = map[string]int{"hosts without a web service": len(quiet)}
		// Every target ends as a service, a failure or a skip: a name
		// that resolved and has neither is a gap, said as a failure.
		accounted := map[string]bool{}
		for _, f := range rep.Failed {
			for _, t := range f.Targets {
				accounted[normalize.HostFromURL(t)], accounted[t] = true, true
			}
		}
		for _, sk := range rep.Skipped {
			accounted[normalize.HostFromURL(sk.Target)], accounted[sk.Target] = true, true
		}
		var gaps []string
		for _, h := range quiet {
			if !accounted[h] {
				gaps = append(gaps, h)
			}
		}
		if len(gaps) > 0 {
			rep.Failed = append(rep.Failed, engine.Failure{Collector: "azhaq-http", Error: "no answer and no failure recorded", Retryable: true, Count: len(gaps), Targets: gaps})
		}
	}
	return rep.finish(c.json, c.silent)
}

// silentHosts are the names that resolved but answered no web request:
// no service on the ports tried, or a filter that drops the requests.
func silentHosts(st *store.Store) []string {
	ents, _ := st.Entities()
	obs, _ := st.Observations()
	byID := map[string]string{}
	for _, e := range ents {
		byID[e.ID] = e.Key
	}
	resolved, answered := map[string]bool{}, map[string]bool{}
	for _, o := range obs {
		var p map[string]any
		_ = json.Unmarshal(o.Payload, &p)
		switch o.Collector {
		case "azhaq-dns":
			if live(p) {
				resolved[byID[o.EntityID]] = true
			}
		case "azhaq-http":
			if u, _ := p["url"].(string); u != "" {
				answered[normalize.HostFromURL(u)] = true
			}
		}
	}
	var out []string
	for h := range resolved {
		if !answered[h] {
			out = append(out, h)
		}
	}
	sort.Strings(out)
	return out
}

// httpxRow names the fields the way httpx -json does (v1.12): host is the
// name, host_ip the address the request connected to, a the addresses the
// name resolved to, status_code the first answer (a 302 stays a 302, as
// httpx prints it without -fr). Where a redirect chain led within the
// scope, final_url and final_status_code say where it ended.
func httpxRow(r engine.ProbeRow, input string, addrs []string) map[string]any {
	status := r.Status
	u, _ := url.Parse(r.URL)
	host, port, scheme, path := "", "", "", "/"
	if u != nil {
		host, scheme = u.Hostname(), u.Scheme
		port = u.Port()
		if port == "" {
			port = map[string]string{"http": "80", "https": "443"}[scheme]
		}
		if u.Path != "" {
			path = u.Path
		}
	}
	if input == "" {
		input = host
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
	out := map[string]any{
		"timestamp": time.Now().Format(time.RFC3339Nano), "url": strings.TrimSuffix(r.URL, "/"), "input": input,
		"host": host, "host_ip": r.IP, "port": port, "scheme": scheme, "path": path, "method": "GET",
		"status_code": status, "content_length": r.Length, "words": r.Words, "lines": r.Lines,
		"time": fmt.Sprintf("%dms", r.MS), "a": a, "failed": false,
	}
	if len(aaaa) > 0 {
		out["aaaa"] = aaaa
	}
	for k, v := range map[string]string{"title": r.Title, "webserver": r.Server, "content_type": r.ContentType} {
		if v != "" {
			out[k] = v
		}
	}
	if len(r.Tech) > 0 {
		out["tech"] = r.Tech
	}
	if r.Favicon != "" {
		out["favicon"] = r.Favicon
	}
	if r.CDN != "" {
		out["cdn"], out["cdn_name"], out["cdn_type"] = r.CDNType != "cloud", r.CDN, r.CDNType
	}
	if r.FinalURL != "" {
		out["final_url"] = r.FinalURL
	}
	if r.FinalStatus != 0 {
		out["final_status_code"] = r.FinalStatus
		out["chain_status_codes"] = []int{r.Status, r.FinalStatus}
	}
	if r.Location != "" {
		out["location"] = r.Location
	}
	if r.CatchAll {
		out["catchall"] = true
	}
	return out
}

// cmdCrawl is katana: the URLs of an application, visited or found in its
// pages, scripts and API descriptions.
func cmdCrawl(args []string) error {
	fs := newFlags("crawl")
	var c common
	c.register(fs)
	var urls stringsFlag
	fs.Var(&urls, "u", "start URL (repeatable)")
	list := fs.String("l", "", "file of start URLs (- for stdin)")
	given := inherit(fs, append([]string{"depth", "max-items", "parallel", "host-parallel", "delay", "paths", "browser", "browser-writes", "login", "login-user", "login-pass"}, targetFlags...)...)
	assets := fs.Bool("assets", false, "also list scripts, styles and images")
	noShell := fs.Bool("no-catchall", false, "leave out URLs that answer with the page every unknown path gets (client-side routes of a single-page app)")
	if err := parse(fs, args); err != nil {
		return err
	}
	targets, err := inputs(urls, *list)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return usagef("give -u URL, -l FILE or URLs on stdin")
	}
	for i, t := range targets {
		if !strings.Contains(t, "://") {
			targets[i] = "https://" + t + "/"
		}
	}
	path, rm, err := tempList(targets)
	if err != nil {
		return err
	}
	defer rm()
	rep := newReport("crawl")
	rep.what = "URLs"
	// The application only: no subdomain, archive or certificate fan-out.
	run := []string{"-list", path, "-skip", "azhaq-subdomains,azhaq-urls,azhaq-rdap,azhaq-tls,azhaq-cloud"}
	st, done, err := runPreset(&c, append(run, given()...), rep, nil)
	if err != nil {
		return err
	}
	defer done()
	ents, _ := st.Entities()
	obs, _ := st.Observations()
	edges, _ := st.Edges()
	seeds, _ := st.LoadSeeds()
	leftover, _ := st.LoadLeftover()
	rows := engine.BuildMap(ents, engine.ScopeSeeds(seeds, ents, edges), obs, leftover, false)
	w, err := newWriter(&c)
	if err != nil {
		return err
	}
	counts := map[string]int{}
	for _, r := range rows {
		if r.Entity.Type != types.TypeURL || (*noShell && r.Coverage == "catchall") || r.Scope != "target" {
			continue
		}
		if !*assets && (r.Role == "script" || r.Role == "asset" || r.Role == "sourcemap" || r.Role == "manifest") {
			continue
		}
		if !w.json && strings.Contains(r.Entity.Key, "{") {
			continue // a route with a parameter (/api/Cards/{id}) is no URL to request; -json lists it
		}
		if !w.json && (r.Role == "client-route" || r.Role == "websocket") {
			continue // a view the app draws, a socket: no page a GET gets; -json lists them
		}
		counts[r.Coverage]++
		if w.json {
			row := mapRowJSON(r)
			row["url"] = r.Entity.Key
			delete(row, "key")
			delete(row, "type")
			w.obj(row)
		} else {
			w.line(r.Entity.Key)
		}
	}
	if err := w.close(); err != nil {
		return err
	}
	rep.Results, rep.Counts = w.count(), counts
	return rep.finish(c.json, c.silent)
}

// cmdURLs is gau: every archived URL of the domains.
func cmdURLs(args []string) error {
	fs := newFlags("urls")
	var c common
	c.register(fs)
	var domains stringsFlag
	fs.Var(&domains, "d", "domain (repeatable)")
	list := fs.String("dL", "", "file of domains (- for stdin)")
	given := inherit(fs, "providers", "urls-timeout", "timeout", "v", "fail-on-errors")
	if err := parse(fs, args); err != nil {
		return err
	}
	ds, err := inputs(domains, *list)
	if err != nil {
		return err
	}
	if len(ds) == 0 {
		return usagef("give -d DOMAIN, -dL FILE or domains on stdin")
	}
	f, err := os.CreateTemp("", "azhaq-urls-")
	if err != nil {
		return err
	}
	f.Close()
	defer os.Remove(f.Name())
	rep := newReport("urls")
	rep.what = "archived URLs"
	run := []string{"-passive", "-depth", "0", "-skip", skipAllBut("azhaq-urls"), "-urls", f.Name(), "-urls-source"}
	for _, d := range ds {
		run = append(run, "-domain", d)
	}
	_, done, err := runPreset(&c, append(run, given()...), rep, nil)
	if err != nil {
		return err
	}
	defer done()
	lines, err := loadLines(f.Name())
	if err != nil {
		return err
	}
	w, err := newWriter(&c)
	if err != nil {
		return err
	}
	for _, l := range lines {
		u, src, _ := strings.Cut(l, "\t")
		if w.json {
			w.obj(map[string]string{"url": u, "source": src})
		} else {
			w.line(u)
		}
	}
	if err := w.close(); err != nil {
		return err
	}
	rep.Results = w.count()
	return rep.finish(c.json, c.silent)
}

// cmdDNS is dnsx: the names that resolve, wildcard answers left out, as
// they resolve.
func cmdDNS(args []string) error {
	fs := newFlags("dns")
	var c common
	c.register(fs)
	var names stringsFlag
	fs.Var(&names, "d", "name (repeatable)")
	list := fs.String("l", "", "file of names (- for stdin)")
	resp := fs.Bool("resp", false, "print the records after each name")
	words := fs.String("w", "", "with -d DOMAIN: resolve WORD.DOMAIN for each word in this file instead, as dnsx -d -w (wildcard answers left out)")
	given := inherit(fs, "resolvers", "dns-rate", "timeout", "v")
	if err := parse(fs, args); err != nil {
		return err
	}
	ns, err := inputs(names, *list)
	if err != nil {
		return err
	}
	if len(ns) == 0 {
		return usagef("give -d NAME, -l FILE or names on stdin")
	}
	path, rm, err := tempList(ns)
	if err != nil {
		return err
	}
	defer rm()
	run := []string{"-list", path, "-passive", "-depth", "0", "-skip", skipAllBut("azhaq-dns")}
	if *words != "" {
		// The guesses are found by azhaq-dns-brute and resolved again by
		// azhaq-dns for their records, one wave later.
		run = []string{"-passive", "-depth", "2", "-skip", skipAllBut("azhaq-dns", "azhaq-dns-brute"), "-dns-brute", *words}
		for _, d := range ns {
			h := normalize.Hostname(d)
			if h == "" || strings.ContainsAny(h, "/: ") {
				return usagef("-w wants -d DOMAIN such as example.com, got %q", d)
			}
			run = append(run, "-domain", h, "-allow", h) // the domains given are the scope of the guesses
		}
	}
	w, err := newWriter(&c)
	if err != nil {
		return err
	}
	var mu sync.Mutex
	printed := map[string]bool{}
	see := func(_ types.Entity, o types.Observation) {
		if o.Collector != "azhaq-dns" {
			return
		}
		p := payloadOf(o)
		name, _ := p["fqdn"].(string)
		if name == "" || !live(p) {
			return
		}
		mu.Lock()
		dup := printed[name]
		printed[name] = true
		mu.Unlock()
		if dup {
			return
		}
		var a, aaaa []string
		for _, ip := range strs(p["ips"]) {
			if strings.Contains(ip, ":") {
				aaaa = append(aaaa, ip)
			} else {
				a = append(a, ip)
			}
		}
		cnames := strs(p["cnames"])
		switch {
		case w.json:
			row := map[string]any{"host": name, "a": a, "aaaa": aaaa, "cname": cnames, "status_code": "NOERROR"}
			if cdn, ok := p["cdn"].(string); ok {
				row["cdn_name"] = cdn
			}
			w.obj(row)
		case *resp:
			w.line(name + " [" + strings.Join(append(append(a, aaaa...), cnames...), ",") + "]")
		default:
			w.line(name)
		}
	}
	rep := newReport("dns")
	rep.what = "live names"
	_, done, err := runPreset(&c, append(run, given()...), rep, see)
	if err != nil {
		return err
	}
	defer done()
	if err := w.close(); err != nil {
		return err
	}
	rep.Results = w.count()
	asked := map[string]bool{}
	for _, n := range ns {
		if h := normalize.Hostname(n); h != "" {
			asked[h] = true
		}
	}
	if *words != "" {
		return rep.finish(c.json, c.silent) // the words are the asked names
	}
	rep.Counts = map[string]int{"asked": len(asked)}
	if d := len(asked) - rep.Results; d > 0 {
		rep.Counts["did not resolve"] = d // NXDOMAIN, no address, or a wildcard's answer
	}
	return rep.finish(c.json, c.silent)
}

// cmdPorts is naabu (connect scan): host:port per open port, as each host
// is scanned. The hosts given are the scope.
func cmdPorts(args []string) error {
	fs := newFlags("ports")
	var c common
	c.register(fs)
	var hosts stringsFlag
	fs.Var(&hosts, "host", "host or IP (repeatable)")
	list := fs.String("l", "", "file of hosts (- for stdin)")
	spec := fs.String("p", "top-100", "ports: top-100, top-1000, full, none, or a list of ports, ranges and these names, such as 22,80,8000-8100 or top-100,8888")
	udp := fs.Bool("udp", false, "also ask the common UDP ports (about 20: dns, ntp, snmp, ssdp, mdns, ...)")
	udpSpec := fs.String("pu", "", "UDP ports to ask: top, full or a list of ports, ranges and these names, such as 53,123,1-1024 or top,5354 (implies -udp)")
	given := inherit(fs, "rate=port-rate", "max-requests", "resolvers", "timeout", "v", "scope", "program", "allow", "deny", "ledger", "kill-file")
	if err := parse(fs, args); err != nil {
		return err
	}
	hs, err := inputs(hosts, *list)
	if err != nil {
		return err
	}
	if len(hs) == 0 {
		return usagef("give -host HOST, -l FILE or hosts on stdin")
	}
	path, rm, err := tempList(hs)
	if err != nil {
		return err
	}
	defer rm()
	w, err := newWriter(&c)
	if err != nil {
		return err
	}
	var mu sync.Mutex
	seen := map[string]bool{}
	see := func(_ types.Entity, o types.Observation) {
		if o.Collector != "azhaq-ports" {
			return
		}
		p := payloadOf(o)
		host, _ := p["host"].(string)
		ip, _ := p["ip"].(string)
		services, _ := p["services"].([]any)
		for _, s := range services {
			svc, _ := s.(map[string]any)
			port := fmt.Sprint(svc["port"])
			key := host + ":" + port
			if w.json {
				key = ip + " " + key // a row per address, as naabu prints
			}
			mu.Lock()
			dup := seen[key]
			seen[key] = true
			mu.Unlock()
			if dup {
				continue
			}
			if !w.json {
				w.line(key)
				continue
			}
			n, _ := strconv.Atoi(port)
			row := map[string]any{"host": host, "ip": ip, "port": n, "protocol": "tcp", "tls": svc["tls"] == true, "timestamp": time.Now().Format(time.RFC3339Nano)}
			for _, k := range []string{"service", "product", "version", "title", "banner", "subject_cn", "subject_an"} {
				if v, ok := svc[k]; ok {
					row[k] = v
				}
			}
			w.obj(row)
		}
		udpServices, _ := p["udp_services"].([]any)
		for _, s := range udpServices {
			svc, _ := s.(map[string]any)
			port := fmt.Sprint(svc["port"])
			key := host + ":" + port + "/udp"
			if w.json {
				key = ip + " " + key
			}
			mu.Lock()
			dup := seen[key]
			seen[key] = true
			mu.Unlock()
			if dup {
				continue
			}
			if !w.json {
				if svc["state"] == "open" { // open|filtered rows are in the JSON
					w.line(host + ":" + port + "/udp")
				}
				continue
			}
			n, _ := strconv.Atoi(port)
			row := map[string]any{"host": host, "ip": ip, "port": n, "protocol": "udp", "timestamp": time.Now().Format(time.RFC3339Nano)}
			for _, k := range []string{"state", "service", "product", "version", "banner"} {
				if v, ok := svc[k]; ok {
					row[k] = v
				}
			}
			w.obj(row)
		}
	}
	rep := newReport("ports")
	rep.what = "open ports"
	run := []string{"-list", path, "-passive", "-depth", "0", "-skip", skipAllBut("azhaq-dns", "azhaq-ports"), "-ports", *spec}
	if *udpSpec != "" {
		run = append(run, "-ports-udp", *udpSpec)
	} else if *udp {
		run = append(run, "-ports-udp", "top")
	}
	extra := given()
	if !hasFlag(extra, "allow", "scope") {
		// The hosts given are the scope.
		for _, h := range hs {
			h = strings.TrimSpace(h)
			if host, _, err := net.SplitHostPort(h); err == nil {
				h = host
			}
			run = append(run, "-allow", h)
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
	return rep.finish(c.json, c.silent)
}

// hasFlag says whether args set one of the flags named.
func hasFlag(args []string, names ...string) bool {
	for _, a := range args {
		k, _, _ := strings.Cut(strings.TrimLeft(a, "-"), "=")
		if strings.HasPrefix(a, "-") && slices.Contains(names, k) {
			return true
		}
	}
	return false
}

// cmdDirs is ffuf with auto-calibration (feroxbuster with -depth): paths
// from a wordlist that answer differently from a path that cannot exist.
// The services given are the scope.
func cmdDirs(args []string) error {
	fs := newFlags("dirs")
	var c common
	c.register(fs)
	var urls stringsFlag
	fs.Var(&urls, "u", "web service, such as https://app.example.com/ (repeatable)")
	list := fs.String("l", "", "file of services (- for stdin)")
	words := fs.String("w", "", "wordlist (required)")
	given := inherit(fs, "e=dirs-ext", "depth=dirs-depth", "t=dirs-threads", "rate=dirs-rate", "mc=dirs-mc",
		"H=header", "cookie", "all-gets", "max-requests", "timeout", "v", "scope", "program", "allow", "deny", "ledger", "kill-file")
	if err := parse(fs, args); err != nil {
		return err
	}
	if *words == "" {
		return usagef("give a wordlist with -w")
	}
	targets, err := inputs(urls, *list)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return usagef("give -u URL, -l FILE or URLs on stdin")
	}
	for i, t := range targets {
		if !strings.Contains(t, "://") {
			targets[i] = "https://" + t + "/"
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
	failed := 0
	see := func(_ types.Entity, o types.Observation) {
		if o.Collector == "azhaq-dirs" && o.Kind == "dirs" {
			failed += intOf(payloadOf(o)["failed"])
			return
		}
		if o.Collector != "azhaq-dirs" || o.Kind != "url" {
			return
		}
		p := payloadOf(o)
		u, _ := p["url"].(string)
		switch {
		case u == "":
		case w.json:
			row := map[string]any{"url": u, "status": p["status"], "length": p["length"], "words": p["words"], "lines": p["lines"]}
			if loc, ok := p["location"]; ok {
				row["redirectlocation"] = loc
			}
			w.obj(row)
		case c.silent:
			w.line(u)
		default:
			w.line(fmt.Sprintf("%s [Status: %d, Size: %d, Words: %d, Lines: %d]", u, intOf(p["status"]), intOf(p["length"]), intOf(p["words"]), intOf(p["lines"])))
		}
	}
	rep := newReport("dirs")
	rep.what = "paths"
	// Paths, not technologies: probe names those (the fingerprints are 40 MB to load).
	run := []string{"-list", path, "-depth", "1", "-no-tech", "-no-favicon", "-skip", skipAllBut("azhaq-dns", "azhaq-http", "azhaq-dirs"), "-dirs", *words}
	extra := given()
	if !hasFlag(extra, "allow", "scope") {
		// The services given are the scope.
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
	if failed > 0 {
		rep.Notes = append(rep.Notes, fmt.Sprintf("%d paths got no whole answer, after one retry: they were not judged (a service under load cuts answers off; run again or lower -t)", failed))
	}
	return rep.finish(c.json, c.silent)
}

// cmdParams is arjun (GET): query parameters the pages read. The pages
// given are the scope.
func cmdParams(args []string) error {
	fs := newFlags("params")
	var c common
	c.register(fs)
	var urls stringsFlag
	fs.Var(&urls, "u", "page URL (repeatable)")
	list := fs.String("l", "", "file of page URLs (- for stdin)")
	words := fs.String("w", "", "parameter names, one per line (required)")
	given := inherit(fs, "rate=params-rate", "H=header", "cookie", "all-gets", "max-requests", "timeout", "v", "scope", "program", "allow", "deny", "ledger", "kill-file")
	if err := parse(fs, args); err != nil {
		return err
	}
	if *words == "" {
		return usagef("give parameter names with -w")
	}
	targets, err := inputs(urls, *list)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return usagef("give -u URL, -l FILE or URLs on stdin")
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
	see := func(_ types.Entity, o types.Observation) {
		if o.Collector != "azhaq-params" {
			return
		}
		p := payloadOf(o)
		u, _ := p["url"].(string)
		names := strs(p["params"])
		switch {
		case len(names) == 0:
		case w.json:
			w.obj(map[string]any{"url": u, "method": "GET", "params": names, "why": p["why"]})
		default:
			w.line(u + " " + strings.Join(names, ","))
		}
	}
	rep := newReport("params")
	rep.what = "pages with parameters"
	run := []string{"-list", path, "-depth", "1", "-no-tech", "-no-favicon", "-skip", skipAllBut("azhaq-dns", "azhaq-http", "azhaq-params"),
		"-params", *words, "-params-per-host", fmt.Sprint(len(targets))}
	extra := given()
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
	return rep.finish(c.json, c.silent)
}

// cmdASN is asnmap: the prefixes autonomous systems announce.
func cmdASN(args []string) error {
	fs := newFlags("asn")
	var c common
	c.register(fs)
	var asns stringsFlag
	fs.Var(&asns, "a", "AS number such as AS64500 (repeatable)")
	list := fs.String("l", "", "file of AS numbers (- for stdin)")
	given := inherit(fs, "timeout", "v")
	if err := parse(fs, args); err != nil {
		return err
	}
	as, err := inputs(asns, *list)
	if err != nil {
		return err
	}
	if len(as) == 0 {
		return usagef("give -a AS64500, -l FILE or AS numbers on stdin")
	}
	rep := newReport("asn")
	rep.what = "prefixes"
	run := []string{"-passive", "-depth", "0", "-skip", skipAllBut("azhaq-asn")}
	for _, a := range as {
		run = append(run, "-asn", a)
	}
	st, done, err := runPreset(&c, append(run, given()...), rep, nil)
	if err != nil {
		return err
	}
	defer done()
	w, err := newWriter(&c)
	if err != nil {
		return err
	}
	for _, p := range payloads(st, "azhaq-asn") {
		for _, x := range strs(p["prefixes"]) {
			if w.json {
				w.obj(map[string]any{"as_number": p["asn"], "as_name": p["holder"], "prefix": x})
			} else {
				w.line(x)
			}
		}
	}
	if err := w.close(); err != nil {
		return err
	}
	rep.Results = w.count()
	return rep.finish(c.json, c.silent)
}

// cmdShots is gowitness: a screenshot of each web service, with a
// perceptual hash to group look-alikes.
func cmdShots(args []string) error {
	fs := newFlags("shots")
	var c common
	c.register(fs)
	var urls stringsFlag
	fs.Var(&urls, "u", "target: URL, host, host:port or IP (repeatable)")
	list := fs.String("l", "", "file of targets (- for stdin)")
	dir := fs.String("dir", "screenshots", "directory for the PNG files")
	given := inherit(fs, append([]string{"tabs", "browser-writes"}, targetFlags...)...)
	if err := parse(fs, args); err != nil {
		return err
	}
	targets, err := inputs(urls, *list)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return usagef("give -u TARGET, -l FILE or targets on stdin")
	}
	if st, err := os.Stat(c.out); c.out != "" && err == nil && st.IsDir() {
		return usagef("-o %s is a directory: -o names the file the results are written to, the PNG files go to -dir", c.out)
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
	see := func(_ types.Entity, o types.Observation) {
		if o.Collector != "azhaq-shots" || o.Kind != "screenshot" {
			return // what Chrome refused, and the writes it mapped, are the summary's
		}
		p := payloadOf(o)
		if w.json {
			w.obj(p)
		} else {
			w.line(fmt.Sprintf("%v %v", p["url"], p["file"]))
		}
	}
	rep := newReport("shots")
	rep.what = "screenshots"
	run := []string{"-list", path, "-depth", "0", "-skip", skipAllBut("azhaq-dns", "azhaq-http", "azhaq-shots"), "-screenshots", *dir}
	_, done, err := runPreset(&c, append(run, given()...), rep, see)
	if err != nil {
		return err
	}
	defer done()
	if err := w.close(); err != nil {
		return err
	}
	rep.Results = w.count()
	return rep.finish(c.json, c.silent)
}

// slowSource names the source that set the wall time, when one took far
// longer than the rest: the user can drop it or give it less time.
func slowSource(domain string, srcs map[string]any) string {
	var slow string
	var first, second float64
	for name, v := range srcs {
		row, _ := v.(map[string]any)
		sec, ok := row["seconds"].(float64)
		if !ok || row["skipped"] != nil {
			continue
		}
		switch {
		case sec > first:
			slow, first, second = name, sec, first
		case sec > second:
			second = sec
		}
	}
	if first < 20 || first < 2*second {
		return ""
	}
	return fmt.Sprintf("%s: %s took %.0f s, the next slowest source %.0f s (-source-timeout bounds each source, -exclude-sources %s drops it, -v lists them all)", domain, slow, first, second, slow)
}

// guessCheck says where the time went when the DNS check of the names
// sources only guess (subdomain.center's) took long: its pace is -dns-rate.
func guessCheck(domain string, srcs map[string]any) string {
	var names []string
	var sec float64
	checked := 0
	for _, name := range slices.Sorted(maps.Keys(srcs)) {
		row, _ := srcs[name].(map[string]any)
		s, ok := row["checked_seconds"].(float64)
		if !ok {
			continue
		}
		names = append(names, name)
		sec = max(sec, s)
		checked += intOf(row["kept"]) + intOf(row["dropped_unresolved"])
	}
	if sec < 20 {
		return ""
	}
	return fmt.Sprintf("%s: checking the %d names %s guessed in DNS took %.0f s, before they were kept or dropped (-dns-rate paces it; -exclude-sources %s leaves them out)",
		domain, checked, strings.Join(names, ", "), sec, strings.Join(names, ","))
}

// sourceDetail is subs -v's line per domain: each source's names, time,
// calls when it was asked more than once, and error.
func sourceDetail(domain string, srcs map[string]any) string {
	var parts []string
	for _, name := range slices.Sorted(maps.Keys(srcs)) {
		row, _ := srcs[name].(map[string]any)
		if row["skipped"] != nil {
			continue
		}
		p := fmt.Sprintf("%s %v in %vs", name, row["count"], row["seconds"])
		if c, ok := row["calls"]; ok {
			p += fmt.Sprintf(" (%v calls)", c)
		}
		if e, ok := row["error"]; ok {
			p += fmt.Sprintf(" [%v]", e)
		}
		parts = append(parts, p)
	}
	return domain + " sources: " + strings.Join(parts, "; ")
}
