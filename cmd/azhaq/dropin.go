package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
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
	for _, spec := range specs {
		local, remote, ok := strings.Cut(spec, "=")
		if !ok {
			remote = local
		}
		f := runFlags().Lookup(remote)
		if f == nil {
			panic("azhaq: run has no -" + remote)
		}
		if _, ok := f.Value.(*stringsFlag); ok {
			fs.Var(new(stringsFlag), local, f.Usage)
		} else {
			var v any
			if g, ok := f.Value.(flag.Getter); ok {
				v = g.Get()
			}
			switch d := v.(type) {
			case bool:
				fs.Bool(local, d, f.Usage)
			case int:
				fs.Int(local, d, f.Usage)
			case int64:
				fs.Int64(local, d, f.Usage)
			case float64:
				fs.Float64(local, d, f.Usage)
			case time.Duration:
				fs.Duration(local, d, f.Usage)
			default:
				fs.String(local, f.DefValue, f.Usage)
			}
		}
		ps = append(ps, pair{local, remote})
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

// targetFlags are the flags of every command that sends requests to
// targets: scope, pace, budget, time, session.
var targetFlags = []string{"scope", "program", "allow", "deny", "rate", "max-requests", "timeout", "H=header", "cookie", "v"}

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
	if c.silent {
		args = append(args, "-quiet")
	}
	observer = see
	out := runOut{embedded: true}
	err := mapTarget(append(args, "-db", db), rep, &out)
	observer = nil
	if dir != "" {
		rep.DB = "" // gone when the command ends
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
		var err error
		if f, err = os.Create(c.out); err != nil {
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

func payloadOf(o types.Observation) map[string]any {
	var p map[string]any
	_ = json.Unmarshal(o.Payload, &p)
	return p
}

// cmdSubs is subfinder (and subfinder | dnsx with -live).
func cmdSubs(args []string) error {
	fs := newFlags("subs")
	var c common
	c.register(fs)
	var domains stringsFlag
	fs.Var(&domains, "d", "domain (repeatable)")
	list := fs.String("dL", "", "file of domains (- for stdin)")
	live := fs.Bool("live", false, "only names that resolve (wildcard answers left out)")
	given := inherit(fs, "sources", "exclude-sources", "all-sources", "providers", "resolvers", "dns-rate", "timeout", "v")
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
	rep := newReport("subs")
	rep.what = "names"
	keep := []string{"azhaq-subdomains"}
	if *live {
		keep = append(keep, "azhaq-dns")
		rep.what = "live names"
	}
	run := []string{"-passive", "-skip", skipAllBut(keep...)}
	for _, d := range ds {
		h := normalize.Hostname(d)
		if h == "" || strings.ContainsAny(h, "/: ") {
			return usagef("-d wants a domain such as example.com, got %q", d)
		}
		run = append(run, "-domain", h)
	}
	if !*live {
		// The names are known once the sources answer: no DNS to wait for.
		run = append(run, "-depth", "0")
	}
	st, done, err := runPreset(&c, append(run, given()...), rep, nil)
	if err != nil {
		return err
	}
	defer done()
	var alive map[string]map[string]any
	if *live {
		alive = liveNames(st)
	}
	w, err := newWriter(&c)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	answered, ran := 0, 0
	for _, p := range payloads(st, "azhaq-subdomains") {
		input, _ := p["domain"].(string)
		foundBy, _ := p["found_by"].(map[string]any)
		srcs, _ := p["sources"].(map[string]any)
		for _, v := range srcs {
			if row, _ := v.(map[string]any); row["skipped"] == nil {
				ran++
				if row["error"] == nil {
					answered++
				}
			}
		}
		for _, name := range strs(p["names"]) {
			if seen[name] || (alive != nil && alive[name] == nil) {
				continue
			}
			seen[name] = true
			if !w.json {
				w.line(name)
				continue
			}
			row := map[string]any{"host": name, "input": input}
			if by := strs(foundBy[name]); len(by) > 0 {
				row["source"], row["sources"] = by[0], by
			}
			if alive != nil {
				row["a"] = strs(alive[name]["ips"])
			}
			w.obj(row)
		}
	}
	if err := w.close(); err != nil {
		return err
	}
	rep.Results = w.count()
	rep.Counts = map[string]int{"sources asked": ran, "sources failed": ran - answered}
	if c.db != "" {
		rep.Next = append(rep.Next, "azhaq query -db "+c.db+" -type Hostname")
	}
	return rep.finish(c.json, c.silent)
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
		if net.ParseIP(host) == nil && fetch.Resolver != nil {
			addrs = fetch.Resolver(context.Background(), host) // the answer HTTP connected with
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
	given := inherit(fs, append([]string{"web-ports", "parallel", "host-parallel", "delay", "no-tech", "resolvers"}, targetFlags...)...)
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
// name resolved to.
func httpxRow(r engine.ProbeRow, input string, addrs []string) map[string]any {
	status := r.Status
	if r.FinalStatus != 0 {
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
	given := inherit(fs, append([]string{"depth", "max-items", "parallel", "host-parallel", "delay", "paths", "browser", "login", "login-user", "login-pass"}, targetFlags...)...)
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
		if !*assets && (r.Role == "script" || r.Role == "asset" || r.Role == "sourcemap") {
			continue
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
	given := inherit(fs, "providers", "urls-timeout", "timeout", "v")
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
	run := []string{"-passive", "-depth", "0", "-skip", skipAllBut("azhaq-urls"), "-urls", f.Name()}
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
	for _, u := range lines {
		if w.json {
			w.obj(map[string]string{"url": u})
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
	run := []string{"-list", path, "-passive", "-depth", "0", "-skip", skipAllBut("azhaq-dns")}
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

// cmdPorts is naabu (connect scan): host:port per open port, as each host
// is scanned. The hosts given are the scope.
func cmdPorts(args []string) error {
	fs := newFlags("ports")
	var c common
	c.register(fs)
	var hosts stringsFlag
	fs.Var(&hosts, "host", "host or IP (repeatable)")
	list := fs.String("l", "", "file of hosts (- for stdin)")
	spec := fs.String("p", "top-100", "ports: top-100, top-1000, full or a list such as 22,80,8000-8100")
	given := inherit(fs, "rate=port-rate", "resolvers", "timeout", "v", "scope", "program", "deny")
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
			row := map[string]any{"host": host, "ip": ip, "port": n, "protocol": "tcp", "tls": false, "timestamp": time.Now().Format(time.RFC3339Nano)}
			if v, ok := svc["service"]; ok {
				row["service"] = v
			}
			if v, ok := svc["banner"]; ok {
				row["banner"] = v
			}
			w.obj(row)
		}
	}
	rep := newReport("ports")
	rep.what = "open ports"
	run := []string{"-list", path, "-passive", "-depth", "0", "-skip", skipAllBut("azhaq-dns", "azhaq-ports"), "-ports", *spec}
	for _, h := range hs {
		h = strings.TrimSpace(h)
		if host, _, err := net.SplitHostPort(h); err == nil {
			h = host
		}
		run = append(run, "-allow", h)
	}
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
		"H=header", "cookie", "max-requests", "timeout", "v", "scope", "program", "deny")
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
	see := func(_ types.Entity, o types.Observation) {
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
			w.line(fmt.Sprintf("%s [Status: %v, Size: %v, Words: %v, Lines: %v]", u, p["status"], p["length"], p["words"], p["lines"]))
		}
	}
	rep := newReport("dirs")
	rep.what = "paths"
	run := []string{"-list", path, "-depth", "1", "-skip", skipAllBut("azhaq-dns", "azhaq-http", "azhaq-dirs"), "-dirs", *words}
	for _, t := range targets {
		if u, err := url.Parse(t); err == nil {
			run = append(run, "-allow", u.Hostname())
		}
	}
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
	given := inherit(fs, "rate=params-rate", "H=header", "cookie", "max-requests", "timeout", "v", "scope", "program", "deny")
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
	run := []string{"-list", path, "-depth", "1", "-skip", skipAllBut("azhaq-dns", "azhaq-http", "azhaq-params"),
		"-params", *words, "-params-per-host", fmt.Sprint(len(targets))}
	for _, t := range targets {
		if u, err := url.Parse(t); err == nil {
			run = append(run, "-allow", u.Hostname())
		}
	}
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
	given := inherit(fs, append([]string{"tabs"}, targetFlags...)...)
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
	see := func(_ types.Entity, o types.Observation) {
		if o.Collector != "azhaq-shots" {
			return
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
