package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/trannghiach/azhaq/catalog"
	"github.com/trannghiach/azhaq/collectors"
	"github.com/trannghiach/azhaq/engine"
	"github.com/trannghiach/azhaq/store"
	"github.com/trannghiach/azhaq/types"
)

// The drop-in commands are run with a preset: one job, results on stdout
// one per line (or JSONL), everything else on stderr, input from flags, a
// file or stdin. They fit where subfinder, httpx, katana, gau and dnsx sit
// in a pipeline.

// common holds the flags every drop-in command takes.
type common struct {
	json, silent bool
	out          string
	db           string
}

func (c *common) register(fs *flag.FlagSet) {
	fs.BoolVar(&c.json, "json", false, "JSONL output")
	fs.BoolVar(&c.silent, "silent", false, "results only: no progress or summary on stderr")
	fs.StringVar(&c.out, "o", "", "also write results to this file")
	fs.StringVar(&c.db, "db", "", "keep the graph in this database (default: a temporary one)")
}

// pass adds run flags that a drop-in command forwards as they are.
func pass(fs *flag.FlagSet, names ...string) map[string]*string {
	vals := map[string]*string{}
	for _, n := range names {
		vals[n] = fs.String(n, "", "see azhaq run -h")
	}
	return vals
}

func forward(vals map[string]*string) []string {
	var out []string
	keys := make([]string, 0, len(vals))
	for k := range vals {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if v := *vals[k]; v != "" {
			out = append(out, "-"+k, v)
		}
	}
	return out
}

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

// runPreset runs cmdRun with args into c.db or a temporary database and
// opens it for reading. Its own output goes to stderr, or nowhere with
// -silent.
func runPreset(c *common, args []string) (*store.Store, func(), error) {
	db, dir := c.db, ""
	if db == "" {
		d, err := os.MkdirTemp("", "azhaq-")
		if err != nil {
			return nil, nil, err
		}
		dir, db = d, filepath.Join(d, "run.db")
	}
	stdout := os.Stdout
	if c.silent {
		null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
		if err != nil {
			return nil, nil, err
		}
		defer null.Close()
		os.Stdout = null
	} else {
		os.Stdout = os.Stderr
	}
	err := cmdRun(append(args, "-db", db, "-quiet"))
	os.Stdout = stdout
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

// writer prints results to stdout and, with -o, to a file.
type writer struct {
	w    *bufio.Writer
	f    *os.File
	json bool
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

func (w *writer) line(s string) { w.w.WriteString(s + "\n") }

func (w *writer) obj(v any) {
	raw, _ := json.Marshal(v)
	w.w.Write(append(raw, '\n'))
}

func (w *writer) close() error {
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
		if o.Collector != collector {
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
	for _, p := range payloads(st, "azhaq-dns") {
		name, _ := p["fqdn"].(string)
		if ips, ok := p["ips"].([]any); ok && len(ips) > 0 && p["wildcard"] == nil && name != "" {
			out[name] = p
		}
	}
	return out
}

// cmdSubs is subfinder (and subfinder | dnsx with -live).
func cmdSubs(args []string) error {
	fs := flag.NewFlagSet("subs", flag.ContinueOnError)
	var c common
	c.register(fs)
	var domains stringsFlag
	fs.Var(&domains, "d", "domain (repeatable)")
	list := fs.String("dL", "", "file of domains (- for stdin)")
	live := fs.Bool("live", false, "only names that resolve (wildcard answers left out)")
	vals := pass(fs, "sources", "exclude-sources", "providers", "resolvers", "dns-rate")
	all := fs.Bool("all-sources", false, "also slower sources")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ds, err := inputs(domains, *list)
	if err != nil {
		return err
	}
	if len(ds) == 0 {
		return fmt.Errorf("give -d DOMAIN, -dL FILE or domains on stdin")
	}
	keep := []string{"azhaq-subdomains"}
	if *live {
		keep = append(keep, "azhaq-dns")
	}
	run := []string{"-passive", "-skip", skipAllBut(keep...)}
	for _, d := range ds {
		run = append(run, "-domain", d)
	}
	if *all {
		run = append(run, "-all-sources")
	}
	run = append(run, forward(vals)...)
	st, done, err := runPreset(&c, run)
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
	for _, p := range payloads(st, "azhaq-subdomains") {
		input, _ := p["domain"].(string)
		names, _ := p["names"].([]any)
		for _, n := range names {
			name, _ := n.(string)
			if name == "" || seen[name] || (alive != nil && alive[name] == nil) {
				continue
			}
			seen[name] = true
			if w.json {
				w.obj(map[string]any{"host": name, "input": input})
			} else {
				w.line(name)
			}
		}
	}
	return w.close()
}

// cmdProbe is httpx: one line per web service.
func cmdProbe(args []string) error {
	fs := flag.NewFlagSet("probe", flag.ContinueOnError)
	var c common
	c.register(fs)
	var urls stringsFlag
	fs.Var(&urls, "u", "target: URL, host, host:port or IP (repeatable)")
	list := fs.String("l", "", "file of targets (- for stdin)")
	vals := pass(fs, "web-ports", "parallel", "host-parallel", "delay")
	noTech := fs.Bool("no-tech", false, "skip technology fingerprints")
	var headers stringsFlag
	fs.Var(&headers, "H", "extra request header K: V (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	targets, err := inputs(urls, *list)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return fmt.Errorf("give -u TARGET, -l FILE or targets on stdin")
	}
	path, rm, err := tempList(targets)
	if err != nil {
		return err
	}
	defer rm()
	run := append([]string{"-list", path, "-probe"}, forward(vals)...)
	if *noTech {
		run = append(run, "-no-tech")
	}
	for _, h := range headers {
		run = append(run, "-header", h)
	}
	st, done, err := runPreset(&c, run)
	if err != nil {
		return err
	}
	defer done()
	obs, _ := st.Observations()
	ips := map[string][]string{}
	for host, p := range liveNames(st) {
		for _, ip := range p["ips"].([]any) {
			ips[host] = append(ips[host], fmt.Sprint(ip))
		}
	}
	w, err := newWriter(&c)
	if err != nil {
		return err
	}
	for _, r := range engine.ProbeRows(obs) {
		switch {
		case w.json:
			w.obj(httpxRow(r, ips))
		case c.silent:
			w.line(r.URL)
		default:
			w.line(r.Line())
		}
	}
	return w.close()
}

// httpxRow names the fields the way httpx -json does.
func httpxRow(r engine.ProbeRow, ips map[string][]string) map[string]any {
	status := r.Status
	if r.FinalStatus != 0 {
		status = r.FinalStatus
	}
	host := ""
	if u, err := url.Parse(r.URL); err == nil {
		host = u.Hostname()
	}
	out := map[string]any{
		"url": strings.TrimSuffix(r.URL, "/"), "input": host, "status_code": status, "title": r.Title,
		"webserver": r.Server, "tech": r.Tech, "content_length": r.Length, "words": r.Words, "lines": r.Lines,
		"time": fmt.Sprintf("%dms", r.MS), "host": r.IP, "a": ips[host], "favicon": r.Favicon,
		"cdn": r.CDN != "" && r.CDNType != "cloud", "cdn_name": r.CDN, "cdn_type": r.CDNType,
	}
	if r.FinalURL != "" {
		out["final_url"] = r.FinalURL
	}
	if r.FinalStatus != 0 {
		out["chain_status_codes"] = []int{r.Status, r.FinalStatus}
	}
	return out
}

// cmdCrawl is katana: the URLs of an application, visited or found in its
// pages, scripts and API descriptions.
func cmdCrawl(args []string) error {
	fs := flag.NewFlagSet("crawl", flag.ContinueOnError)
	var c common
	c.register(fs)
	var urls stringsFlag
	fs.Var(&urls, "u", "start URL (repeatable)")
	list := fs.String("l", "", "file of start URLs (- for stdin)")
	vals := pass(fs, "depth", "max-items", "parallel", "host-parallel", "delay", "paths")
	var headers, cookies stringsFlag
	fs.Var(&headers, "H", "extra request header K: V (repeatable)")
	fs.Var(&cookies, "cookie", "Cookie name=value (repeatable)")
	assets := fs.Bool("assets", false, "also list scripts, styles and images")
	noShell := fs.Bool("no-catchall", false, "leave out URLs that answer with the page every unknown path gets (client-side routes of a single-page app)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	targets, err := inputs(urls, *list)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return fmt.Errorf("give -u URL, -l FILE or URLs on stdin")
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
	// The application only: no subdomain, archive or certificate fan-out.
	run := []string{"-list", path, "-skip", "azhaq-subdomains,azhaq-urls,azhaq-rdap,azhaq-tls,azhaq-cloud"}
	run = append(run, forward(vals)...)
	for _, h := range headers {
		run = append(run, "-header", h)
	}
	for _, ck := range cookies {
		run = append(run, "-cookie", ck)
	}
	st, done, err := runPreset(&c, run)
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
	for _, r := range rows {
		if r.Entity.Type != types.TypeURL || (*noShell && r.Coverage == "catchall") || r.Scope != "target" {
			continue
		}
		if !*assets && (r.Role == "script" || r.Role == "asset" || r.Role == "sourcemap") {
			continue
		}
		if w.json {
			row := map[string]any{"url": r.Entity.Key, "coverage": r.Coverage}
			if r.Role != "" {
				row["role"] = r.Role
			}
			if len(r.Methods) > 0 {
				row["methods"] = r.Methods
			}
			if len(r.Params) > 0 {
				row["params"] = r.Params
			}
			w.obj(row)
		} else {
			w.line(r.Entity.Key)
		}
	}
	return w.close()
}

// cmdURLs is gau: every archived URL of the domains.
func cmdURLs(args []string) error {
	fs := flag.NewFlagSet("urls", flag.ContinueOnError)
	var c common
	c.register(fs)
	var domains stringsFlag
	fs.Var(&domains, "d", "domain (repeatable)")
	list := fs.String("dL", "", "file of domains (- for stdin)")
	vals := pass(fs, "providers")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ds, err := inputs(domains, *list)
	if err != nil {
		return err
	}
	if len(ds) == 0 {
		return fmt.Errorf("give -d DOMAIN, -dL FILE or domains on stdin")
	}
	f, err := os.CreateTemp("", "azhaq-urls-")
	if err != nil {
		return err
	}
	f.Close()
	defer os.Remove(f.Name())
	run := []string{"-passive", "-skip", skipAllBut("azhaq-urls"), "-urls", f.Name()}
	for _, d := range ds {
		run = append(run, "-domain", d)
	}
	run = append(run, forward(vals)...)
	_, done, err := runPreset(&c, run)
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
	return w.close()
}

// cmdDNS is dnsx: the names that resolve, wildcard answers left out.
func cmdDNS(args []string) error {
	fs := flag.NewFlagSet("dns", flag.ContinueOnError)
	var c common
	c.register(fs)
	var names stringsFlag
	fs.Var(&names, "d", "name (repeatable)")
	list := fs.String("l", "", "file of names (- for stdin)")
	resp := fs.Bool("resp", false, "print the records after each name")
	vals := pass(fs, "resolvers", "dns-rate")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ns, err := inputs(names, *list)
	if err != nil {
		return err
	}
	if len(ns) == 0 {
		return fmt.Errorf("give -d NAME, -l FILE or names on stdin")
	}
	path, rm, err := tempList(ns)
	if err != nil {
		return err
	}
	defer rm()
	run := append([]string{"-list", path, "-passive", "-depth", "0", "-skip", skipAllBut("azhaq-dns")}, forward(vals)...)
	st, done, err := runPreset(&c, run)
	if err != nil {
		return err
	}
	defer done()
	live := liveNames(st)
	keys := make([]string, 0, len(live))
	for k := range live {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	w, err := newWriter(&c)
	if err != nil {
		return err
	}
	for _, name := range keys {
		p := live[name]
		var a, aaaa []string
		for _, ip := range p["ips"].([]any) {
			s := fmt.Sprint(ip)
			if strings.Contains(s, ":") {
				aaaa = append(aaaa, s)
			} else {
				a = append(a, s)
			}
		}
		var cnames []string
		if cs, ok := p["cnames"].([]any); ok {
			for _, cn := range cs {
				cnames = append(cnames, fmt.Sprint(cn))
			}
		}
		switch {
		case w.json:
			row := map[string]any{"host": name, "a": a, "aaaa": aaaa, "cname": cnames}
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
	return w.close()
}

// cmdPorts is naabu (connect scan): host:port per open port. The hosts
// given are the scope.
func cmdPorts(args []string) error {
	fs := flag.NewFlagSet("ports", flag.ContinueOnError)
	var c common
	c.register(fs)
	var hosts stringsFlag
	fs.Var(&hosts, "host", "host or IP (repeatable)")
	list := fs.String("l", "", "file of hosts (- for stdin)")
	spec := fs.String("p", "top-100", "ports: top-100, top-1000, full or a list such as 22,80,8000-8100")
	rate := fs.String("rate", "300", "connection attempts per second")
	vals := pass(fs, "resolvers")
	if err := fs.Parse(args); err != nil {
		return err
	}
	hs, err := inputs(hosts, *list)
	if err != nil {
		return err
	}
	if len(hs) == 0 {
		return fmt.Errorf("give -host HOST, -l FILE or hosts on stdin")
	}
	path, rm, err := tempList(hs)
	if err != nil {
		return err
	}
	defer rm()
	run := []string{"-list", path, "-passive", "-depth", "0", "-skip", skipAllBut("azhaq-dns", "azhaq-ports"), "-ports", *spec, "-port-rate", *rate}
	for _, h := range hs {
		h = strings.TrimSpace(h)
		if host, _, err := net.SplitHostPort(h); err == nil {
			h = host
		}
		run = append(run, "-allow", h)
	}
	run = append(run, forward(vals)...)
	st, done, err := runPreset(&c, run)
	if err != nil {
		return err
	}
	defer done()
	w, err := newWriter(&c)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, p := range payloads(st, "azhaq-ports") {
		host, _ := p["host"].(string)
		ip, _ := p["ip"].(string)
		services, _ := p["services"].([]any)
		for _, s := range services {
			o, _ := s.(map[string]any)
			port := fmt.Sprint(o["port"])
			key := host + ":" + port
			if seen[key] {
				continue
			}
			seen[key] = true
			if w.json {
				row := map[string]any{"host": host, "ip": ip, "port": o["port"], "protocol": "tcp"}
				if v, ok := o["service"]; ok {
					row["service"] = v
				}
				if v, ok := o["banner"]; ok {
					row["banner"] = v
				}
				w.obj(row)
			} else {
				w.line(key)
			}
		}
	}
	return w.close()
}
