package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"maps"
	"math/rand"
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
	"github.com/trannghiach/azhaq/internal/collectors/dirscol"
	"github.com/trannghiach/azhaq/internal/collectors/shotcol"
	"github.com/trannghiach/azhaq/internal/collectors/urlcol"
	"github.com/trannghiach/azhaq/internal/normalize"
	"github.com/trannghiach/azhaq/internal/targets"
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
	appendOut    bool // -o adds to the file instead of replacing it (urls, as gau; subs, as subfinder, making its directory)
}

func (c *common) register(fs *flag.FlagSet) {
	fs.BoolVar(&c.json, "json", false, "JSONL output, and the summary as one JSON object on stderr")
	fs.BoolVar(&c.silent, "silent", false, "results only: no progress; the summary only when something failed (a source that failed, a takeover candidate as a [takeover] line on stderr); stdout stays one result per line")
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
	if c.json && !c.silent {
		out.progress = "json" // the run is hushed; a long one still says it is working
	}
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
// time: commands print from the goroutines that find the results. Output
// is written out at most every flushEvery, and at the end: a result seen
// by the next reader within that is as live as one written at once, and a
// write per line of a list of thousands costs as much as finding them.
type writer struct {
	mu    sync.Mutex
	w     *bufio.Writer
	f     *os.File
	json  bool
	n     int
	last  time.Time
	timer *time.Timer
	// headed: the CSV header has been written.
	headed bool
}

// flushEvery is how often buffered results reach stdout.
const flushEvery = 20 * time.Millisecond

func newWriter(c *common) (*writer, error) { return newWriterMode(c, false) }

// newWriterMode is newWriter; appendOut adds to the -o file instead of
// replacing it, as dnsx does.
func newWriterMode(c *common, appendOut bool) (*writer, error) {
	var dst io.Writer = os.Stdout
	var f *os.File
	if c.out != "" {
		if st, err := os.Stat(c.out); err == nil && st.IsDir() {
			return nil, usagef("-o %s is a directory: -o names the file the results are written to", c.out)
		}
		var err error
		flags := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
		if appendOut || c.appendOut { // urls and subs set it on the flags, dns asks for it
			flags = os.O_WRONLY | os.O_CREATE | os.O_APPEND
			if err = os.MkdirAll(filepath.Dir(c.out), 0o755); err != nil {
				return nil, err
			}
		}
		if f, err = os.OpenFile(c.out, flags, 0o644); err != nil {
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
	w.flushSoon()
	w.n++
}

// lineRaw writes one line of JSON that is already encoded.
func (w *writer) lineRaw(raw []byte) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.w.Write(append(raw, '\n'))
	w.w.Flush()
	w.n++
}

func (w *writer) obj(v any) {
	raw, _ := json.Marshal(v)
	w.mu.Lock()
	defer w.mu.Unlock()
	w.w.Write(append(raw, '\n'))
	w.flushSoon()
	w.n++
}

// flushSoon writes the output out now if the last write was long ago,
// else leaves it to a timer; call it with mu held.
func (w *writer) flushSoon() {
	if time.Since(w.last) >= flushEvery {
		w.w.Flush()
		w.last = time.Now()
		return
	}
	if w.timer == nil {
		w.timer = time.AfterFunc(flushEvery, func() {
			w.mu.Lock()
			defer w.mu.Unlock()
			w.w.Flush()
			w.last = time.Now()
			w.timer = nil
		})
	}
}

func (w *writer) count() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.n
}

func (w *writer) close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.timer != nil {
		w.timer.Stop()
		w.timer = nil
	}
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

// cmdURLs is gau: every archived URL of the domains. Into a pipe the URLs
// are printed as the pages arrive (unsorted, each once); on a terminal, or
// with -sort, once every archive has answered, sorted.
func cmdURLs(args []string) error {
	fs := newFlags("urls")
	var c common
	c.register(fs)
	fs.Lookup("o").Usage = "also write results to this file, appending to it as gau does"
	var domains stringsFlag
	fs.Var(&domains, "d", "domain (repeatable; domains may also be given as arguments, as gau takes them)")
	list := fs.String("dL", "", "file of domains (- for stdin)")
	subs := fs.Bool("subs", false, "also the subdomains of each domain: the archives are asked for *.DOMAIN (default: the name given, as gau does without --subs; azhaq run keeps the broader default)")
	providers := fs.String("providers", "", "the archives to ask, comma-separated: wayback, commoncrawl, otx, urlscan, arquivo (default: all five). A value that names a file, or has a / in it, is the API-key file, as -providers meant before; -provider-config says that without doubt")
	threads := new(int)
	fs.IntVar(threads, "urls-threads", 0, "domains asked at once (default 16)")
	fs.IntVar(threads, "threads", 0, "same as -urls-threads")
	stream := fs.Bool("stream", false, "print each URL as it arrives, unsorted (the default when stdout is not a terminal)")
	sorted := fs.Bool("sort", false, "print once every archive has answered, sorted (the default on a terminal)")
	config := fs.String("config", "", "a gau config file (default: ~/.gau.toml when it exists): threads, retries, subdomains, parameters, providers, blacklist, proxy, [urlscan] apikey and host, otx, and the [filters] table; flags win")
	failCapped := fs.Bool("fail-on-capped", false, "exit 4 when an archive stopped at its page cap with more to read")
	showVersion := fs.Bool("version", false, "print the version")
	given := inherit(fs, "provider-config=providers", "mc=urls-mc", "fc=urls-fc", "mt=urls-mt", "ft=urls-ft", "from=urls-from", "to=urls-to",
		"blacklist=urls-blacklist", "fp=urls-fp", "retries=urls-retries", "urls-pages", "urls-pause", "proxy=urls-proxy", "urls-max",
		"archive=urls-archive", "raw=urls-raw", "urls-timeout", "timeout", "v", "fail-on-errors")
	if err := parse(fs, args); err != nil {
		return err
	}
	if *showVersion {
		return cmdVersion(nil)
	}
	var notes []string
	if cfg, err := gauConfigPath(*config); err != nil {
		return err
	} else if cfg != "" {
		n, err := applyGauConfig(fs, cfg)
		if err != nil {
			return usagef("%v", err)
		}
		notes = append(notes, n...)
	}
	ds, err := inputs(append(domains, fs.Args()...), *list)
	if err != nil {
		return err
	}
	if len(ds) == 0 {
		return usagef("give -d DOMAIN, -dL FILE, domains as arguments or on stdin")
	}
	raw := fs.Lookup("raw").Value.String() == "true"
	switch {
	case *stream && *sorted:
		return usagef("-stream and -sort say opposite things")
	case raw && *sorted:
		return usagef("-raw prints the URLs as they arrive: it cannot be sorted")
	}
	var run []string
	if *providers != "" {
		if isKeyFile(*providers) {
			run = append(run, "-providers", *providers)
		} else if names := splitList(*providers); true {
			if err := urlcol.CheckSources(names); err != nil {
				return usagef("-providers: %v (an API-key file is given with -provider-config)", err)
			}
			run = append(run, "-urls-sources", strings.Join(names, ","))
		}
	}
	if *threads > 0 {
		run = append(run, "-parallel", strconv.Itoa(*threads))
	}
	rep := newReport("urls")
	rep.what = "archived URLs"
	rep.Notes = append(rep.Notes, notes...)
	live := *stream || raw || !stdoutTerminal()
	if *sorted {
		live = false
	}
	c.appendOut = true
	w, err := newWriter(&c)
	if err != nil {
		return err
	}
	run = append(run, "-passive", "-depth", "0", "-skip", skipAllBut("azhaq-urls"), "-urls-subs="+strconv.FormatBool(*subs))
	flush := func() {}
	if live {
		// Each URL is printed from the goroutine that reads its page: a
		// stop keeps what was already printed.
		var mu sync.Mutex
		seen := map[string]bool{}
		urlSink = func(u, src string) {
			if !raw {
				mu.Lock()
				dup := seen[u]
				seen[u] = true
				mu.Unlock()
				if dup {
					return
				}
			}
			if w.json {
				w.obj(map[string]string{"url": u, "source": src})
			} else {
				w.line(u)
			}
		}
		defer func() { urlSink = nil }()
	} else {
		f, err := os.CreateTemp("", "azhaq-urls-")
		if err != nil {
			return err
		}
		f.Close()
		defer os.Remove(f.Name())
		run = append(run, "-urls", f.Name(), "-urls-source")
		flush = func() {
			// The file holds what the archives gave, a stopped run's too.
			lines, _ := loadLines(f.Name())
			sort.Strings(lines)
			seen := map[string]bool{}
			for _, l := range lines {
				u, src, _ := strings.Cut(l, "\t")
				if seen[u] {
					continue
				}
				seen[u] = true
				if w.json {
					w.obj(map[string]string{"url": u, "source": src})
				} else {
					w.line(u)
				}
			}
		}
	}
	defer func() { urlscanKey = "" }()
	for _, d := range ds {
		run = append(run, "-domain", d)
	}
	st, done, err := runPreset(&c, append(run, given()...), rep, nil)
	flush()
	if cerr := w.close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	defer done()
	urlsNotes(rep, payloads(st, "azhaq-urls"), *failCapped)
	if !raw {
		urlsJunk(rep, payloads(st, "azhaq-urls"))
	}
	rep.Sources = archiveHealth(payloads(st, "azhaq-urls"))
	if n := rep.Sources.archivesNote(); n != "" {
		rep.Notes = append(rep.Notes, n)
	}
	rep.failOnErrors = hasFlag(given(), "fail-on-errors")
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
	words := fs.String("w", "", "wordlist (default: SecLists' common.txt, built in: "+strconv.Itoa(len(dirscol.DefaultWords()))+" words)")
	specs := []string{"e=dirs-ext", "depth=dirs-depth", "t=dirs-threads", "rate=dirs-rate",
		"H=header", "cookie", "all-gets", "max-requests", "timeout", "v", "scope", "program", "allow", "deny", "ledger", "kill-file"}
	for _, m := range dirsMatchers {
		specs = append(specs, m.flag+"=dirs-"+m.flag)
	}
	given := inherit(fs, specs...)
	if err := parse(fs, args); err != nil {
		return err
	}
	matchGiven := map[string]string{}
	for _, m := range dirsMatchers {
		matchGiven[m.flag] = fs.Lookup(m.flag).Value.String()
	}
	if _, err := dirsSet(matchGiven, "-"); err != nil {
		return err
	}
	targets, err := inputs(urls, *list)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return usagef("give -u URL, -l FILE or URLs on stdin")
	}
	var notes []string
	for i, t := range targets {
		if !strings.Contains(t, "://") {
			t = "https://" + t
		}
		// The path is where the sweep starts; a query or fragment is not
		// part of a directory.
		if u, err := url.Parse(t); err == nil && u.Host != "" {
			if u.RawQuery != "" || u.Fragment != "" {
				notes = append(notes, fmt.Sprintf("%s: the sweep goes under its path; the query or fragment is not sent", targets[i]))
				u.RawQuery, u.Fragment, u.ForceQuery = "", "", false
			}
			if u.Path == "" {
				u.Path = "/"
			}
			t = u.String()
		}
		targets[i] = t
	}
	path, rm, err := tempList(targets)
	if err != nil {
		return err
	}
	defer rm()
	wordsFile := *words
	if wordsFile == "" {
		wordsFile = dirscol.Builtin
	}
	w, err := newWriter(&c)
	if err != nil {
		return err
	}
	failed, limited, requests := 0, 0, 0
	see := func(_ types.Entity, o types.Observation) {
		if o.Collector == "azhaq-dirs" && o.Kind == "dirs" {
			p := payloadOf(o)
			failed += intOf(p["failed"])
			limited += intOf(p["rate_limited"])
			requests += intOf(p["requests"])
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
	rep.Notes = append(rep.Notes, notes...)
	// Paths, not technologies: probe names those (the fingerprints are 40 MB to load).
	run := []string{"-list", path, "-depth", "1", "-no-tech", "-no-favicon", "-skip", skipAllBut("azhaq-dns", "azhaq-http", "azhaq-dirs"), "-dirs", wordsFile}
	extra := given()
	if !hasFlag(extra, "allow", "scope") {
		// The services given are the scope.
		for _, t := range targets {
			if u, err := url.Parse(t); err == nil {
				run = append(run, "-allow", u.Hostname())
			}
		}
		if !hasFlag(extra, "deny") {
			// With no rule, a host a -H names is part of what was named.
			for _, h := range flagHeaderHosts(extra) {
				run = append(run, "-allow", h)
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
		rep.warned = true
	}
	if limited > 0 {
		rep.Notes = append(rep.Notes, fmt.Sprintf("%d of %d guesses were answered 429 (too many requests) and not judged: the service is limiting the sweep; lower -rate or -t, and run again", limited, requests))
		rep.warned = true
	}
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
	var urls, nmapFiles, nessusFiles stringsFlag
	fs.Var(&urls, "u", "target: URL (its path and query are kept), host, host:port, IP or address range such as 192.0.2.0/24 (repeatable)")
	list := fs.String("l", "", "file of targets (- for stdin)")
	dir := fs.String("dir", "screenshots", "directory for the picture files")
	csvOut := fs.String("csv", "", "also write one row per page to this CSV file (url, final_url, response_code, title, technologies, file, phash, partial)")
	ports := fs.String("p", "", "web ports to try on each host, comma-separated: numbers, ranges, small (80, 443), medium or large (default: 443, then 80)")
	noHTTP := fs.Bool("no-http", false, "try names and addresses over https only")
	noHTTPS := fs.Bool("no-https", false, "try names and addresses over http only")
	random := fs.Bool("random", false, "take the targets in random order")
	fs.Var(&nmapFiles, "nmap", "an nmap XML file (-oX): the web services it found (repeatable)")
	fs.Var(&nessusFiles, "nessus", "a Nessus file (.nessus): the web services it found (repeatable)")
	service := fs.String("service", "", "with -nmap or -nessus: the service names to take, comma-separated, or all (default: http ones; www, http and https for Nessus)")
	openOnly := fs.Bool("open-only", true, "with -nmap: only ports found open")
	hostnames := fs.Bool("hostnames", false, "with -nmap or -nessus: the host's name instead of its address, when the file has one")
	given := inherit(fs, append([]string{"tabs", "browser-writes", "cidr", "max-ips", "shot-size", "shot-fullpage", "shot-wait", "shot-timeout", "shot-format",
		"shot-quality", "shot-js", "shot-codes", "shot-html", "chrome", "chrome-proxy", "chrome-profile", "unsafe-ports", "no-tech"}, targetFlags...)...)
	if err := parse(fs, args); err != nil {
		return err
	}
	if *noHTTP && *noHTTPS {
		return usagef("-no-http and -no-https together leave no scheme to try")
	}
	portList, err := targets.Ports(*ports)
	if err != nil {
		return usagef("-p: %v", err)
	}
	var targs []string
	if len(nmapFiles)+len(nessusFiles) == 0 || len(urls) > 0 || *list != "" {
		if targs, err = inputs(urls, *list); err != nil {
			return err
		}
	}
	opt := targets.Options{Ports: portList, Hostnames: *hostnames, OpenOnly: *openOnly}
	for _, s := range splitList(*service) {
		opt.Services = append(opt.Services, s)
	}
	for _, f := range nmapFiles {
		more, err := scanFile(f, func(r io.Reader) ([]string, error) { return targets.NmapXML(r, opt) })
		if err != nil {
			return err
		}
		targs = append(targs, more...)
	}
	for _, f := range nessusFiles {
		more, err := scanFile(f, func(r io.Reader) ([]string, error) { return targets.Nessus(r, opt) })
		if err != nil {
			return err
		}
		targs = append(targs, more...)
	}
	targs, prefixes := targets.SplitPrefixes(targs)
	if len(portList) > 0 || *noHTTP || *noHTTPS {
		targs = targets.Expand(targs, portList, *noHTTP, *noHTTPS)
	}
	if len(targs) == 0 && len(prefixes) == 0 && len(*fs.Lookup("cidr").Value.(*stringsFlag)) == 0 {
		if len(nmapFiles)+len(nessusFiles) > 0 {
			return usagef("the scan files name no web service (-service all takes every open port)")
		}
		return usagef("give -u TARGET, -l FILE, -nmap FILE, -nessus FILE or targets on stdin")
	}
	if *random {
		rand.Shuffle(len(targs), func(i, j int) { targs[i], targs[j] = targs[j], targs[i] })
	}
	if st, err := os.Stat(c.out); c.out != "" && err == nil && st.IsDir() {
		return usagef("-o %s is a directory: -o names the file the results are written to, the PNG files go to -dir", c.out)
	}
	path, rm, err := tempList(targs)
	if err != nil {
		return err
	}
	defer rm()
	w, err := newWriter(&c)
	if err != nil {
		return err
	}
	var csvw *csv.Writer
	var csvf *os.File
	var csvMu sync.Mutex
	if *csvOut != "" {
		if csvf, err = os.Create(*csvOut); err != nil {
			return err
		}
		defer csvf.Close()
		csvw = csv.NewWriter(csvf)
		_ = csvw.Write([]string{"url", "final_url", "response_code", "title", "technologies", "file", "format", "bytes", "phash", "partial"})
	}
	see := func(_ types.Entity, o types.Observation) {
		if o.Collector != "azhaq-shots" || o.Kind != "screenshot" {
			return // what Chrome refused, and the writes it mapped, are the summary's
		}
		p := payloadOf(o)
		if csvw != nil {
			var tech []string
			if ts, ok := p["technologies"].([]any); ok {
				for _, t := range ts {
					if m, ok := t.(map[string]any); ok {
						tech = append(tech, fmt.Sprint(m["value"]))
					}
				}
			}
			cell := func(k string) string {
				if v, ok := p[k]; ok && v != nil {
					return fmt.Sprint(v)
				}
				return ""
			}
			csvMu.Lock()
			_ = csvw.Write([]string{cell("url"), cell("final_url"), cell("response_code"), cell("title"),
				strings.Join(tech, ";"), cell("file"), cell("format"), cell("bytes"), cell("phash"), fmt.Sprint(p["partial"] == true)})
			csvw.Flush()
			csvMu.Unlock()
		}
		if w.json {
			w.obj(p)
		} else {
			line := fmt.Sprintf("%v %v", p["url"], p["file"])
			if p["partial"] == true {
				var hosts []string
				if hs, ok := p["blocked_hosts"].([]any); ok {
					for _, h := range hs {
						hosts = append(hosts, fmt.Sprint(h))
					}
				}
				line += "  partial (" + shotcol.PartialWhy(intOf(p["unloaded"]), intOf(p["resources"]), intOf(p["blocked"]), hosts) + ")"
			}
			w.line(line)
		}
	}
	rep := newReport("shots")
	rep.what = "screenshots"
	keep := []string{"azhaq-dns", "azhaq-http", "azhaq-shots"}
	if len(prefixes) > 0 || len(*fs.Lookup("cidr").Value.(*stringsFlag)) > 0 {
		keep = append(keep, "azhaq-prefix")
	}
	depth := "0"
	if len(prefixes) > 0 || len(*fs.Lookup("cidr").Value.(*stringsFlag)) > 0 {
		depth = "2" // a range gives its addresses, and they give their pages
	}
	// The favicon is hashed by the HTTP collector for the map; a screenshot run has no use for it.
	run := []string{"-depth", depth, "-skip", skipAllBut(keep...), "-screenshots", *dir, "-no-favicon"}
	if len(targs) > 0 {
		run = append(run, "-list", path)
	}
	for _, pf := range prefixes {
		run = append(run, "-cidr", pf)
	}
	if len(portList) > 0 {
		var ps []string
		for _, p := range portList {
			ps = append(ps, strconv.Itoa(p))
		}
		run = append(run, "-web-ports", strings.Join(ps, ","))
	}
	switch {
	case *noHTTP:
		run = append(run, "-web-scheme", "https")
	case *noHTTPS:
		run = append(run, "-web-scheme", "http")
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

// scanFile reads a scan file with read.
func scanFile(path string, read func(io.Reader) ([]string, error)) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	lines, err := read(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return lines, nil
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
	return fmt.Sprintf("%s: %s took %.0f s, the next slowest source %.0f s, so it held the run (-source-timeout bounds each source: a shorter one ends the wait sooner and its names are then missing; -exclude-sources %s drops it; -v lists them all)", domain, slow, first, second, slow)
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
