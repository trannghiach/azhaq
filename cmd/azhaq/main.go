package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/trannghiach/azhaq/internal/catalog"
	"github.com/trannghiach/azhaq/internal/collectors"
	"github.com/trannghiach/azhaq/internal/connector"
	"github.com/trannghiach/azhaq/internal/engine"
	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/internal/scope"
	"github.com/trannghiach/azhaq/internal/store"
	"github.com/trannghiach/azhaq/internal/timing"
	"github.com/trannghiach/azhaq/internal/types"
)

const lastDBFile = ".azhaq-last"
const version = "0.3.1"

func main() {
	if err := run(os.Args[1:]); err != nil {
		if err == flag.ErrHelp {
			os.Exit(0)
		}
		fmt.Fprintf(os.Stderr, "azhaq: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, helpText)
		return fmt.Errorf("need a command")
	}
	switch args[0] {
	case "run":
		return cmdRun(args[1:])
	case "plan":
		return cmdPlan(args[1:])
	case "ingest":
		return cmdIngest(args[1:])
	case "export":
		return cmdExport(args[1:])
	case "diff":
		return cmdDiff(args[1:])
	case "bench":
		return cmdBench(args[1:])
	case "version":
		fmt.Printf("azhaq %s\n", version)
		return nil
	case "help", "-h", "--help":
		return usage()
	default:
		return fmt.Errorf("unknown command %q\n%s", args[0], helpText)
	}
}

const helpText = `azhaq — generic recon engine

  azhaq run    -url URL | -org NAME | -cloud FILE | -in seeds.jsonl | -demo  [-db FILE]
               [-exec CMD] [-facts FILE] [-cookie N=V] [-header 'K: V'] [-paths FILE]
               [-depth N] [-max-items N] [-delay D] [-quiet] [-json] [-obs]
               [-fail-on-errors] [-fail-on-capped] [-allow D] [-deny D] [-passive]
               # -depth 0 = seed wave only (not unlimited); default 4
               # -passive skips HTTP/crawl/JS/paths/TLS (no handshake to the target)
               # print is a ranked map (visited/hint); -obs dumps the observation log
               # parallel runs: give each its own -db FILE or AZHAQ_DB
  azhaq plan   -url URL | -org NAME | -cloud FILE | -in seeds.jsonl
  azhaq ingest -in facts.jsonl  [-db FILE]
  azhaq export [-db FILE]
  azhaq diff   -a OLD.db -b NEW.db  [-jsonl] [-quiet]
  azhaq bench
  azhaq version
`

func usage() error {
	fmt.Fprint(os.Stderr, helpText)
	return flag.ErrHelp
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	url := fs.String("url", "", "seed URL")
	org := fs.String("org", "", "seed Organization name")
	cloud := fs.String("cloud", "", "CloudAccount JSON inventory (local file)")
	in := fs.String("in", "", "JSONL seeds")
	factsPath := fs.String("facts", "", "JSONL connector facts to ingest before native collectors")
	execCmd := fs.String("exec", "", "connector command (seeds on stdin, facts on stdout)")
	dbPath := fs.String("db", "", "sqlite path (default: new file each run)")
	demo := fs.Bool("demo", false, "run against the built-in fixture server (no internet)")
	pathsFile := fs.String("paths", "", "extra path wordlist (one path per line)")
	quiet := fs.Bool("quiet", false, "print summary only (human line + JSON)")
	jsonOut := fs.Bool("json", false, "stdout is one JSON summary only")
	showObs := fs.Bool("obs", false, "also print the observation log")
	failErrs := fs.Bool("fail-on-errors", false, "exit 1 on collector errors, connector failures, or degraded third-party calls (429/503)")
	failCapped := fs.Bool("fail-on-capped", false, "exit 1 if the run hit -max-items or -depth with work left")
	passive := fs.Bool("passive", false, "skip HTTP/crawl/JS/paths/TLS (no handshake to the target)")
	depth := fs.Int("depth", 4, "max fan-out waves (0 = seed wave only, not unlimited)")
	maxItems := fs.Int("max-items", 0, "max collector invocations (default 512)")
	delay := fs.Duration("delay", 0, "pause before each uncached fetch")
	var cookies, headers, allow, deny stringsFlag
	fs.Var(&cookies, "cookie", "Cookie name=value (repeatable; sent as one Cookie header)")
	fs.Var(&headers, "header", "extra request header K: V (repeatable)")
	fs.Var(&allow, "allow", "allowed domain or host for fan-out (repeatable)")
	fs.Var(&deny, "deny", "excluded domain or host (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	fetch.Reset()
	fetch.Delay = *delay
	if err := applyExtra(cookies, headers); err != nil {
		return err
	}

	var client *http.Client
	var seeds []types.Seed
	if *demo {
		if *url != "" || *org != "" || *cloud != "" || *in != "" {
			fmt.Fprintln(os.Stderr, "azhaq: -demo ignores -url/-org/-cloud/-in")
		}
		srv := demoServer()
		defer srv.Close()
		client = srv.Client()
		seeds = []types.Seed{{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/"}}}
	} else {
		var err error
		seeds, err = loadSeeds(*url, *org, *cloud, *in)
		if err != nil {
			return err
		}
		if len(seeds) == 0 && *factsPath == "" && *execCmd == "" {
			return fmt.Errorf("need -url, -org, -cloud, -in, -facts, -exec, or -demo")
		}
		if *execCmd != "" && len(seeds) == 0 {
			return fmt.Errorf("-exec needs a seed (-url, -org, -cloud, or -in)")
		}
	}

	path, remember := resolveDB(*dbPath)
	prevDB := ""
	if remember {
		prevDB = readLastDB()
		if err := os.WriteFile(lastDBFile, []byte(path+"\n"), 0o644); err != nil {
			return err
		}
	}

	st, err := store.Open(path)
	if err != nil {
		return err
	}
	defer st.Close()
	budgets := engine.DefaultBudgets()
	budgets.FailOnErrors = *failErrs
	budgets.FailOnCapped = *failCapped
	budgets.Passive = *passive
	budgets.Scope = scope.Rules{Allow: append([]string(nil), allow...), Deny: append([]string(nil), deny...)}
	if *depth == 0 {
		budgets.MaxDepth = 1
	} else {
		budgets.MaxDepth = *depth
	}
	if *maxItems > 0 {
		budgets.MaxItems = *maxItems
	}
	if err := st.BeginRun(newRunID(), *depth, budgets.MaxItems); err != nil {
		return err
	}
	cat := catalog.New()
	var extraPaths []string
	if *pathsFile != "" {
		var err error
		extraPaths, err = loadPathList(*pathsFile)
		if err != nil {
			return err
		}
	}
	collectors.RegisterAllWith(cat, client, extraPaths)
	eng := &engine.Engine{Cat: cat, Store: st}

	log := timing.New()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx = timing.With(ctx, log)
	if *quiet || *jsonOut {
		ctx = engine.WithQuiet(ctx)
	}

	t0 := time.Now()
	if *factsPath != "" {
		facts, err := connector.ReadFile(*factsPath)
		if err != nil {
			return err
		}
		done := timing.Start(ctx, "ingest", *factsPath)
		hints, err := eng.Ingest(ctx, facts)
		done()
		if err != nil {
			return err
		}
		seeds = append(seeds, hints...)
	}
	if *execCmd != "" {
		argv, err := splitCmd(*execCmd)
		if err != nil {
			return err
		}
		done := timing.Start(ctx, "connector", argv[0])
		facts, err := connector.Exec(ctx, argv, engine.ExpandSeeds(seeds))
		done()
		if err != nil {
			fmt.Fprintf(os.Stderr, "azhaq: connector %s: %v\n", argv[0], err)
			if recErr := eng.NoteExternalError(seeds, "connector", fmt.Errorf("%s: %w", argv[0], err)); recErr != nil {
				return recErr
			}
		} else if !*quiet && !*jsonOut {
			fmt.Fprintf(os.Stderr, "  . connector %s (%s)\n", argv[0], connector.Protocol)
		}
		if len(facts) > 0 {
			hints, err := eng.Ingest(ctx, facts)
			if err != nil {
				return err
			}
			seeds = append(seeds, hints...)
		}
	}
	if err := st.SaveSeeds(engine.ExpandSeeds(seeds)); err != nil {
		return err
	}
	if err := eng.RunLocal(ctx, seeds, budgets); err != nil && err != context.Canceled {
		return err
	}
	ents, _ := st.Entities()
	obs, _ := st.Observations()
	edges, _ := st.Edges()
	leftover, _ := st.LoadLeftover()
	scope := engine.ScopeSeeds(seeds, ents, edges)
	_ = st.SaveSeeds(scope)
	stats, err := st.Stats()
	if err != nil {
		return err
	}
	rows := engine.BuildMap(ents, scope, obs, leftover, stats.Capped)
	if !*quiet && !*jsonOut {
		fmt.Fprint(os.Stderr, log.Report(time.Since(t0)))
	}
	if !*quiet && !*jsonOut {
		fmt.Println("map")
		for _, row := range rows {
			fmt.Printf("  %s\n", row.Line())
		}
		if *showObs {
			fmt.Println("observations")
			for _, o := range obs {
				fmt.Printf("  %s %s %s\n", o.Collector, o.Kind, compact(o.Payload))
			}
		}
	}
	stats.DB = path
	if *jsonOut {
		if err := json.NewEncoder(os.Stdout).Encode(stats); err != nil {
			return err
		}
	} else {
		fmt.Printf("db %s\n", path)
		fmt.Println(stats.Line())
		if err := json.NewEncoder(os.Stdout).Encode(stats); err != nil {
			return err
		}
	}
	if *failErrs && stats.Errors+stats.Degraded > 0 {
		return fmt.Errorf("run %s: %d error(s), %d degraded", stats.RunID, stats.Errors, stats.Degraded)
	}
	if *failCapped && stats.Capped {
		return fmt.Errorf("run %s: capped (depth=%d max-items=%d)", stats.RunID, stats.Depth, stats.MaxItems)
	}
	if !*quiet && !*jsonOut && !*demo && prevDB != "" && prevDB != path {
		if err := printDiff(prevDB, path, diffOpts{}); err != nil {
			fmt.Fprintf(os.Stderr, "azhaq: diff vs %s: %v\n", prevDB, err)
		}
	}
	return nil
}

func cmdIngest(args []string) error {
	fs := flag.NewFlagSet("ingest", flag.ContinueOnError)
	in := fs.String("in", "", "JSONL connector facts")
	dbPath := fs.String("db", "", "sqlite path (default: new file each run)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *in == "" {
		return fmt.Errorf("need -in facts.jsonl")
	}
	facts, err := connector.ReadFile(*in)
	if err != nil {
		return err
	}

	path, remember := resolveDB(*dbPath)
	if remember {
		if err := os.WriteFile(lastDBFile, []byte(path+"\n"), 0o644); err != nil {
			return err
		}
	}
	st, err := store.Open(path)
	if err != nil {
		return err
	}
	defer st.Close()

	eng := &engine.Engine{Store: st}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	hints, err := eng.Ingest(ctx, facts)
	if err != nil {
		return err
	}
	_ = st.SaveSeeds(hints)
	ents, _ := st.Entities()
	obs, _ := st.Observations()
	fmt.Println("map")
	for _, row := range engine.BuildMap(ents, hints, obs, nil, false) {
		fmt.Printf("  %s\n", row.Line())
	}
	fmt.Printf("db %s\n", path)
	sum, err := st.Summary()
	if err != nil {
		return err
	}
	fmt.Println(sum)
	return nil
}

func cmdBench(args []string) error {
	fs := flag.NewFlagSet("bench", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	fetch.Reset()
	srv := demoServer()
	defer srv.Close()

	dir, err := os.MkdirTemp("", "azhaq-bench-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	st, err := store.Open(filepath.Join(dir, "bench.db"))
	if err != nil {
		return err
	}
	defer st.Close()

	cat := catalog.New()
	collectors.RegisterAll(cat, srv.Client())
	eng := &engine.Engine{Cat: cat, Store: st}
	seeds := []types.Seed{{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/"}}}

	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	t0 := time.Now()
	if err := eng.RunLocal(context.Background(), seeds, engine.DefaultBudgets()); err != nil {
		return err
	}
	wall := time.Since(t0)
	runtime.GC()
	runtime.ReadMemStats(&ms)

	sum, err := st.Summary()
	if err != nil {
		return err
	}
	const maxWall = 5 * time.Second
	const maxHeap = 256 << 20
	fmt.Printf("bench ok\n")
	fmt.Printf("  wall  %s\n", wall.Round(time.Millisecond))
	fmt.Printf("  heap  %.1fMB\n", float64(ms.HeapAlloc)/(1<<20))
	fmt.Printf("  %s\n", sum)
	if wall > maxWall {
		return fmt.Errorf("bench: wall %s over %s", wall.Round(time.Millisecond), maxWall)
	}
	if ms.HeapAlloc > maxHeap {
		return fmt.Errorf("bench: heap %dMB over %dMB", ms.HeapAlloc>>20, maxHeap>>20)
	}
	return nil
}

func cmdPlan(args []string) error {
	fs := flag.NewFlagSet("plan", flag.ContinueOnError)
	url := fs.String("url", "", "seed URL")
	org := fs.String("org", "", "seed Organization name")
	cloud := fs.String("cloud", "", "CloudAccount JSON inventory (local file)")
	in := fs.String("in", "", "JSONL seeds")
	if err := fs.Parse(args); err != nil {
		return err
	}
	seeds, err := loadSeeds(*url, *org, *cloud, *in)
	if err != nil {
		return err
	}
	if len(seeds) == 0 {
		return fmt.Errorf("need -url, -org, -cloud, or -in")
	}
	cat := catalog.New()
	collectors.RegisterAll(cat, nil)
	eng := &engine.Engine{Cat: cat}
	enc := json.NewEncoder(os.Stdout)
	for _, item := range eng.Plan(engine.ExpandSeeds(seeds)) {
		if err := enc.Encode(item); err != nil {
			return err
		}
	}
	return nil
}

func cmdDiff(args []string) error {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	a := fs.String("a", "", "old sqlite")
	b := fs.String("b", "", "new sqlite (default: last run)")
	jsonl := fs.Bool("jsonl", false, "emit JSONL instead of a text report")
	quiet := fs.Bool("quiet", false, "entities and counts only (skip observation lines)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *a == "" {
		return fmt.Errorf("need -a OLD.db")
	}
	newPath := *b
	if newPath == "" {
		newPath = readLastDB()
		if newPath == "" {
			return fmt.Errorf("need -b (no %s)", lastDBFile)
		}
	}
	return printDiff(*a, newPath, diffOpts{JSONL: *jsonl, Quiet: *quiet})
}

func readLastDB() string {
	raw, err := os.ReadFile(lastDBFile)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

type diffOpts struct {
	JSONL bool
	Quiet bool
}

func printDiff(oldPath, newPath string, opts diffOpts) error {
	old, err := store.OpenExisting(oldPath)
	if err != nil {
		return err
	}
	defer old.Close()
	neu, err := store.OpenExisting(newPath)
	if err != nil {
		return err
	}
	defer neu.Close()
	d, err := store.Compare(old, neu)
	if err != nil {
		return err
	}
	if opts.JSONL {
		enc := json.NewEncoder(os.Stdout)
		for _, e := range d.Added {
			if err := enc.Encode(map[string]any{"kind": "added", "type": e.Type, "key": e.Key}); err != nil {
				return err
			}
		}
		for _, e := range d.Removed {
			if err := enc.Encode(map[string]any{"kind": "removed", "type": e.Type, "key": e.Key}); err != nil {
				return err
			}
		}
		if !opts.Quiet {
			for _, o := range d.NewObs {
				if err := enc.Encode(map[string]any{"kind": "observation", "collector": o.Collector, "obs_kind": o.Kind, "payload": o.Payload}); err != nil {
					return err
				}
			}
		}
		return enc.Encode(map[string]any{
			"kind":         "summary",
			"added":        len(d.Added),
			"removed":      len(d.Removed),
			"observations": len(d.NewObs),
		})
	}
	fmt.Printf("diff vs %s\n", oldPath)
	if len(d.Added) == 0 && len(d.Removed) == 0 && len(d.NewObs) == 0 {
		fmt.Println("  (no new entities or observations)")
		fmt.Println("added=0 removed=0 observations=0")
		return nil
	}
	for _, e := range d.Added {
		fmt.Printf("  + %s %s\n", e.Type, e.Key)
	}
	for _, e := range d.Removed {
		fmt.Printf("  - %s %s\n", e.Type, e.Key)
	}
	if !opts.Quiet {
		for _, o := range d.NewObs {
			fmt.Printf("  + %s %s %s\n", o.Collector, o.Kind, compact(o.Payload))
		}
	}
	fmt.Printf("added=%d removed=%d observations=%d\n", len(d.Added), len(d.Removed), len(d.NewObs))
	return nil
}

func newRunID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("local-%d-%d", time.Now().UnixNano(), os.Getpid())
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func cmdExport(args []string) error {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	dbPath := fs.String("db", "", "sqlite path (default: last run)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	path := *dbPath
	if path == "" {
		b, err := os.ReadFile(lastDBFile)
		if err != nil {
			return fmt.Errorf("need -db (no %s from a previous run)", lastDBFile)
		}
		path = strings.TrimSpace(string(b))
	}
	st, err := store.OpenExisting(path)
	if err != nil {
		return err
	}
	defer st.Close()
	enc := json.NewEncoder(os.Stdout)
	ents, err := st.Entities()
	if err != nil {
		return err
	}
	seeds, _ := st.LoadSeeds()
	obs, err := st.Observations()
	if err != nil {
		return err
	}
	edges, err := st.Edges()
	if err != nil {
		return err
	}
	leftover, _ := st.LoadLeftover()
	scope := engine.ScopeSeeds(seeds, ents, edges)
	stats, _ := st.Stats()
	for _, row := range engine.BuildMap(ents, scope, obs, leftover, stats.Capped) {
		out := map[string]any{"kind": "entity", "entity": row.Entity, "scope": row.Scope}
		if row.Coverage != "" {
			out["coverage"] = row.Coverage
		}
		if row.Role != "" {
			out["role"] = row.Role
		}
		if row.Proof != "" {
			out["proof"] = row.Proof
		}
		if err := enc.Encode(out); err != nil {
			return err
		}
	}
	for _, o := range obs {
		if err := enc.Encode(map[string]any{"kind": "observation", "observation": o}); err != nil {
			return err
		}
	}
	for _, e := range edges {
		if err := enc.Encode(map[string]any{"kind": "edge", "edge": e}); err != nil {
			return err
		}
	}
	return nil
}

func demoServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html><title>Azhaq fixture</title>
<a href="/login">login</a>
<a href="https://evil.example/out">out</a>
<script src="/app.js"></script>
`))
	})
	mux.HandleFunc("/login", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!doctype html><title>Login</title><form action="/auth"></form>`))
	})
	mux.HandleFunc("/app.js", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte(`fetch("/api/status"); const x = "https://evil.example/js";`))
	})
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	mux.HandleFunc("/auth", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!doctype html><title>Auth</title>`))
	})
	return httptest.NewServer(mux)
}

func loadSeeds(url, org, cloud, path string) ([]types.Seed, error) {
	var seeds []types.Seed
	if url != "" {
		u, err := parseCLIURL(url)
		if err != nil {
			return nil, err
		}
		seeds = append(seeds, types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": u}})
	}
	if org != "" {
		seeds = append(seeds, types.Seed{Type: types.TypeOrganization, Keys: map[string]string{"name": org}})
	}
	if cloud != "" {
		if _, err := os.Stat(cloud); err != nil {
			return nil, fmt.Errorf("cloud inventory: %w", err)
		}
		seeds = append(seeds, types.Seed{Type: types.TypeCloudAccount, Keys: map[string]string{"id": cloud, "path": cloud}})
	}
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		for i, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			s, err := parseSeedLine([]byte(line))
			if err != nil {
				return nil, fmt.Errorf("%s:%d: %w", path, i+1, err)
			}
			seeds = append(seeds, s)
		}
	}
	return seeds, nil
}

type stringsFlag []string

func (s *stringsFlag) String() string { return strings.Join(*s, ", ") }

func (s *stringsFlag) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func resolveDB(flag string) (path string, remember bool) {
	if flag != "" {
		return flag, false
	}
	if v := os.Getenv("AZHAQ_DB"); v != "" {
		return v, false
	}
	return uniqueDB(), true
}

func uniqueDB() string {
	stamp := time.Now().Format("20060102-150405")
	pid := os.Getpid()
	for i := 0; i < 64; i++ {
		path := fmt.Sprintf("azhaq-%s-%d.db", stamp, pid)
		if i > 0 {
			path = fmt.Sprintf("azhaq-%s-%d-%d.db", stamp, pid, i)
		}
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL, 0o644)
		if err == nil {
			f.Close()
			return path
		}
		if !os.IsExist(err) {
			break
		}
	}
	return fmt.Sprintf("azhaq-%s-%d-%d.db", stamp, pid, time.Now().UnixNano())
}

func parseCLIURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("need an http(s) URL, got %q", raw)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("unsupported URL scheme %q", u.Scheme)
	}
	return raw, nil
}

func parseSeedLine(raw []byte) (types.Seed, error) {
	var probe struct {
		Collector string          `json:"collector"`
		ID        string          `json:"id"`
		Type      types.SeedType  `json:"type"`
		Seed      json.RawMessage `json:"seed"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return types.Seed{}, err
	}
	if probe.Collector != "" && probe.ID != "" {
		return types.Seed{}, fmt.Errorf("plan work item, not a seed (pass the original seeds to -in)")
	}
	var s types.Seed
	if err := json.Unmarshal(raw, &s); err != nil {
		return types.Seed{}, err
	}
	if s.Type == "" || s.Key() == "" {
		return types.Seed{}, fmt.Errorf("not a seed")
	}
	if !types.Known(s.Type) {
		return types.Seed{}, fmt.Errorf("unknown seed type %q", s.Type)
	}
	return s, nil
}

func loadPathList(path string) ([]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, strings.TrimPrefix(line, "/"))
	}
	return out, nil
}

func applyExtra(cookies, headers []string) error {
	if len(cookies) == 0 && len(headers) == 0 {
		return nil
	}
	h := make(http.Header)
	var cookieParts []string
	for _, c := range cookies {
		c = strings.TrimSpace(c)
		if c == "" || !strings.Contains(c, "=") {
			return fmt.Errorf("cookie must be name=value")
		}
		cookieParts = append(cookieParts, c)
	}
	if len(cookieParts) > 0 {
		h.Set("Cookie", strings.Join(cookieParts, "; "))
	}
	for _, raw := range headers {
		k, v, ok := strings.Cut(raw, ":")
		if !ok || strings.TrimSpace(k) == "" {
			return fmt.Errorf("header must be K: V")
		}
		h.Add(strings.TrimSpace(k), strings.TrimSpace(v))
	}
	fetch.Extra = h
	return nil
}

func splitCmd(s string) ([]string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty -exec")
	}
	var parts []string
	var cur strings.Builder
	var quote rune
	for _, r := range s {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
		case r == '\'' || r == '"':
			quote = r
		case r == ' ' || r == '\t':
			if cur.Len() > 0 {
				parts = append(parts, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if quote != 0 {
		return nil, fmt.Errorf("unclosed quote in -exec")
	}
	if cur.Len() > 0 {
		parts = append(parts, cur.String())
	}
	if len(parts) == 0 {
		return nil, fmt.Errorf("empty -exec")
	}
	return parts, nil
}

func compact(raw json.RawMessage) string {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return string(raw)
	}
	parts := make([]string, 0, 4)
	for _, k := range []string{"status", "title", "url", "via", "path", "fqdn", "ips", "params", "role", "count", "not_after", "error", "skipped", "registrar", "registrant", "name", "id", "method", "action", "fields", "auth", "final_url", "extracted", "warning", "note"} {
		if v, ok := m[k]; ok && v != nil && fmt.Sprint(v) != "" {
			parts = append(parts, fmt.Sprintf("%s=%v", k, v))
		}
	}
	return strings.Join(parts, " ")
}
