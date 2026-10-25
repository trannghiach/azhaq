package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/trannghiach/azhaq/catalog"
	"github.com/trannghiach/azhaq/collectors"
	"github.com/trannghiach/azhaq/engine"
	"github.com/trannghiach/azhaq/internal/browser"
	"github.com/trannghiach/azhaq/internal/collectors/asncol"
	"github.com/trannghiach/azhaq/internal/collectors/dirscol"
	"github.com/trannghiach/azhaq/internal/collectors/httpcol"
	"github.com/trannghiach/azhaq/internal/collectors/paramcol"
	"github.com/trannghiach/azhaq/internal/collectors/subcol"
	"github.com/trannghiach/azhaq/internal/collectors/urlcol"
	"github.com/trannghiach/azhaq/internal/connector"
	"github.com/trannghiach/azhaq/internal/dnsr"
	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/internal/normalize"
	"github.com/trannghiach/azhaq/internal/portscan"
	"github.com/trannghiach/azhaq/internal/timing"
	"github.com/trannghiach/azhaq/scope"
	"github.com/trannghiach/azhaq/store"
	"github.com/trannghiach/azhaq/types"
)

const lastDBFile = ".azhaq-last"

// version is set at release time (-ldflags "-X main.version=0.4.0"); a
// go install of a tagged version reports the module version instead.
var version = "dev"

func init() {
	if version == "dev" {
		if bi, ok := debug.ReadBuildInfo(); ok && strings.HasPrefix(bi.Main.Version, "v") {
			version = strings.TrimPrefix(bi.Main.Version, "v")
		}
	}
	fetch.UserAgent = "azhaq/" + version
}

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
	case "roles":
		return cmdRoles(args[1:])
	case "resume":
		return cmdResume(args[1:])
	case "worker":
		return cmdWorker(args[1:])
	case "scope":
		return cmdScope(args[1:])
	case "watch":
		return cmdWatch(args[1:])
	case "new":
		return cmdNew(args[1:])
	case "subs":
		return cmdSubs(args[1:])
	case "probe":
		return cmdProbe(args[1:])
	case "crawl":
		return cmdCrawl(args[1:])
	case "urls":
		return cmdURLs(args[1:])
	case "dns":
		return cmdDNS(args[1:])
	case "ports":
		return cmdPorts(args[1:])
	case "dirs":
		return cmdDirs(args[1:])
	case "params":
		return cmdParams(args[1:])
	case "asn":
		return cmdASN(args[1:])
	case "shots":
		return cmdShots(args[1:])
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

  azhaq run    -url URL | -domain D | -list FILE | -org NAME | -cloud FILE | -in seeds.jsonl | -demo
               [-scope FILE|PLATFORM -program NAME] [-asn AS64500] [-cidr 192.0.2.0/24] [-max-ips N]
               [-probe] [-web-ports 80,443,8080] [-no-tech] [-urls FILE] [-screenshots DIR] [-browser] [-tabs N]
               [-db FILE] [-exec CMD] [-facts FILE] [-cookie N=V] [-header 'K: V']
               [-login URL -login-user U -login-pass P]
               [-paths FILE] [-depth N] [-max-items N] [-max-names N] [-parallel N]
               [-max-requests N] [-rate N] [-daily-requests N]
               [-delay D] [-quiet] [-json] [-obs] [-fail-on-errors] [-fail-on-capped]
               [-allow D] [-deny D] [-passive]
               [-sources A,B] [-exclude-sources A,B] [-all-sources] [-providers FILE]
               [-resolvers FILE] [-dns-rate N] [-dns-brute FILE] [-permute] [-graphql] [-skip A,B]
               # -depth 0 = seed wave only (not unlimited); default 4
               # -passive keeps third-party sources and DNS; nothing is sent to the target
               # -dns-brute, -permute and -graphql are active and need -allow
               # -probe: resolve and fetch each target once, one line per web service
               # print is a ranked map (visited/hint); -obs dumps the observation log
               # parallel runs: give each its own -db FILE or AZHAQ_DB
  azhaq subs   -d DOMAIN | -dL FILE | stdin  [-live] [-json] [-silent] [-o FILE]   # like subfinder
  azhaq dns    -d NAME | -l FILE | stdin  [-resp] [-json]                        # like dnsx
  azhaq probe  -u TARGET | -l FILE | stdin  [-web-ports P] [-json] [-silent]     # like httpx
  azhaq crawl  -u URL | -l FILE | stdin  [-depth N] [-assets] [-json]            # like katana
  azhaq urls   -d DOMAIN | -dL FILE | stdin  [-json]                              # like gau
  azhaq ports  -host HOST | -l FILE | stdin  [-p top-100|top-1000|full|LIST] [-rate N] [-json]  # like naabu
  azhaq dirs   -u URL | -l FILE | stdin  -w WORDLIST [-e EXT] [-depth N] [-mc LIST] [-json]   # like ffuf -ac
  azhaq params -u URL | -l FILE | stdin  -w NAMES [-rate N] [-json]                # like arjun (GET)
  azhaq asn    -a AS64500 | -l FILE | stdin  [-json]                               # like asnmap
  azhaq shots  -u TARGET | -l FILE | stdin  [-dir DIR] [-tabs N] [-json]           # like gowitness
               # results on stdout, one per line; progress on stderr (-silent drops it)
  azhaq plan   -url URL | -domain D | -org NAME | -cloud FILE | -in seeds.jsonl
  azhaq scope  -scope FILE|hackerone|bugcrowd|intigriti|yeswehack [-program NAME]  # show what a run would take
  azhaq watch  -db WORKSPACE.db [-every 24h] [-notify WEBHOOK] [-notify-cmd CMD] [-json] -- RUN OPTIONS
               # run again and again; report new hosts, services, URLs and ports
  azhaq new    -db WORKSPACE.db [-since 168h] [-json]       # what the workspace first saw lately
  azhaq roles  -role anon -role 'user=Authorization: Bearer …' [-dir DIR] [-jsonl] -- RUN OPTIONS
               # one run per session; prints the endpoints whose status differs
  azhaq ingest -in facts.jsonl  [-db FILE]
  azhaq export [-db FILE]
  azhaq diff   -a OLD.db -b NEW.db | -db WORKSPACE.db  [-jsonl] [-quiet]
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
	list := fs.String("list", "", "targets, one per line: URL, host, host:port or IP (- for stdin)")
	var asns, cidrs stringsFlag
	fs.Var(&asns, "asn", "seed an autonomous system: its announced prefixes (repeatable)")
	fs.Var(&cidrs, "cidr", "seed an address range such as 192.0.2.0/24 (repeatable)")
	render := fs.Bool("browser", false, "also load pages in Chrome: the requests their scripts send and the links of the rendered page (needs Chrome)")
	shots := fs.String("screenshots", "", "save a screenshot of each web service's front page in this directory (needs Chrome)")
	tabs := fs.Int("tabs", 4, "Chrome tabs open at once for screenshots and -browser")
	urlsTimeout := fs.Duration("urls-timeout", 3*time.Minute, "time each archive source gets per domain (the Wayback Machine's answer for a large domain takes several minutes)")
	login := fs.String("login", "", "sign in on this page with Chrome before the run; its cookies and token go with every request (needs -login-user and -login-pass)")
	loginUser := fs.String("login-user", "", "user name or email for -login")
	loginPass := fs.String("login-pass", "", "password for -login (default $AZHAQ_LOGIN_PASS)")
	maxIPs := fs.Int("max-ips", 4096, "addresses expanded from -asn and -cidr prefixes, for the whole run")
	scopeSpec := fs.String("scope", "", "a program's scope: a file (HackerOne CSV, bounty-targets JSON, Burp options, lines) or hackerone, bugcrowd, intigriti, yeswehack")
	program := fs.String("program", "", "the program to take from a -scope list (handle, name or URL)")
	probe := fs.Bool("probe", false, "resolve and fetch each target once, print one line per web service, no crawl or enumeration")
	noTech := fs.Bool("no-tech", false, "skip technology fingerprints (saves about 30 MB of memory)")
	urlsOut := fs.String("urls", "", "write every archived URL of the run's domains to this file, one per line")
	webPorts := fs.String("web-ports", "", "ports to probe on each hostname, comma-separated (default: 443, falling back to 80)")
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
	maxItems := fs.Int("max-items", 0, "max collector invocations (default 2048)")
	maxRequests := fs.Int64("max-requests", 0, "requests to targets this run may send (0: no cap); the work left over is for azhaq resume")
	rateFlag := fs.Float64("rate", 0, "requests per second to targets, over all hosts (0: no pace)")
	resumeRun := fs.String("resume-run", "", "continue this run of -db (azhaq resume sets it)")
	serve := fs.String("serve", "", "let azhaq worker processes take this run's work, at this address (127.0.0.1:7777)")
	workerToken := fs.String("worker-token", os.Getenv("AZHAQ_WORKER_TOKEN"), "the token workers give (default $AZHAQ_WORKER_TOKEN, else a new one)")
	workerOf := fs.String("worker-of", "", "run as a worker of the run at this address (azhaq worker sets it)")
	daily := fs.Int64("daily-requests", 0, "requests a day to the program's targets (-program, else this run's targets), counted over the runs in -db")
	maxNames := fs.Int("max-names", 0, "max hostnames resolved (default 20000)")
	parallel := fs.Int("parallel", 0, "work items in flight (default 16)")
	delay := fs.Duration("delay", 0, "pause before each uncached fetch")
	hostParallel := fs.Int("host-parallel", 0, "requests in flight per host (default 4)")
	sourcesList := fs.String("sources", "", "subdomain sources to run, comma-separated (default: the default set)")
	excludeSources := fs.String("exclude-sources", "", "subdomain sources never to run, comma-separated")
	allSources := fs.Bool("all-sources", false, "also run slower subdomain sources outside the default set")
	providersFile := fs.String("providers", "", "API keys per source, YAML (default ~/.config/azhaq/providers.yaml, else subfinder's provider-config.yaml)")
	resolversFile := fs.String("resolvers", "", "DNS resolvers, one per line (default: public resolvers)")
	dnsRate := fs.Float64("dns-rate", 100, "DNS queries per second per resolver")
	bruteFile := fs.String("dns-brute", "", "resolve WORD.domain for each word in this file (active: needs -allow)")
	permute := fs.Bool("permute", false, "resolve variations of found names (active: needs -allow)")
	portsSpec := fs.String("ports", "", "scan TCP ports: top-100, top-1000, full or a list such as 22,80,8000-8100 (active: needs -allow)")
	portRate := fs.Float64("port-rate", 300, "port connection attempts per second")
	dirsFile := fs.String("dirs", "", "guess paths on each web service from this wordlist (active: needs -allow)")
	dirsExt := fs.String("dirs-ext", "", "also try each word with these extensions, comma-separated (php,bak)")
	dirsDepth := fs.Int("dirs-depth", 1, "directory levels to sweep; 2 also sweeps directories found")
	dirsThreads := fs.Int("dirs-threads", 20, "path guesses in flight per service")
	dirsRate := fs.Float64("dirs-rate", 100, "path guesses per second per host")
	paramsFile := fs.String("params", "", "find query parameters pages read, from this wordlist (active: needs -allow)")
	paramsPerHost := fs.Int("params-per-host", 20, "pages searched for parameters per host")
	paramsRate := fs.Float64("params-rate", 20, "parameter requests per second per host")
	dirsMatch := fs.String("dirs-mc", "", "statuses to report (default ffuf's: 200-299,301,302,307,401,403,405,500)")
	graphql := fs.Bool("graphql", false, "read the schema of GraphQL endpoints with an introspection query (active: needs -allow)")
	skip := fs.String("skip", "", "collectors not to run, comma-separated (see azhaq plan)")
	var cookies, headers, allow, deny, domains stringsFlag
	fs.Var(&domains, "domain", "seed Domain, for subdomain discovery (repeatable)")
	fs.Var(&cookies, "cookie", "Cookie name=value (repeatable; sent as one Cookie header)")
	fs.Var(&headers, "header", "extra request header K: V (repeatable)")
	fs.Var(&allow, "allow", "allowed domain or host for fan-out (repeatable)")
	fs.Var(&deny, "deny", "excluded domain or host (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	fetch.Reset()
	fetch.Delay = *delay
	if *hostParallel > 0 {
		fetch.HostParallel = *hostParallel
	}
	if err := applyExtra(cookies, append(headers, workerHeaders...)); err != nil {
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
		if *list != "" {
			more, err := loadList(*list)
			if err != nil {
				return err
			}
			seeds = append(seeds, more...)
		}
		for _, a := range asns {
			n, ok := asncol.NormalizeASN(a)
			if !ok {
				return fmt.Errorf("-asn wants a number such as AS64500, got %q", a)
			}
			seeds = append(seeds, types.Seed{Type: types.TypeASN, Keys: map[string]string{"asn": n}})
		}
		for _, c := range cidrs {
			pf, err := netip.ParsePrefix(strings.TrimSpace(c))
			if err != nil {
				return fmt.Errorf("-cidr: %w", err)
			}
			seeds = append(seeds, types.Seed{Type: types.TypePrefix, Keys: map[string]string{"prefix": pf.Masked().String()}})
		}
		if *scopeSpec != "" {
			sc, err := loadScope(*scopeSpec, *program)
			if err != nil {
				return err
			}
			more, err := scopeSeeds(sc)
			if err != nil {
				return err
			}
			seeds = append(seeds, more...)
			allow = append(allow, sc.Allow...)
			deny = append(deny, sc.Deny...)
			if !*quiet && !*jsonOut {
				fmt.Fprintf(os.Stderr, "scope %s: %d rules in, %d out, %d domains, %d targets, %d entries skipped\n",
					sc.Program, len(sc.Allow), len(sc.Deny), len(sc.Domains), len(sc.Targets), len(sc.Skipped))
			}
		}
		for _, d := range domains {
			h := normalize.Hostname(d)
			if h == "" || strings.ContainsAny(h, "/: ") {
				return fmt.Errorf("-domain wants a bare domain such as example.com, got %q", d)
			}
			seeds = append(seeds, types.Seed{Type: types.TypeDomain, Keys: map[string]string{"domain": h}})
		}
		if len(seeds) == 0 && *factsPath == "" && *execCmd == "" && *workerOf == "" {
			return fmt.Errorf("need -url, -domain, -list, -scope, -asn, -cidr, -org, -cloud, -in, -facts, -exec, or -demo")
		}
		if *execCmd != "" && len(seeds) == 0 {
			return fmt.Errorf("-exec needs a seed (-url, -org, -cloud, or -in)")
		}
	}

	input := store.SeedsKey(normalizeSeeds(seeds))
	path, remember := resolveDB(*dbPath)
	prevDB := ""
	if remember {
		prevDB = previousRun(input)
		if err := os.WriteFile(lastDBFile, []byte(path+"\n"), 0o644); err != nil {
			return err
		}
	}

	st, err := store.Open(path)
	if err != nil {
		return err
	}
	defer st.Close()
	if input != "" && !*demo {
		if err := st.SaveInput(input); err != nil {
			return err
		}
	}
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
	if *maxNames > 0 {
		budgets.MaxNames = *maxNames
	}
	if *parallel > 0 {
		budgets.Parallel = *parallel
	}
	budgets.Skip = map[string]bool{}
	for _, name := range splitList(*skip) {
		budgets.Skip[name] = true
	}
	ports, err := parsePorts(*webPorts)
	if err != nil {
		return err
	}
	budgets.Active = map[string]bool{}
	if *bruteFile != "" {
		budgets.Active["dns-brute"] = true
	}
	if *permute {
		budgets.Active["permute"] = true
	}
	if *graphql {
		budgets.Active["graphql"] = true
	}
	if *portsSpec != "" {
		budgets.Active["ports"] = true
	}
	if *dirsFile != "" {
		budgets.Active["dirs"] = true
	}
	if *paramsFile != "" {
		budgets.Active["params"] = true
	}
	if !budgets.Scope.Empty() {
		fetch.Allow = budgets.Scope.Allows
	}
	if len(budgets.Active) > 0 && len(allow) == 0 {
		return fmt.Errorf("-dns-brute, -permute, -graphql, -ports, -dirs and -params are active: name the scope with -allow DOMAIN")
	}
	doneBefore := 0
	if *resumeRun != "" {
		st.UseRun(*resumeRun)
		budgets.Resume = true
		doneBefore = st.TasksDone()
	} else {
		if err := st.BeginRun(newRunID(), *depth, budgets.MaxItems); err != nil {
			return err
		}
		if err := st.SetRunArgs(keptArgs(args)); err != nil {
			return err
		}
	}
	fetch.SetRate(*rateFlag)
	fetch.MaxRequests = *maxRequests
	if *daily > 0 {
		key := *program
		if key == "" {
			key = input
		}
		day := time.Now().UTC().Format(time.DateOnly)
		left := *daily - st.Spent(key, day)
		if left <= 0 {
			return fmt.Errorf("-daily-requests: the %d requests of %s are spent (resets at 00:00 UTC)", *daily, day)
		}
		if fetch.MaxRequests == 0 || left < fetch.MaxRequests {
			fetch.MaxRequests = left
		}
		defer func() { _ = st.AddSpent(key, day, fetch.Sent()) }()
	}
	cat := catalog.New()
	opts := collectors.Options{Client: client, WebPorts: ports, NoTech: *noTech, PortRate: *portRate, MaxIPs: *maxIPs, Shots: *shots, Render: *render}
	if *shots != "" || *render {
		if _, err := browser.Find(); err != nil {
			return fmt.Errorf("-screenshots and -browser: %w", err)
		}
		hdr := map[string]any{}
		for k, vs := range fetch.Extra {
			if len(vs) > 0 && !strings.EqualFold(k, "User-Agent") {
				hdr[k] = strings.Join(vs, ", ")
			}
		}
		opts.Browser = &browser.Browser{Tabs: *tabs, UserAgent: fetch.Extra.Get("User-Agent"), Header: hdr}
		defer opts.Browser.Close()
	}
	if *login != "" {
		home, err := signIn(opts.Browser, *login, *loginUser, *loginPass)
		if err != nil {
			return err
		}
		// The page the login ended on is the signed-in app.
		if home != *login && hasHost(seeds, home) {
			seeds = append(seeds, types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": home}})
		}
	}
	if *portsSpec != "" {
		if opts.Ports, err = portscan.Ports(*portsSpec); err != nil {
			return fmt.Errorf("-ports: %w", err)
		}
	}
	if *paramsFile != "" {
		words, err := loadLines(*paramsFile)
		if err != nil {
			return err
		}
		opts.Params = paramcol.Options{Words: words, PerHost: *paramsPerHost, Rate: *paramsRate}
	}
	if *dirsFile != "" {
		words, err := loadLines(*dirsFile)
		if err != nil {
			return err
		}
		opts.Dirs = dirscol.Options{Words: words, Extensions: splitList(*dirsExt), Depth: *dirsDepth, Threads: *dirsThreads, Rate: *dirsRate}
		if *dirsMatch != "" {
			if opts.Dirs.Match, err = dirscol.ParseStatuses(*dirsMatch); err != nil {
				return fmt.Errorf("-dirs-mc: %w", err)
			}
		}
	}
	if *pathsFile != "" {
		if opts.Paths, err = loadPathList(*pathsFile); err != nil {
			return err
		}
	}
	var resolvers []string
	if *resolversFile != "" {
		if resolvers, err = loadLines(*resolversFile); err != nil {
			return err
		}
	}
	opts.DNS = dnsr.New(dnsr.Options{Resolvers: resolvers, PerSecond: *dnsRate})
	if *bruteFile != "" {
		if opts.BruteWords, err = loadLines(*bruteFile); err != nil {
			return err
		}
	}
	providerPaths := subcol.ProviderPaths()
	if *providersFile != "" {
		providerPaths = []string{*providersFile}
	}
	keys, _, err := subcol.LoadProviders(providerPaths...)
	if err != nil {
		return fmt.Errorf("provider keys: %w", err)
	}
	opts.Subdomains = subcol.Options{Keys: keys, Only: splitList(*sourcesList), Exclude: splitList(*excludeSources), All: *allSources}
	opts.URLs = urlcol.Options{Keys: keys, Out: *urlsOut, Timeout: *urlsTimeout}
	if *urlsOut != "" && *resumeRun == "" {
		if err := os.WriteFile(*urlsOut, nil, 0o644); err != nil { // start empty; each domain appends
			return err
		}
	}
	collectors.Register(cat, opts)
	if *probe {
		budgets.MaxDepth = 1 // the listed targets only: no CNAME or redirect targets
		for _, n := range cat.Names() {
			if n != "azhaq-dns" && n != "azhaq-http" {
				budgets.Skip[n] = true
			}
		}
	}
	if *workerOf != "" {
		return runWorker(cat, *workerOf, *workerToken, budgets.Parallel)
	}
	eng := &engine.Engine{Cat: cat, Store: st}
	if *serve != "" {
		if *workerToken == "" {
			*workerToken = newToken()
		}
		cfg, err := forWorkers(fs, args, allow, deny)
		if err != nil {
			return err
		}
		eng.Workers = engine.NewWorkers()
		stopServe, err := serveWorkers(*serve, *workerToken, eng.Workers, cfg)
		if err != nil {
			return fmt.Errorf("-serve: %w", err)
		}
		defer stopServe()
		fmt.Fprintf(os.Stderr, "azhaq: workers can join with: AZHAQ_WORKER_TOKEN=%s azhaq worker -server http://%s\n", *workerToken, *serve)
	}

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
	if !*quiet && !*jsonOut && *probe {
		fmt.Println("probe")
		for _, r := range engine.ProbeRows(obs) {
			fmt.Printf("  %s\n", r.Line())
		}
	} else if !*quiet && !*jsonOut {
		fmt.Println("map")
		printMap(rows)
		if *showObs {
			fmt.Println("observations")
			for _, o := range obs {
				fmt.Printf("  %s %s %s\n", o.Collector, o.Kind, compact(o.Payload))
			}
		}
	}
	stats.DB = path
	stats.Requests, stats.MaxRequests = fetch.Sent(), fetch.MaxRequests
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
	if left := st.TasksLeft(); left > 0 && !*quiet {
		fmt.Fprintf(os.Stderr, "azhaq: %d tasks left; azhaq resume -db %s continues the run\n", left, path)
		if *resumeRun != "" && st.TasksDone() == doneBefore && fetch.Spent() {
			fmt.Fprintf(os.Stderr, "azhaq: no task finished: each one left needs more than %d requests (a path sweep needs one per word); raise -max-requests\n", fetch.MaxRequests)
		}
	}
	if *failErrs && stats.Errors+stats.Degraded > 0 {
		return fmt.Errorf("run %s: %d error(s), %d degraded", stats.RunID, stats.Errors, stats.Degraded)
	}
	if *failCapped && stats.Capped {
		return fmt.Errorf("run %s: capped (depth=%d max-items=%d)", stats.RunID, stats.Depth, stats.MaxItems)
	}
	if remember && !*demo && input != "" {
		_ = recordRun(input, path)
	}
	if !*quiet && !*jsonOut && !*demo && prevDB != "" && prevDB != path {
		if err := printDiff(prevDB, path, diffOpts{}); err != nil {
			fmt.Fprintf(os.Stderr, "azhaq: diff vs %s: %v\n", prevDB, err)
		}
	}
	if !*quiet && !*jsonOut && !*demo && !remember {
		// -db names a workspace: compare with its previous run, if any.
		if err := printRunDiff(path, diffOpts{}); err != nil {
			fmt.Fprintf(os.Stderr, "azhaq: diff vs the previous run in %s: %v\n", path, err)
		}
	}
	return nil
}

const runIndexFile = ".azhaq-index"

// previousRun is the last database written in this directory for the same
// seeds. Diffing against a run of another target would be noise.
func previousRun(input string) string {
	idx := readRunIndex()
	path := idx[input]
	if path == "" {
		return ""
	}
	if _, err := os.Stat(path); err != nil {
		return ""
	}
	return path
}

func readRunIndex() map[string]string {
	idx := map[string]string{}
	raw, err := os.ReadFile(runIndexFile)
	if err != nil {
		return idx
	}
	_ = json.Unmarshal(raw, &idx)
	return idx
}

func recordRun(input, path string) error {
	idx := readRunIndex()
	idx[input] = path
	raw, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(runIndexFile, append(raw, '\n'), 0o644)
}

func normalizeSeeds(seeds []types.Seed) []types.Seed {
	out := make([]types.Seed, 0, len(seeds))
	for _, s := range seeds {
		out = append(out, normalize.Seed(s))
	}
	return out
}

func printMap(rows []engine.MapEntry) {
	for _, row := range engine.GroupTemplates(rows) {
		fmt.Printf("  %s\n", row.Line())
		for _, d := range row.Details() {
			fmt.Printf("      %s\n", d)
		}
	}
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
	printMap(engine.BuildMap(ents, hints, obs, nil, false))
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
	var domains stringsFlag
	fs.Var(&domains, "domain", "seed Domain (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	seeds, err := loadSeeds(*url, *org, *cloud, *in)
	if err != nil {
		return err
	}
	for _, d := range domains {
		seeds = append(seeds, types.Seed{Type: types.TypeDomain, Keys: map[string]string{"domain": normalize.Hostname(d)}})
	}
	if len(seeds) == 0 {
		return fmt.Errorf("need -url, -domain, -org, -cloud, or -in")
	}
	cat := catalog.New()
	collectors.RegisterAll(cat, nil)
	eng := &engine.Engine{Cat: cat}
	enc := json.NewEncoder(os.Stdout)
	for _, item := range eng.Plan(engine.ExpandSeeds(seeds)) {
		if col, ok := cat.Get(item.Collector); ok && catalog.InfoOf(col).Kind == catalog.Active {
			continue // runs only with its own flag
		}
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
	ws := fs.String("db", "", "workspace: compare the last two runs recorded in this database")
	jsonl := fs.Bool("jsonl", false, "emit JSONL instead of a text report")
	quiet := fs.Bool("quiet", false, "entities and counts only (skip observation lines)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *ws != "" {
		return printRunDiff(*ws, diffOpts{JSONL: *jsonl, Quiet: *quiet})
	}
	if *a == "" {
		return fmt.Errorf("need -a OLD.db, or -db WORKSPACE.db")
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
	return printDiffStores(old, neu, oldPath, opts)
}

// printRunDiff compares the last two runs recorded in one database (a
// workspace). It prints nothing when there is only one run.
func printRunDiff(path string, opts diffOpts) error {
	old, err := store.OpenExisting(path)
	if err != nil {
		return err
	}
	defer old.Close()
	runs, err := old.Runs()
	if err != nil || len(runs) < 2 {
		return err
	}
	neu, err := store.OpenExisting(path)
	if err != nil {
		return err
	}
	defer neu.Close()
	prev, last := runs[len(runs)-2], runs[len(runs)-1]
	old.UseRun(prev.ID)
	neu.UseRun(last.ID)
	return printDiffStores(old, neu, fmt.Sprintf("the run of %s in %s", prev.Started.Format("2006-01-02 15:04"), path), opts)
}

func printDiffStores(old, neu *store.Store, oldLabel string, opts diffOpts) error {
	d, err := store.Compare(old, neu)
	if err != nil {
		return err
	}
	oldIn, newIn := old.Input(), neu.Input()
	differ := oldIn != "" && newIn != "" && oldIn != newIn
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
		sum := map[string]any{
			"kind":         "summary",
			"added":        len(d.Added),
			"removed":      len(d.Removed),
			"observations": len(d.NewObs),
		}
		if differ {
			sum["seeds_differ"] = true
		}
		return enc.Encode(sum)
	}
	fmt.Printf("diff vs %s\n", oldLabel)
	if differ {
		fmt.Printf("  ! the runs had different seeds; this compares two targets, not two scans of one\n")
		fmt.Printf("    old: %s\n    new: %s\n", strings.ReplaceAll(oldIn, "\n", ", "), strings.ReplaceAll(newIn, "\n", ", "))
	}
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
	format := fs.String("format", "jsonl", "jsonl, urls, hosts, targets (for nuclei -l), openapi, burp (scope), html, graphml, secrets")
	origin := fs.String("origin", "", "openapi: the origin to describe (default: the one with most API routes)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *format != "jsonl" {
		path := *dbPath
		if path == "" {
			path = readLastDB()
		}
		if path == "" {
			return fmt.Errorf("need -db (no %s from a previous run)", lastDBFile)
		}
		return exportAs(path, *format, *origin, os.Stdout)
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
		if row.Template != "" {
			out["template"] = row.Template
		}
		if len(row.Methods) > 0 {
			out["methods"] = row.Methods
		}
		if len(row.Params) > 0 {
			out["params"] = row.Params
		}
		if len(row.Forms) > 0 {
			out["forms"] = row.Forms
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

// loadList reads targets the way httpx does: a URL is fetched as given, a
// bare host is probed over HTTPS then HTTP, and host:port or an IP address
// becomes a URL that falls back to plain HTTP.
func loadList(path string) ([]types.Seed, error) {
	var lines []string
	var err error
	if path == "-" {
		lines, err = readLines(os.Stdin)
	} else {
		lines, err = loadLines(path)
	}
	if err != nil {
		return nil, err
	}
	var seeds []types.Seed
	for i, line := range lines {
		s, err := listSeed(line)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, i+1, err)
		}
		seeds = append(seeds, s)
	}
	return seeds, nil
}

func listSeed(line string) (types.Seed, error) {
	if strings.Contains(line, "://") {
		u, err := parseCLIURL(line)
		if err != nil {
			return types.Seed{}, err
		}
		return types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": u}}, nil
	}
	if strings.ContainsAny(line, " /?#@") {
		return types.Seed{}, fmt.Errorf("want a URL, host, host:port or IP, got %q", line)
	}
	host, port, err := net.SplitHostPort(line)
	if err != nil {
		host, port = strings.Trim(line, "[]"), ""
	}
	if ip := net.ParseIP(host); ip == nil && port == "" {
		return types.Seed{Type: types.TypeHostname, Keys: map[string]string{"fqdn": normalize.Hostname(host)}}, nil
	}
	hp := host
	if net.ParseIP(host) != nil && strings.Contains(host, ":") {
		hp = "[" + host + "]"
	}
	if port == "80" {
		return types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": "http://" + hp + "/"}}, nil
	}
	if port != "" {
		hp = net.JoinHostPort(host, port)
	}
	return types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": "https://" + hp + "/", httpcol.FallbackKey: "http"}}, nil
}

func parsePorts(raw string) ([]int, error) {
	var out []int
	for _, p := range splitList(raw) {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("-web-ports: bad port %q", p)
		}
		out = append(out, n)
	}
	return out, nil
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
	if i := strings.IndexFunc(raw, func(r rune) bool { return r <= ' ' || r == 0x7f }); i >= 0 {
		return "", fmt.Errorf("URL contains whitespace or a control character: %q", raw)
	}
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
	if s.Type == types.TypeURL {
		u, err := parseCLIURL(s.Keys["url"])
		if err != nil {
			return types.Seed{}, err
		}
		s.Keys["url"] = u
	}
	return s, nil
}

// loadLines reads one entry per line, skipping blanks and # comments.
func loadLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readLines(f)
}

// readLines returns non-empty lines that are not # comments.
func readLines(r io.Reader) ([]string, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(raw), "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out, nil
}

func splitList(s string) []string {
	var out []string
	for _, x := range strings.Split(s, ",") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
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

// hasHost says whether a URL seed is on the host of raw.
func hasHost(seeds []types.Seed, raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	for _, sd := range seeds {
		if su, err := url.Parse(sd.Keys["url"]); err == nil && sd.Type == types.TypeURL && su.Host == u.Host {
			return true
		}
	}
	return false
}

// signIn signs in on loginURL with Chrome (b, or a browser of its own) and
// adds the session to every request; it returns the page the login ended
// on.
func signIn(b *browser.Browser, loginURL, user, pass string) (string, error) {
	if pass == "" {
		pass = os.Getenv("AZHAQ_LOGIN_PASS")
	}
	if user == "" || pass == "" {
		return "", fmt.Errorf("-login needs -login-user and -login-pass (or AZHAQ_LOGIN_PASS)")
	}
	if b == nil {
		b = &browser.Browser{UserAgent: fetch.Extra.Get("User-Agent")}
		defer b.Close()
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	s, err := b.Login(ctx, loginURL, user, pass)
	if err != nil {
		return "", fmt.Errorf("-login %s: %w", loginURL, err)
	}
	if len(s.Cookies) == 0 && s.Bearer == "" {
		return "", fmt.Errorf("-login %s: signed in, but the site set no cookie and stored no token", loginURL)
	}
	if fetch.Extra == nil {
		fetch.Extra = make(http.Header)
	}
	if len(s.Cookies) > 0 {
		c := strings.Join(s.Cookies, "; ")
		if old := fetch.Extra.Get("Cookie"); old != "" {
			c = old + "; " + c
		}
		fetch.Extra.Set("Cookie", c)
	}
	what := fmt.Sprintf("%d cookies", len(s.Cookies))
	if s.Bearer != "" && fetch.Extra.Get("Authorization") == "" {
		fetch.Extra.Set("Authorization", "Bearer "+s.Bearer)
		if b.Header == nil {
			b.Header = map[string]any{}
		}
		b.Header["Authorization"] = "Bearer " + s.Bearer // the browser keeps the cookies itself
		what += ", a token from " + s.From
	}
	fmt.Fprintf(os.Stderr, "azhaq: signed in as %s (%s); now on %s\n", user, what, s.URL)
	return s.URL, nil
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
	for _, k := range []string{"status", "catchall", "title", "url", "via", "methods", "path", "fqdn", "ips", "params", "role", "count", "not_after", "error", "skipped", "registrar", "registrant", "name", "id", "method", "action", "fields", "auth", "final_url", "extracted", "warning", "note"} {
		if v, ok := m[k]; ok && v != nil && fmt.Sprint(v) != "" {
			parts = append(parts, fmt.Sprintf("%s=%v", k, v))
		}
	}
	return strings.Join(parts, " ")
}
