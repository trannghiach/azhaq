package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/trannghiach/azhaq/engine"
	"github.com/trannghiach/azhaq/internal/connector"
	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/internal/fuzz"
	"github.com/trannghiach/azhaq/internal/neterr"
	"github.com/trannghiach/azhaq/scope"
	"github.com/trannghiach/azhaq/store"
)

// cmdFuzz is ffuf: a request template with keywords, wordlists put into
// it, matchers and filters on the answers. It keeps ffuf's flags and
// counting so its results are the same; every request goes through the
// run's budget and pace, and the host of -u is the scope.
func cmdFuzz(args []string) error {
	fs := newFlags("fuzz")
	var c common
	c.register(fs)
	fs.Lookup("db").Usage = "keep the matches in this database for query, show, export and diff (none by default)"
	fs.Lookup("silent").Usage = "print the input values only, no progress; the summary only when something failed"
	fs.Lookup("o").Usage = "write the report to this file, in the format -of says (json by default; a name ending .txt gets what stdout shows, as before)"
	fs.BoolVar(&c.silent, "s", false, "ffuf's name for -silent")
	rawURL := fs.String("u", "", "target URL; the keyword (FUZZ) may stand anywhere in it, in the host too")
	var lists, headers, cookies, allow, deny, inputCmds, encs, acStrategies, acStrings stringsFlag
	fs.Var(&lists, "w", "wordlist `FILE[:KEYWORD]` (- for stdin; repeatable; a comma list is several; the keyword is FUZZ without one)")
	mode := fs.String("mode", "clusterbomb", "how several wordlists combine: clusterbomb (every combination), pitchfork (line by line) or sniper (one wordlist in each §marked§ place of the request in turn)")
	method := fs.String("X", "", "HTTP method (default GET, POST with -d); the keyword may stand in it")
	data := fs.String("d", "", "request body; the keyword may stand in it")
	fs.StringVar(data, "data", "", "ffuf's alias of -d")
	fs.StringVar(data, "data-ascii", "", "ffuf's alias of -d")
	fs.StringVar(data, "data-binary", "", "ffuf's alias of -d")
	fs.Var(&headers, "H", "header \"Name: value\"; the keyword may stand in name and value, Host included (repeatable). A header that names a host (Host, X-Forwarded-Host, X-Host, X-Original-Host) joins the target when no -allow, -deny or -scope is given; with one, the host must be in the scope")
	fs.Var(&cookies, "b", "cookie data \"NAME=VALUE; NAME2=VALUE2\"")
	fs.Var(&cookies, "cookie", "ffuf's alias of -b")
	reqFile := fs.String("request", "", "read the request from this file (a raw HTTP request, as Burp saves it); -u, -X, -d, -H and -b replace what it holds")
	reqProto := fs.String("request-proto", "https", "the protocol for the URL a -request file's Host header gives")
	proxy := fs.String("x", "", "send every request through this proxy: an http, https, socks5 or socks5h URL")
	replayProxy := fs.String("replay-proxy", "", "send each match once more through this proxy (Burp, for the history); the copy is the proxy's own, not counted by -max-requests or -rate and not in the ledger")
	ignoreBody := fs.Bool("ignore-body", false, "do not read the answer's body: size is the Content-Length, words and lines 0")
	raw := fs.Bool("raw", false, "send the path and query as written, not encoded")
	sni := fs.String("sni", "", "the server name for TLS (the keyword does not work here)")
	http2 := fs.Bool("http2", false, "use HTTP/2 where the server offers it")
	certFile := fs.String("cc", "", "client certificate file for TLS; -ck names its key")
	keyFile := fs.String("ck", "", "client key file for TLS")
	mc := fs.String("mc", "", "match these statuses, comma-separated values and ranges, or all (default 200-299,301,302,307,401,403,405,500, unless another matcher is given)")
	ms := fs.String("ms", "", "match these response sizes (values and ranges)")
	mw := fs.String("mw", "", "match these word counts (values and ranges)")
	ml := fs.String("ml", "", "match these line counts (values and ranges)")
	mr := fs.String("mr", "", "match answers (headers and body) with this regexp; the keyword stands for its input")
	mt := fs.String("mt", "", "match answers by milliseconds to the first byte: >MS or <MS")
	fc := fs.String("fc", "", "filter out these statuses")
	fsz := fs.String("fs", "", "filter out these response sizes")
	fw := fs.String("fw", "", "filter out these word counts")
	fl := fs.String("fl", "", "filter out these line counts")
	fr := fs.String("fr", "", "filter out answers matching this regexp")
	ft := fs.String("ft", "", "filter out answers by milliseconds to the first byte: >MS or <MS")
	mmode := fs.String("mmode", "or", "matchers: an answer must match any (or) or all (and) of them")
	fmode := fs.String("fmode", "or", "filters: an answer is dropped by any (or) or by all (and) of them")
	ac := fs.Bool("ac", false, "calibrate the filters on names that cannot exist, as ffuf does (off by default, as in ffuf; -acs, -acc and -ach turn it on too)")
	ack := fs.String("ack", "FUZZ", "the keyword calibration replaces")
	ach := fs.Bool("ach", false, "calibrate for each host and directory of the path (with a Host header or a keyword in the host)")
	fs.Var(&acStrategies, "acs", "calibration strategy: basic, advanced (adds the names as directories), or a file ~/.config/ffuf/autocalibration/NAME.json (repeatable or comma list)")
	fs.Var(&acStrings, "acc", "a name to calibrate with instead of the random ones (repeatable)")
	recursion := fs.Bool("recursion", false, "descend into directories found (the URL must end with FUZZ)")
	depth := fs.Int("recursion-depth", 0, "levels of recursion (0: no limit)")
	strategy := fs.String("recursion-strategy", "default", "default: directories that redirect to themselves; greedy: every match")
	start := fs.Int("start", 0, "skip the first N inputs: where a stopped run left off (its summary gives the command)")
	exts := fs.String("e", "", "extensions added to each FUZZ word, comma-separated: .php,.bak")
	dirsearch := fs.Bool("D", false, "dirsearch wordlists: %EXT% in a line stands for each -e extension")
	ic := fs.Bool("ic", false, "ignore comments in wordlists")
	fs.Var(&inputCmds, "input-cmd", "a command whose output is the input, `COMMAND[:KEYWORD]`, run for each number up to -input-num with FFUF_NUM set (repeatable)")
	inputNum := fs.Int("input-num", 100, "how many inputs an -input-cmd gives")
	inputShell := fs.String("input-shell", "/bin/sh", "the shell that runs an -input-cmd")
	fs.Var(&encs, "enc", "encoders for a keyword: 'FUZZ:urlencode b64encode' (repeatable); one of "+strings.Join(fuzz.EncoderNames(), ", ")+" or a .tmpl file with #PAYLOAD#")
	threads := fs.Int("t", 40, "requests in flight")
	rate := fs.Float64("rate", 0, "requests per second, over all (0: no pace)")
	delay := fs.String("p", "", "seconds each thread waits after a request: 0.1, or a random time in a range 0.1-2.0")
	ledgerFlag := fs.String("ledger", "", ledgerHelp)
	killFile := fs.String("kill-file", "", killFileHelp)
	sealTo := fs.String("seal-to", "", sealToHelp)
	timeout := fs.Float64("timeout", 10, "each request's timeout, in `seconds`")
	maxtime := fs.Float64("maxtime", 0, "stop after this many `seconds` and say so (0: no limit)")
	maxtimeJob := fs.Float64("maxtime-job", 0, "give up a job (the first one, or a directory found by -recursion) after this many `seconds` and go on with the next (0: no limit)")
	sf := fs.Bool("sf", false, "stop when more than 95% of the first 50 or more answers are 403")
	sa := fs.Bool("sa", false, "stop on all of these: -sf, over 20% of answers 429, and -se")
	se := fs.Bool("se", false, "stop on spurious errors: twice -t requests in a row failing (without it, five requests in a row that got no answer stop the run)")
	seAfter := fs.Int("se-after", 0, "stop after this many requests in a row failing, in place of -se's twice -t")
	follow := fs.Bool("r", false, "follow redirects")
	verbose := fs.Bool("v", false, "print the full URL and redirect location with each result")
	maxReq := fs.Int64("max-requests", 0, "requests this run may send (0: no cap)")
	scopeSpec := fs.String("scope", "", "a program's scope: a file or hackerone, bugcrowd, intigriti, yeswehack")
	program := fs.String("program", "", "the program to take from a -scope list")
	fs.Var(&allow, "allow", "a domain, host or address range the run may touch (repeatable); default: the host of -u")
	fs.Var(&deny, "deny", "a domain, host or address range the run must not touch (repeatable)")
	flights := &flightFlags{}
	fs.Var(flightFile{flights, false}, "preflight", "a raw request file sent before each fuzzing request (repeatable, in order); it carries -H and -b of the command, and is held to the scope, budget and pace")
	fs.Var(flightVar{flights, false, false}, "preflight-var", "a value read from the answer of the -preflight before it: NAME:regexp (the first group; the body, then the headers); NAME in later requests stands for it (repeatable)")
	fs.Var(flightVar{flights, false, true}, "preflight-var-auto", "a value read from that answer by name: NAME:key tries a form field, meta tag, cookie and header, NAME:[form|meta|cookie|header]key names one (repeatable)")
	fs.Var(flightFile{flights, true}, "postflight", "a raw request file sent after each fuzzing request that was answered (repeatable)")
	fs.Var(flightVar{flights, true, false}, "postflight-var", "like -preflight-var, for the -postflight before it")
	fs.Var(flightVar{flights, true, true}, "postflight-var-auto", "like -preflight-var-auto, for the -postflight before it")
	preMode := fs.String("preflight-mode", "per-request", "per-request: the preflights run before each request; per-thread: once for each thread, its values kept")
	preError := fs.String("preflight-error", "abort", "abort: a failed flight fails the request; ignore: it is noted and the request goes on without the flight's values")
	of := fs.String("of", "", "the format of -o: "+strings.Join(fuzz.Formats, ", ")+" (all writes one file for each, with the suffixes)")
	od := fs.String("od", "", "keep the request and answer of each match as a file in this directory (its name is shown with the match)")
	orSkip := fs.Bool("or", false, "write no -o file when there are no matches")
	controlFile := fs.String("control", "", "steer the run from this file: lines added to it are commands (rate N, pause, resume, stop, fc|fs|fw|fl|fr|ft VALUE, afc… to add, none to remove, show, savejson FILE, queueshow, queuedel N, queueskip)")
	debugLog := fs.String("debug-log", "", "write each failed request and its error to this file")
	colors := fs.Bool("c", false, "colour the status of each result in the text output")
	fs.String("config", "", "read these settings from an ffuf configuration file (default: ~/.config/ffuf/ffufrc, else ~/.ffufrc); flags override it")
	showVersion := fs.Bool("V", false, "print the version")
	fs.Bool("noninteractive", false, "accepted for ffuf's command lines: no effect (there is no console; see -control)")
	origArgs := args
	rcNote, cfgPath := "", ""
	if !describing {
		var err error
		if args, rcNote, cfgPath, err = withConfigFile(args); err != nil {
			return usageErr{err}
		}
	}
	if err := parse(fs, args); err != nil {
		return err
	}
	if *showVersion {
		fmt.Println("azhaq " + version)
		return nil
	}
	if *rawURL == "" && *reqFile == "" {
		return usagef("give the target with -u, with the keyword FUZZ where the words go (or a request with -request)")
	}
	if len(lists) == 0 && len(inputCmds) == 0 {
		return usagef("give a wordlist with -w FILE[:KEYWORD] (or a command with -input-cmd)")
	}
	md, err := fuzz.ParseMode(*mode)
	if err != nil {
		return usageErr{err}
	}
	if *reqProto != "http" && *reqProto != "https" {
		return usagef("-request-proto is http or https")
	}
	given := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { given[f.Name] = true })
	tmpl, err := fuzzTemplate(*method, *rawURL, *data, *reqFile, *reqProto, headers, cookies)
	if err != nil {
		return usageErr{err}
	}
	rawTmplURL := tmpl.URL
	if md == fuzz.Sniper {
		if len(lists)+len(inputCmds) != 1 {
			return usagef("sniper mode takes one wordlist (or one input command)")
		}
		marked, err := fuzz.HasSniperMarks(tmpl)
		if err != nil {
			return usageErr{err}
		}
		if !marked {
			return usagef("sniper mode wants places marked %s like this%s in the URL, headers or body", fuzz.SniperMark, fuzz.SniperMark)
		}
		if *recursion {
			return usagef("-recursion does not work with -mode sniper")
		}
		tmpl.URL = strings.ReplaceAll(tmpl.URL, fuzz.SniperMark, "")
	}
	u, err := url.Parse(tmpl.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return usagef("-u needs an http(s) URL, got %q", tmpl.URL)
	}
	if md == fuzz.Sniper {
		tmpl.URL = rawTmplURL
	}
	if *threads < 1 {
		return usagef("-t wants at least 1")
	}
	if *strategy != "default" && *strategy != "greedy" {
		return usagef("-recursion-strategy is default or greedy")
	}
	if *inputNum < 1 {
		return usagef("-input-num wants at least 1")
	}
	for _, v := range []struct{ name, val string }{{"-x", *proxy}, {"-replay-proxy", *replayProxy}} {
		if v.val == "" {
			continue
		}
		pu, err := url.Parse(v.val)
		if err != nil || pu.Host == "" || (pu.Scheme != "http" && pu.Scheme != "https" && pu.Scheme != "socks5" && pu.Scheme != "socks5h") {
			return usagef("%s needs an http, https or socks5 URL such as http://127.0.0.1:8080, got %q", v.name, v.val)
		}
	}
	dmin, dmax, err := parseDelay(*delay)
	if err != nil {
		return usageErr{err}
	}
	chains := map[string]fuzz.Chain{}
	for _, e := range encs {
		kw, chain, ok := strings.Cut(e, ":")
		if !ok {
			return usagef("-enc %q: want 'KEYWORD:encoder encoder' (e.g. FUZZ:urlencode)", e)
		}
		ch, err := fuzz.ParseChain(chain)
		if err != nil {
			return usagef("-enc %s: %v", kw, err)
		}
		chains[kw] = ch
	}
	extList := splitList(*exts)
	var all []fuzz.List
	for _, spec := range fuzz.SplitWordlists(lists) {
		path, kw := fuzz.ParseWordlist(spec)
		if md == fuzz.Sniper {
			path, kw = spec, "FUZZ"
			if p, k := fuzz.ParseWordlist(spec); k != "FUZZ" {
				return usagef("-w %s: sniper mode does not take a keyword (%s)", spec, p)
			}
		}
		l, err := fuzz.ReadList(path, kw, fuzz.ListOptions{Exts: extList, IgnoreComments: *ic, DirSearch: *dirsearch, Chain: chains[kw]})
		if err != nil {
			return usagef("-w %s: %v", spec, err)
		}
		// Two lists of one keyword (-w a.txt,b.txt) are one list, a then b:
		// as two they would be a product in which the second hides the first.
		if i := slices.IndexFunc(all, func(x fuzz.List) bool { return x.Keyword == kw && x.Gen == nil }); i >= 0 {
			all[i].Words = append(all[i].Words, l.Words...)
			continue
		}
		all = append(all, l)
	}
	cmdKeywords := map[string]bool{}
	for _, spec := range inputCmds {
		command, kw := splitInputCmd(spec)
		if md == fuzz.Sniper {
			kw = "FUZZ"
		}
		all = append(all, fuzz.CommandList(*inputShell, command, kw, *inputNum, chains[kw]))
		cmdKeywords[kw] = true
	}
	var kept []fuzz.List
	var keywords []string
	for _, l := range all {
		if md != fuzz.Sniper && !tmpl.Has(l.Keyword) {
			fmt.Fprintf(os.Stderr, "azhaq: the keyword %s is in no part of the request: its wordlist is not used\n", l.Keyword)
			continue
		}
		kept = append(kept, l)
		keywords = append(keywords, l.Keyword)
	}
	if len(kept) == 0 {
		return usagef("no wordlist keyword is in the request: put FUZZ in the URL, a header or the body")
	}
	for kw := range chains {
		if !slices.Contains(keywords, kw) {
			fmt.Fprintf(os.Stderr, "azhaq: -enc %s: no wordlist has that keyword\n", kw)
		}
	}
	if *recursion && !strings.HasSuffix(tmpl.URL, "FUZZ") {
		return usagef("with -recursion the URL (-u) must end with FUZZ")
	}

	set := fuzz.NewSet(keywords)
	set.PerHost = *ach
	set.MatcherAnd, set.FilterAnd = *mmode == "and", *fmode == "and"
	if (*mmode != "and" && *mmode != "or") || (*fmode != "and" && *fmode != "or") {
		return usagef("-mmode and -fmode take and or or")
	}
	if given["mc"] || !(given["ms"] || given["ml"] || given["mw"] || given["mr"] || given["mt"]) {
		if *mc == "" {
			*mc = "200-299,301,302,307,401,403,405,500"
		}
		if err := set.AddMatcher("status", *mc); err != nil {
			return usageErr{err}
		}
	}
	for _, o := range []struct {
		kind, val string
		match     bool
	}{
		{"size", *ms, true}, {"word", *mw, true}, {"line", *ml, true}, {"regexp", *mr, true}, {"time", *mt, true},
		{"status", *fc, false}, {"size", *fsz, false}, {"word", *fw, false}, {"line", *fl, false}, {"regexp", *fr, false}, {"time", *ft, false},
	} {
		if o.val == "" {
			continue
		}
		if o.match {
			err = set.AddMatcher(o.kind, o.val)
		} else {
			err = set.AddFilter(o.kind, o.val)
		}
		if err != nil {
			return usageErr{err}
		}
	}

	// As ffuf's help says, -acs, -acc and -ach imply -ac.
	calibrate := *ac || !given["ac"] && (given["acs"] || given["acc"] || given["ach"])
	var notes []string
	if rcNote != "" {
		notes = append(notes, rcNote)
	}
	calGroups, err := fuzz.CalibrationGroups(splitAll(acStrategies), acStrings)
	if err != nil {
		return usageErr{err}
	}

	// What -H typed, as against what a -request file brought.
	typedTmpl, err := fuzz.NewTemplate("", "http://x/", "", headers, nil)
	if err != nil {
		return usageErr{err}
	}
	rules, openHeaders, err := fuzzScope(tmpl, typedTmpl.Headers, keywords, *scopeSpec, *program, allow, deny)
	if err != nil {
		return err
	}

	// The output files, checked before the first request: a run that finds
	// it cannot write its report only at the end has wasted its requests.
	out, err := newFuzzOut(&c, *of, *od, *orSkip, given["of"])
	if err != nil {
		return err
	}

	fetch.Reset()
	fetch.SetRate(*rate)
	fetch.MaxRequests = *maxReq
	to := time.Duration(*timeout * float64(time.Second))
	sender, err := fuzz.NewSender(fuzz.HTTPOptions{Timeout: to, Threads: *threads, Follow: *follow, Allow: rules.Allows,
		Proxy: *proxy, ReplayProxy: *replayProxy, IgnoreBody: *ignoreBody, Raw: *raw, SNI: *sni, HTTP2: *http2,
		CertFile: *certFile, KeyFile: *keyFile, KeepRaw: *od != ""})
	if err != nil {
		return usageErr{err}
	}
	trips := fetch.OriginTrips
	anyErr := *se || *sa || *seAfter > 0
	if *se || *sa {
		trips = 2 * *threads
	}
	if *seAfter > 0 {
		trips = *seAfter
	}
	cfg := fuzz.Config{
		Template: tmpl, Lists: kept, Mode: md, Set: set, Threads: *threads, Sender: sender,
		Calibrate: calibrate, CalKeyword: *ack, CalGroups: calGroups, Recursion: *recursion, Depth: *depth, Strategy: *strategy,
		MaxTimeJob: time.Duration(*maxtimeJob * float64(time.Second)), DelayMin: dmin, DelayMax: dmax,
		StopOn403: *sf || *sa, StopOnAll: *sa, Allow: rules.Allows, OpenHeaders: openHeaders, OriginTrips: trips, TripOnAnyError: anyErr, Start: *start,
		Progress: new(fuzz.Progress),
	}
	cfg.Skip, cfg.SkipTotal = takeFuzzSkip(tmpl)
	if *replayProxy != "" {
		cfg.Replay = sender.(fuzz.Replayer)
	}
	if len(flights.pre)+len(flights.post) > 0 {
		if *preMode != "per-request" && *preMode != "per-thread" {
			return usagef("-preflight-mode is per-request or per-thread")
		}
		if *preError != "abort" && *preError != "ignore" {
			return usagef("-preflight-error is abort or ignore")
		}
		fl := &fuzz.Flights{Pre: flights.pre, Post: flights.post, PerThread: *preMode == "per-thread", Ignore: *preError == "ignore"}
		if err := fl.Load(tmpl, keywords); err != nil {
			return usagef("-preflight/-postflight: %v", err)
		}
		if cfg.Sender, err = fuzz.WithFlights(sender, fl, tmpl, keywords, rules.Allows); err != nil {
			return err
		}
	}

	w, err := newWriter(&c)
	if err != nil {
		return err
	}
	ctx, stop := stopContext()
	defer stop()
	ctx, cancelRun := context.WithCancelCause(ctx)
	defer cancelRun(nil)
	if *maxtime > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(*maxtime*float64(time.Second)))
		defer cancel()
	}

	var hitsMu sync.Mutex
	var hits []fuzz.Result
	look := fuzzLook{keywords: keywords, command: cmdKeywords, verbose: *verbose, colors: *colors && !c.json && !c.silent}
	var debug *debugLogger
	if *debugLog != "" {
		if debug, err = newDebugLog(*debugLog); err != nil {
			return err
		}
		defer debug.close()
		cfg.OnError = debug.request
	}
	cfg.OnResult = func(r fuzz.Result) {
		r = out.keep(r, &c)
		hitsMu.Lock()
		hits = append(hits, r)
		hitsMu.Unlock()
		switch {
		case c.json:
			w.obj(fuzz.StdoutJSON(r))
		case c.silent:
			w.line(look.inputs(r))
		case len(keywords) > 1 || *verbose || *od != "":
			w.line(look.multiline(r))
		default:
			w.line(look.normal(r))
		}
	}
	snapshot := func() fuzz.Report {
		hitsMu.Lock()
		defer hitsMu.Unlock()
		res := append([]fuzz.Result(nil), hits...)
		return out.report(res, keywords, os.Args, set, fuzzReportConfig(fuzzCfgInfo{
			args: os.Args, set: set, tmpl: tmpl, lists: lists, cmds: inputCmds, encs: encs, exts: extList, mode: md, threads: *threads, timeout: int(*timeout), rate: int64(*rate),
			delay: *delay, maxtime: int(*maxtime), maxtimeJob: int(*maxtimeJob), follow: *follow, ignoreBody: *ignoreBody, ic: *ic, dirsearch: *dirsearch,
			inputNum: *inputNum, inputShell: *inputShell, mmode: *mmode, fmode: *fmode, od: *od, o: out.file, of: out.format, orSkip: *orSkip, proxy: *proxy, replay: *replayProxy,
			raw: *raw, recursion: *recursion, depth: *depth, strategy: *strategy, reqFile: *reqFile, reqProto: *reqProto, sni: *sni, sa: *sa, sf: *sf, se: *se,
			verbose: *verbose, http2: *http2, cc: *certFile, ck: *keyFile, calibrate: calibrate, ack: *ack, ach: *ach, acs: acStrategies, acc: acStrings,
			json: c.json, silent: c.silent, colors: *colors, config: cfgPath, keywords: keywords,
		}))
	}
	var ctrl *fuzz.Control
	if *controlFile != "" {
		ctrl = fuzz.NewControl(fuzz.ControlEnv{
			Set: set, SetRate: fetch.SetRate,
			Save: func(path string) error { return fuzz.WriteReport(path, "json", snapshot()) },
			Show: func() string {
				hitsMu.Lock()
				defer hitsMu.Unlock()
				var b []string
				for _, h := range hits {
					b = append(b, look.normal(h))
				}
				return strings.Join(b, "\n")
			},
			Prune: func() {
				hitsMu.Lock()
				defer hitsMu.Unlock()
				kept := hits[:0]
				for _, h := range hits {
					if set.KeptBy(&fuzz.Response{Status: h.Status, Length: h.Length, Words: h.Words, Lines: h.Lines, Duration: h.Duration}) {
						kept = append(kept, h)
					}
				}
				hits = kept
			},
			Log: func(m string) {
				if !c.json && !c.silent {
					fmt.Fprintln(os.Stderr, "azhaq: "+m)
				}
			},
		})
		ctrl.Stop = func(why string) { cancelRun(errors.New(why)) }
		cfg.Control = ctrl
		go ctrl.Watch(ctx, *controlFile)
	}
	rep := newReport("fuzz")
	led, err := startLedger(*ledgerFlag, *killFile, c.db, c.db == "", rules, *sealTo)
	if err != nil {
		return err
	}
	defer led.close(rep)
	rep.what = "matches"
	t0 := time.Now()
	switch {
	case c.silent:
	case stderrIsTerminal():
		defer fuzzProgress(ctx, cfg.Progress, t0)()
	default:
		pc := progressCfg{JSON: c.json, Cap: fetch.MaxRequests, CapBy: "-max-requests", Timeout: time.Duration(*maxtime * float64(time.Second))}
		defer startProgress(ctx, pc, os.Stderr, func() progressSnap {
			return progressSnap{At: time.Since(t0), Sent: fetch.Sent(), Left: -1}
		})()
	}
	st := fuzz.Run(ctx, cfg)
	if err := w.close(); err != nil {
		return err
	}

	rep.Results = st.Matches
	rep.Requests = fetch.Sent()
	rep.Unreachable = st.Down
	if st.Errors > 0 {
		rep.Failed = append(rep.Failed, engine.Failure{Collector: "azhaq-fuzz", Error: "request failed", Retryable: true, Count: st.Errors})
	}
	if st.OutOfScope > 0 {
		rep.Skipped = append(rep.Skipped, engine.Skip{Target: fmt.Sprintf("%d inputs", st.OutOfScope), Reason: "their host is outside the scope"})
	}
	if len(st.Filters) > 0 {
		rep.Notes = append(rep.Notes, "auto-calibration filtered out answers with "+strings.Join(st.Filters, ", "))
	}
	rep.Notes = append(rep.Notes, notes...)
	rep.Notes = appendUnique(rep.Notes, st.Notes...)
	if len(st.Timeouts) > 0 {
		rep.Notes = append(rep.Notes, "requests timed out while -mt or -ft is on, so their time was not judged: "+strings.Join(st.Timeouts, "; ")+" (more may have)")
	}
	for _, j := range st.CutJobs {
		rep.Notes = append(rep.Notes, "-maxtime-job ended "+j+": the rest of it was not asked")
	}
	if *replayProxy != "" {
		n := fmt.Sprintf("%d matches were sent through the replay proxy %s (the proxy's own requests: not in the request count or the ledger)", st.Replayed, *replayProxy)
		if st.ReplayErr > 0 {
			n += fmt.Sprintf("; %d could not be sent", st.ReplayErr)
		}
		rep.Notes = append(rep.Notes, n)
		if st.ReplayErr > 0 {
			rep.Failed = append(rep.Failed, engine.Failure{Collector: "azhaq-fuzz", Error: "replay through " + *replayProxy + " failed", Retryable: true, Count: st.ReplayErr})
		}
	}
	if ran, failed, first := fuzz.FlightStats(cfg.Sender); ran > 0 || failed > 0 {
		rep.Notes = append(rep.Notes, fmt.Sprintf("%d preflight/postflight requests were sent (counted in the request total)", ran))
		if failed > 0 {
			rep.Failed = append(rep.Failed, engine.Failure{Collector: "azhaq-fuzz", Error: "preflight/postflight failed: " + first, Retryable: true, Count: failed})
		}
	}
	if ctrl != nil && len(ctrl.Applied) > 0 {
		rep.Notes = append(rep.Notes, fmt.Sprintf("-control: %d commands taken: %s", len(ctrl.Applied), strings.Join(ctrl.Applied, "; ")))
	}
	var killed *neterr.Killed
	cause := context.Cause(ctx)
	switch {
	case errors.As(fetch.Killed(), &killed):
		rep.Stopped = "the kill switch: kill file " + killed.Path + " exists"
	case st.Spent:
		rep.Stopped = fmt.Sprintf("the request budget of %d is spent", fetch.MaxRequests)
	case st.StoppedBy != "":
		rep.Stopped = st.StoppedBy
	case len(st.Down) > 0:
		rep.Notes = append(rep.Notes, fmt.Sprintf("%s stopped answering after %d requests in a row %s", strings.Join(st.Down, ", "), trips, map[bool]string{true: "failing", false: "without an answer"}[anyErr]))
	case ctx.Err() != nil && cause != nil && !errors.Is(cause, context.Canceled) && !errors.Is(cause, context.DeadlineExceeded):
		rep.Stopped = cause.Error()
	case ctx.Err() != nil && *maxtime > 0 && time.Since(rep.start) >= time.Duration(*maxtime*float64(time.Second)):
		rep.Stopped = fmt.Sprintf("-maxtime %gs reached", *maxtime)
	case ctx.Err() != nil:
		rep.Stopped = "interrupted"
	}
	if err := out.write(snapshot, rep); err != nil {
		rep.Failed = append(rep.Failed, engine.Failure{Collector: "azhaq-fuzz", Error: "the report " + out.file + " was not written: " + err.Error()})
	}
	if rep.Stopped != "" {
		// Go on from the first input not answered; azhaq resume -db runs it.
		next := append(withoutFlag(origArgs, "start"), "-start", strconv.Itoa(*start+st.Done))
		rep.Resume = "azhaq fuzz " + shellJoin(next)
		if st.Queued > 0 {
			rep.Notes = append(rep.Notes, fmt.Sprintf("%d directories found for -recursion were not swept: run fuzz on each (they are in the results)", st.Queued))
		}
		if c.db != "" {
			if err := setFuzzResume(c.db, next, fuzzAsked{Key: fuzzSkipKey(tmpl), Total: st.Total, Spans: st.Asked}); err != nil {
				return err
			}
		}
	} else if c.db != "" {
		if err := setFuzzResume(c.db, nil, fuzzAsked{}); err != nil {
			return err
		}
	}
	if c.db != "" {
		hitsMu.Lock()
		kept := append([]fuzz.Result(nil), hits...)
		hitsMu.Unlock()
		if err := keepFuzzHits(c.db, kept, tmpl.Method, os.Args); err != nil {
			return err
		}
		rep.DB = c.db
		rep.Next = append(rep.Next, "azhaq query -db "+c.db)
	}
	return rep.finish(c.json, c.silent)
}

// fuzzTemplate is the request: -request's file when there is one, with
// -u, -X, -d, -H and -b put over it, else what those say.
func fuzzTemplate(method, rawURL, data, reqFile, proto string, headers, cookies []string) (fuzz.Template, error) {
	if reqFile == "" {
		return fuzz.NewTemplate(method, rawURL, data, headers, cookies)
	}
	t, err := fuzz.ParseRequestFile(reqFile, proto)
	if err != nil {
		return t, fmt.Errorf("-request %s: %v", reqFile, err)
	}
	if rawURL != "" {
		t.URL = rawURL
	}
	if t.URL == "" {
		return t, fmt.Errorf("-request %s has no Host header: say where it goes with -u", reqFile)
	}
	if m := strings.TrimSpace(method); m != "" {
		t.Method = m
	}
	if data != "" {
		t.Data = data
	}
	over, err := fuzz.NewTemplate("", "http://x/", "", headers, cookies)
	if err != nil {
		return t, err
	}
	for _, h := range over.Headers {
		t = t.WithHeader(h.Name, h.Value)
	}
	return t, nil
}

// withConfigFile puts the settings of ffuf's configuration file in front of
// the command line's flags. note says which file was read.
func withConfigFile(args []string) (out []string, note, path string, err error) {
	path, explicit := rcPath(args)
	if path == "" {
		return args, "", "", nil
	}
	rc, ignored, err := rcArgs(path)
	if err != nil {
		if explicit {
			return nil, "", "", fmt.Errorf("-config: %v", err)
		}
		return nil, "", "", fmt.Errorf("%v (azhaq reads ffuf's ffufrc: fix it, or name another file with -config)", err)
	}
	note = "settings read from " + path
	if len(ignored) > 0 {
		note += "; not used by fuzz: " + strings.Join(ignored, ", ")
	}
	return append(rc, args...), note, path, nil
}

// parseDelay reads -p: seconds, or a range "0.1-2.0".
func parseDelay(s string) (min, max time.Duration, err error) {
	if s == "" {
		return 0, 0, nil
	}
	lo, hi, isRange := strings.Cut(s, "-")
	a, err1 := strconv.ParseFloat(lo, 64)
	if err1 != nil || a < 0 {
		return 0, 0, fmt.Errorf("-p needs a number of seconds (0.1) or a range (0.1-2.0), got %q", s)
	}
	min = time.Duration(a * float64(time.Second))
	if !isRange {
		return min, 0, nil
	}
	b, err2 := strconv.ParseFloat(hi, 64)
	if err2 != nil || b < a {
		return 0, 0, fmt.Errorf("-p needs a number of seconds (0.1) or a range (0.1-2.0), got %q", s)
	}
	return min, time.Duration(b * float64(time.Second)), nil
}

// splitInputCmd is "COMMAND[:KEYWORD]": the keyword is after the last colon
// when it looks like one.
func splitInputCmd(spec string) (command, keyword string) {
	if i := strings.LastIndex(spec, ":"); i > 0 && regexp.MustCompile(`^[A-Za-z0-9_]+$`).MatchString(spec[i+1:]) {
		return spec[:i], spec[i+1:]
	}
	return spec, "FUZZ"
}

func splitAll(vals []string) []string {
	var out []string
	for _, v := range vals {
		out = append(out, splitList(v)...)
	}
	return out
}

func appendUnique(dst []string, add ...string) []string {
	for _, a := range add {
		if !slices.Contains(dst, a) {
			dst = append(dst, a)
		}
	}
	return dst
}

// fuzzScope is the rules the run keeps to: -allow, -deny and a program's
// -scope, else the host of -u (when the keyword stands at the start of
// the host, its domain: FUZZ.example.com is example.com).
//
// A header that names a host (Host, X-Forwarded-Host, …) is held to them as
// the URL's host is, with one exception: with no -allow, -deny or -scope, a
// host that -H names (typed) joins the target, a literal one in the scope and
// one that holds the keyword (virtual hosts) open for every word: what the
// user typed is what they authorized. A host from a -request file is not
// typed: a literal one the rules leave out is refused before the run, one with
// the keyword is checked for each input, and its domain is the scope too.
func fuzzScope(t fuzz.Template, typed []fuzz.Header, keywords []string, spec, program string, allow, deny []string) (rules scope.Rules, open map[string]bool, err error) {
	allow, deny = append([]string(nil), allow...), append([]string(nil), deny...)
	if spec != "" {
		sc, err := loadScope(spec, program)
		if err != nil {
			return scope.Rules{}, nil, err
		}
		allow, deny = append(allow, sc.Allow...), append(deny, sc.Deny...)
	}
	noRule := len(allow) == 0 && len(deny) == 0 && spec == ""
	if len(allow) == 0 {
		u, _ := url.Parse(t.URL)
		hosts := []struct{ what, host string }{{"-u", u.Hostname()}}
		for _, h := range t.Headers {
			if !scope.NamesHost(h.Name) {
				continue
			}
			isTyped := slices.Contains(typed, h)
			for _, host := range scope.HeaderHosts(h.Value) {
				switch {
				case noRule && isTyped && holdsKeyword(host, keywords):
					if open == nil {
						open = map[string]bool{}
					}
					open[strings.ToLower(h.Name)] = true
				case noRule && isTyped:
					allow = append(allow, host)
				case holdsKeyword(host, keywords):
					hosts = append(hosts, struct{ what, host string }{"-H " + h.Name, host})
				}
			}
		}
		for _, hh := range hosts {
			host := hh.host
			for _, k := range keywords {
				if rest, ok := strings.CutPrefix(host, k+"."); ok {
					host = rest
				}
				if strings.Contains(host, k) {
					return scope.Rules{}, nil, usagef("the host in %s holds the keyword %s: say what may be touched with -allow DOMAIN or -scope", hh.what, k)
				}
			}
			allow = append(allow, host)
		}
	}
	rules = scope.Rules{Allow: allow, Deny: deny}
	if u, err := url.Parse(t.URL); err == nil && !strings.Contains(u.Hostname(), "FUZZ") && !rules.Allows(u.Hostname()) {
		return scope.Rules{}, nil, usagef("%s is outside the scope", u.Hostname())
	}
	// A literal host header, before anything is sent; the ones that hold a
	// keyword are held to the scope for each input (fuzz.InScope).
	lit := http.Header{}
	for _, h := range t.Headers {
		if scope.NamesHost(h.Name) && !hasKeyword(h.Name+h.Value, keywords) {
			lit.Add(h.Name, h.Value)
		}
	}
	if err := hostHeadersFrom("-H", lit, rules.Compile()); err != nil {
		return scope.Rules{}, nil, err
	}
	return rules, open, nil
}

// holdsKeyword says whether s holds a wordlist keyword.
func holdsKeyword(s string, keywords []string) bool {
	for _, k := range keywords {
		if strings.Contains(s, k) {
			return true
		}
	}
	return false
}

// hasKeyword says whether s holds a keyword or a sniper mark: where a word
// may go.
func hasKeyword(s string, keywords []string) bool {
	return strings.Contains(s, fuzz.SniperMark) || holdsKeyword(s, keywords)
}

// keepFuzzHits stores the hits in the workspace as ffuf's report, which
// ingest reads: a hit asked with GET is the URL's answer, with another
// method it says the route takes it.
func keepFuzzHits(path string, hits []fuzz.Result, method string, argv []string) error {
	rows := make([]map[string]any, 0, len(hits))
	for _, h := range hits {
		in := make(map[string]string, len(h.Input))
		for k, v := range h.Input {
			if k != "FFUFHASH" { // a name for the request, not an input
				in[k] = v
			}
		}
		rows = append(rows, map[string]any{
			"input": in, "position": h.Position, "status": h.Status, "length": h.Length, "words": h.Words, "lines": h.Lines,
			"content-type": h.ContentType, "redirectlocation": h.RedirectLocation, "url": h.URL, "duration": h.Duration, "host": h.Host,
		})
	}
	raw, err := json.Marshal(map[string]any{"commandline": strings.Join(argv, " "), "results": rows, "config": map[string]any{"method": method}})
	if err != nil {
		return err
	}
	facts, _, _, err := connector.ReadLines(raw)
	if err != nil {
		return err
	}
	st, err := store.Open(path)
	if err != nil {
		return err
	}
	defer st.Close()
	runs, err := st.Runs()
	if err != nil {
		return err
	}
	fresh := len(runs) == 0
	if fresh {
		if err := st.BeginRun(newRunID(), 0, 0); err != nil {
			return err
		}
		_ = st.SetRunArgs(append([]string{"fuzz"}, argv[min(2, len(argv)):]...))
	} else {
		st.UseRun(runs[len(runs)-1].ID)
	}
	eng := &engine.Engine{Store: st}
	hints, err := eng.Ingest(context.Background(), facts)
	if err != nil {
		return err
	}
	if fresh {
		_ = st.SaveSeeds(hints)
	}
	return nil
}

// fuzzResumeKey holds, in a workspace, the fuzz command that goes on from
// where a stopped one left off; azhaq resume runs it. fuzzAskedKey holds
// the exact inputs it already asked: they come back in any order, so a
// budget or a stop leaves holes that -start alone cannot say.
const (
	fuzzResumeKey = "fuzz:resume"
	fuzzAskedKey  = "fuzz:asked"
)

// fuzzAsked is the set of inputs a stopped run asked, with what it needs
// to be trusted: the request it was for and the inputs the run had.
type fuzzAsked struct {
	Key   string     `json:"key"`
	Total int        `json:"total"`
	Spans fuzz.Spans `json:"spans"`
}

// fuzzSkip is the asked set azhaq resume read from the workspace; the fuzz
// run it starts takes it (as storedList is taken).
var fuzzSkip *fuzzAsked

func fuzzSkipKey(t fuzz.Template) string { return t.Method + " " + t.URL + " " + t.Data }

// takeFuzzSkip hands the run the set azhaq resume read, when it is for the
// same request.
func takeFuzzSkip(t fuzz.Template) (fuzz.Spans, int) {
	a := fuzzSkip
	fuzzSkip = nil
	if a == nil || a.Key != fuzzSkipKey(t) {
		return nil, 0
	}
	return a.Spans, a.Total
}

func setFuzzResume(path string, args []string, asked fuzzAsked) error {
	st, err := store.Open(path)
	if err != nil {
		return err
	}
	defer st.Close()
	v, a := "", ""
	if args != nil {
		raw, _ := json.Marshal(args)
		v = string(raw)
		raw, _ = json.Marshal(asked)
		a = string(raw)
	}
	if err := st.SetMeta(fuzzAskedKey, a); err != nil {
		return err
	}
	return st.SetMeta(fuzzResumeKey, v)
}

// withoutFlag is args without -name and its value.
func withoutFlag(args []string, name string) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		k, _, eq := strings.Cut(strings.TrimLeft(args[i], "-"), "=")
		if strings.HasPrefix(args[i], "-") && k == name {
			if !eq {
				i++
			}
			continue
		}
		out = append(out, args[i])
	}
	return out
}

// shellJoin quotes args for a shell where they need it.
func shellJoin(args []string) string {
	out := make([]string, len(args))
	for i, a := range args {
		if a == "" || strings.ContainsAny(a, " \t'\"$`\\|&;<>(){}*?[]#~!") {
			a = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
		}
		out[i] = a
	}
	return strings.Join(out, " ")
}
