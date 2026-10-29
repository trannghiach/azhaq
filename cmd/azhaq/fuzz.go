package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/signal"
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
	fs.BoolVar(&c.silent, "s", false, "ffuf's name for -silent")
	rawURL := fs.String("u", "", "target URL; the keyword (FUZZ) may stand anywhere in it, in the host too")
	var lists, headers, cookies, allow, deny stringsFlag
	fs.Var(&lists, "w", "wordlist `FILE[:KEYWORD]` (- for stdin; repeatable; the keyword is FUZZ without one)")
	mode := fs.String("mode", "clusterbomb", "how several wordlists combine: clusterbomb (every combination) or pitchfork (line by line)")
	method := fs.String("X", "", "HTTP method (default GET, POST with -d); the keyword may stand in it")
	data := fs.String("d", "", "request body; the keyword may stand in it")
	fs.Var(&headers, "H", "header \"Name: value\"; the keyword may stand in name and value, Host included (repeatable)")
	fs.Var(&cookies, "b", "cookie data \"NAME=VALUE; NAME2=VALUE2\"")
	mc := fs.String("mc", "", "match these statuses, comma-separated values and ranges, or all (default 200-299,301,302,307,401,403,405,500, unless another matcher is given)")
	ms := fs.String("ms", "", "match these response sizes (values and ranges)")
	mw := fs.String("mw", "", "match these word counts (values and ranges)")
	ml := fs.String("ml", "", "match these line counts (values and ranges)")
	mr := fs.String("mr", "", "match answers (headers and body) with this regexp; the keyword stands for its input")
	fc := fs.String("fc", "", "filter out these statuses")
	fsz := fs.String("fs", "", "filter out these response sizes")
	fw := fs.String("fw", "", "filter out these word counts")
	fl := fs.String("fl", "", "filter out these line counts")
	fr := fs.String("fr", "", "filter out answers matching this regexp")
	mmode := fs.String("mmode", "or", "matchers: an answer must match any (or) or all (and) of them")
	fmode := fs.String("fmode", "or", "filters: an answer is dropped by any (or) or by all (and) of them")
	ac := fs.Bool("ac", true, "calibrate the filters on paths that cannot exist (-ac=false turns it off; ffuf's default is off)")
	ack := fs.String("ack", "FUZZ", "the keyword calibration replaces")
	recursion := fs.Bool("recursion", false, "descend into directories found (the URL must end with FUZZ)")
	depth := fs.Int("recursion-depth", 0, "levels of recursion (0: no limit)")
	start := fs.Int("start", 0, "skip the first N inputs: where a stopped run left off (its summary gives the command)")
	exts := fs.String("e", "", "extensions added to each FUZZ word, comma-separated: .php,.bak")
	ic := fs.Bool("ic", false, "ignore comments in wordlists")
	threads := fs.Int("t", 40, "requests in flight")
	rate := fs.Float64("rate", 0, "requests per second, over all (0: no pace)")
	ledgerFlag := fs.String("ledger", "", ledgerHelp)
	killFile := fs.String("kill-file", "", killFileHelp)
	timeout := fs.Float64("timeout", 10, "each request's timeout, in `seconds`")
	maxtime := fs.Float64("maxtime", 0, "stop after this many `seconds` and say so (0: no limit)")
	follow := fs.Bool("r", false, "follow redirects")
	verbose := fs.Bool("v", false, "print the full URL and redirect location with each result")
	maxReq := fs.Int64("max-requests", 0, "requests this run may send (0: no cap)")
	scopeSpec := fs.String("scope", "", "a program's scope: a file or hackerone, bugcrowd, intigriti, yeswehack")
	program := fs.String("program", "", "the program to take from a -scope list")
	fs.Var(&allow, "allow", "a domain, host or address range the run may touch (repeatable); default: the host of -u")
	fs.Var(&deny, "deny", "a domain, host or address range the run must not touch (repeatable)")
	fs.Bool("c", false, "accepted for ffuf's command lines: no effect")
	fs.Bool("noninteractive", false, "accepted for ffuf's command lines: no effect")
	if err := parse(fs, args); err != nil {
		return err
	}
	if *rawURL == "" {
		return usagef("give the target with -u, with the keyword FUZZ where the words go")
	}
	if len(lists) == 0 {
		return usagef("give a wordlist with -w FILE[:KEYWORD]")
	}
	md, err := fuzz.ParseMode(*mode)
	if err != nil {
		return usageErr{err}
	}
	tmpl, err := fuzz.NewTemplate(*method, *rawURL, *data, headers, cookies)
	if err != nil {
		return usageErr{err}
	}
	u, err := url.Parse(tmpl.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return usagef("-u needs an http(s) URL, got %q", tmpl.URL)
	}
	extList := splitList(*exts)
	var all []fuzz.List
	for _, spec := range lists {
		path, kw := fuzz.ParseWordlist(spec)
		l, err := fuzz.ReadList(path, kw, extList, *ic)
		if err != nil {
			return usagef("-w %s: %v", spec, err)
		}
		all = append(all, l)
	}
	var kept []fuzz.List
	var keywords []string
	for _, l := range all {
		if !tmpl.Has(l.Keyword) {
			fmt.Fprintf(os.Stderr, "azhaq: the keyword %s is in no part of the request: its wordlist is not used\n", l.Keyword)
			continue
		}
		kept = append(kept, l)
		keywords = append(keywords, l.Keyword)
	}
	if len(kept) == 0 {
		return usagef("no wordlist keyword is in the request: put FUZZ in the URL, a header or the body")
	}
	if *recursion && !strings.HasSuffix(tmpl.URL, "FUZZ") {
		return usagef("with -recursion the URL (-u) must end with FUZZ")
	}
	if *threads < 1 {
		return usagef("-t wants at least 1")
	}

	set := fuzz.NewSet(keywords)
	set.MatcherAnd, set.FilterAnd = *mmode == "and", *fmode == "and"
	if (*mmode != "and" && *mmode != "or") || (*fmode != "and" && *fmode != "or") {
		return usagef("-mmode and -fmode take and or or")
	}
	given := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { given[f.Name] = true })
	if given["mc"] || !(given["ms"] || given["ml"] || given["mw"] || given["mr"]) {
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
		{"size", *ms, true}, {"word", *mw, true}, {"line", *ml, true}, {"regexp", *mr, true},
		{"status", *fc, false}, {"size", *fsz, false}, {"word", *fw, false}, {"line", *fl, false}, {"regexp", *fr, false},
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

	rules, err := fuzzScope(tmpl, keywords, *scopeSpec, *program, allow, deny)
	if err != nil {
		return err
	}

	fetch.Reset()
	fetch.SetRate(*rate)
	fetch.MaxRequests = *maxReq
	to := time.Duration(*timeout * float64(time.Second))
	cfg := fuzz.Config{
		Template: tmpl, Lists: kept, Mode: md, Set: set, Threads: *threads,
		Sender:    fuzz.NewSender(fuzz.HTTPOptions{Timeout: to, Threads: *threads, Follow: *follow, Allow: rules.Allows}),
		Calibrate: *ac, CalKeyword: *ack, Recursion: *recursion, Depth: *depth,
		Allow: rules.Allows, OriginTrips: fetch.OriginTrips, Start: *start,
	}

	w, err := newWriter(&c)
	if err != nil {
		return err
	}
	var hitsMu sync.Mutex
	var hits []fuzz.Result
	cfg.OnResult = func(r fuzz.Result) {
		hitsMu.Lock()
		hits = append(hits, r)
		hitsMu.Unlock()
		switch {
		case c.json:
			w.obj(fuzzJSON(r))
		case c.silent:
			w.line(fuzzInputs(r, keywords))
		case len(keywords) > 1 || *verbose:
			w.line(fuzzMultiline(r, keywords, *verbose))
		default:
			w.line(fmt.Sprintf("%-23s [Status: %d, Size: %d, Words: %d, Lines: %d, Duration: %dms]", fuzzInputs(r, keywords), r.Status, r.Length, r.Words, r.Lines, r.Duration/int64(time.Millisecond)))
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if *maxtime > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(*maxtime*float64(time.Second)))
		defer cancel()
	}
	rep := newReport("fuzz")
	led, err := startLedger(*ledgerFlag, *killFile, c.db, c.db == "", rules)
	if err != nil {
		return err
	}
	defer led.close(rep)
	rep.what = "matches"
	if !c.json && !c.silent {
		t0 := time.Now()
		tick := time.NewTicker(30 * time.Second)
		defer tick.Stop()
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case <-tick.C:
					fmt.Fprintf(os.Stderr, "azhaq: working, %s: %d requests sent\n", time.Since(t0).Round(time.Second), fetch.Sent())
				}
			}
		}()
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
	rep.Notes = append(rep.Notes, st.Notes...)
	var killed *neterr.Killed
	switch {
	case errors.As(fetch.Killed(), &killed):
		rep.Stopped = "the kill switch: kill file " + killed.Path + " exists"
	case st.Spent:
		rep.Stopped = fmt.Sprintf("the request budget of %d is spent", fetch.MaxRequests)
	case len(st.Down) > 0:
		rep.Notes = append(rep.Notes, fmt.Sprintf("%s stopped answering after %d requests in a row without an answer", strings.Join(st.Down, ", "), fetch.OriginTrips))
	case ctx.Err() != nil && *maxtime > 0 && time.Since(rep.start) >= time.Duration(*maxtime*float64(time.Second)):
		rep.Stopped = fmt.Sprintf("-maxtime %gs reached", *maxtime)
	case ctx.Err() != nil:
		rep.Stopped = "interrupted"
	}
	if rep.Stopped != "" {
		// Go on from the first input not answered; azhaq resume -db runs it.
		next := append(withoutFlag(args, "start"), "-start", strconv.Itoa(*start+st.Done))
		rep.Resume = "azhaq fuzz " + shellJoin(next)
		if st.Queued > 0 {
			rep.Notes = append(rep.Notes, fmt.Sprintf("%d directories found for -recursion were not swept: run fuzz on each (they are in the results)", st.Queued))
		}
		if c.db != "" {
			if err := setFuzzResume(c.db, next); err != nil {
				return err
			}
		}
	} else if c.db != "" {
		if err := setFuzzResume(c.db, nil); err != nil {
			return err
		}
	}
	if c.db != "" {
		if err := keepFuzzHits(c.db, hits, tmpl.Method, os.Args); err != nil {
			return err
		}
		rep.DB = c.db
		rep.Next = append(rep.Next, "azhaq query -db "+c.db)
	}
	return rep.finish(c.json, c.silent)
}

// fuzzScope is the rules the run keeps to: -allow, -deny and a program's
// -scope, else the host of -u (when the keyword stands at the start of
// the host, its domain: FUZZ.example.com is example.com).
func fuzzScope(t fuzz.Template, keywords []string, spec, program string, allow, deny []string) (scope.Rules, error) {
	allow, deny = append([]string(nil), allow...), append([]string(nil), deny...)
	if spec != "" {
		sc, err := loadScope(spec, program)
		if err != nil {
			return scope.Rules{}, err
		}
		allow, deny = append(allow, sc.Allow...), append(deny, sc.Deny...)
	}
	if len(allow) == 0 {
		u, _ := url.Parse(t.URL)
		host := u.Hostname()
		for _, k := range keywords {
			if rest, ok := strings.CutPrefix(host, k+"."); ok {
				host = rest
			}
			if strings.Contains(host, k) {
				return scope.Rules{}, usagef("the host in -u holds the keyword %s: say what may be touched with -allow DOMAIN or -scope", k)
			}
		}
		allow = []string{host}
	}
	rules := scope.Rules{Allow: allow, Deny: deny}
	if u, err := url.Parse(t.URL); err == nil && !strings.Contains(u.Hostname(), "FUZZ") && !rules.Allows(u.Hostname()) {
		return scope.Rules{}, usagef("%s is outside the scope", u.Hostname())
	}
	return rules, nil
}

// fuzzInputs is ffuf's one-line form of a result's inputs: the word, or
// "KEY : word" for each keyword when there are several.
func fuzzInputs(r fuzz.Result, keywords []string) string {
	if len(keywords) == 1 {
		return r.Input[keywords[0]]
	}
	var b strings.Builder
	for _, k := range keywords {
		fmt.Fprintf(&b, "%s : %s ", k, r.Input[k])
	}
	return b.String()
}

func fuzzMultiline(r fuzz.Result, keywords []string, verbose bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "[Status: %d, Size: %d, Words: %d, Lines: %d, Duration: %dms]\n", r.Status, r.Length, r.Words, r.Lines, r.Duration/int64(time.Millisecond))
	if verbose {
		fmt.Fprintf(&b, "| URL | %s\n", r.URL)
		if r.RedirectLocation != "" {
			fmt.Fprintf(&b, "| --> | %s\n", r.RedirectLocation)
		}
	}
	for _, k := range keywords {
		fmt.Fprintf(&b, "    * %s: %s\n", k, r.Input[k])
	}
	return b.String()
}

// fuzzJSON is a result with ffuf's field names; its inputs are base64, as
// ffuf prints them.
func fuzzJSON(r fuzz.Result) map[string]any {
	in := make(map[string]string, len(r.Input))
	for k, v := range r.Input {
		in[k] = base64.StdEncoding.EncodeToString([]byte(v))
	}
	return map[string]any{
		"input": in, "position": r.Position, "status": r.Status, "length": r.Length, "words": r.Words, "lines": r.Lines,
		"content-type": r.ContentType, "redirectlocation": r.RedirectLocation, "url": r.URL, "duration": r.Duration, "host": r.Host,
	}
}

// keepFuzzHits stores the hits in the workspace as ffuf's report, which
// ingest reads: a hit asked with GET is the URL's answer, with another
// method it says the route takes it.
func keepFuzzHits(path string, hits []fuzz.Result, method string, argv []string) error {
	rows := make([]map[string]any, 0, len(hits))
	for _, h := range hits {
		rows = append(rows, map[string]any{
			"input": h.Input, "position": h.Position, "status": h.Status, "length": h.Length, "words": h.Words, "lines": h.Lines,
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
// where a stopped one left off; azhaq resume runs it.
const fuzzResumeKey = "fuzz:resume"

func setFuzzResume(path string, args []string) error {
	st, err := store.Open(path)
	if err != nil {
		return err
	}
	defer st.Close()
	v := ""
	if args != nil {
		raw, _ := json.Marshal(args)
		v = string(raw)
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
