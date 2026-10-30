package main

import (
	"crypto/md5"
	"fmt"
	"net/textproto"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/trannghiach/azhaq/internal/fuzz"
)

// fuzzOut is what fuzz writes besides stdout: the report of -o and -of, and
// the files of -od.
type fuzzOut struct {
	file, format string // the report; empty file: none
	dir          string // -od
	skipEmpty    bool
	failed       atomic.Int64 // -od files that could not be written
	warned       sync.Once
}

// newFuzzOut reads -o, -of, -od and -or. A report name ending .txt, with no
// -of, keeps what -o did before: the text of stdout. The format of any other
// name is -of's, else the suffix's (.csv, .html, .md, .ejson, .ecsv), else json
// as in ffuf.
func newFuzzOut(c *common, of, od string, skipEmpty, ofGiven bool) (*fuzzOut, error) {
	o := &fuzzOut{dir: od, skipEmpty: skipEmpty}
	if c.out == "" {
		if ofGiven {
			fmt.Fprintln(os.Stderr, "azhaq: -of has no effect without -o")
		}
	} else {
		if st, err := os.Stat(c.out); err == nil && st.IsDir() {
			return nil, usagef("-o %s is a directory: -o names the file the report is written to", c.out)
		}
		switch {
		case ofGiven:
			if !contains(fuzz.Formats, of) {
				return nil, usagef("-of %q: one of %s", of, strings.Join(fuzz.Formats, ", "))
			}
			o.format = of
		case strings.EqualFold(filepath.Ext(c.out), ".txt"):
			// the text of stdout, written by newWriter
		default:
			o.format = formatOfName(c.out)
		}
		if o.format != "" {
			o.file = c.out
			c.out = ""
			// the place must take a file, found out now and not after the run
			dir := filepath.Dir(o.file)
			f, err := os.CreateTemp(dir, ".azhaq-fuzz-")
			if err != nil {
				return nil, usagef("-o %s: %v", o.file, err)
			}
			f.Close()
			os.Remove(f.Name())
		}
	}
	if od != "" {
		if err := os.MkdirAll(od, 0o750); err != nil {
			return nil, usagef("-od %s: %v", od, err)
		}
	}
	return o, nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func formatOfName(name string) string {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".csv":
		return "csv"
	case ".ecsv":
		return "ecsv"
	case ".html", ".htm":
		return "html"
	case ".md":
		return "md"
	case ".ejson":
		return "ejson"
	}
	return "json"
}

// keep writes the request and answer of a match to -od and names the file in
// the result, as ffuf does: the file is named by the hash of its text.
func (o *fuzzOut) keep(r fuzz.Result, c *common) fuzz.Result {
	if o.dir == "" {
		return r
	}
	text := fmt.Sprintf("%s\n---- ↑ Request ---- Response ↓ ----\n\n%s", r.RawRequest, r.RawResponse)
	name := fmt.Sprintf("%x", md5.Sum([]byte(text)))
	if err := os.WriteFile(filepath.Join(o.dir, name), []byte(text), 0o640); err != nil {
		o.failed.Add(1)
		o.warned.Do(func() { fmt.Fprintf(os.Stderr, "azhaq: -od: %v\n", err) })
		return r
	}
	r.ResultFile = name
	r.RawRequest, r.RawResponse = "", ""
	return r
}

// report is the report of results so far: in the order they were asked
// (position, a job at a time), whatever order the answers came in.
func (o *fuzzOut) report(res []fuzz.Result, keywords []string, argv []string, set *fuzz.Set, cfg fuzz.ReportConfig) fuzz.Report {
	sort.SliceStable(res, func(i, j int) bool {
		if res[i].Job != res[j].Job {
			return res[i].Job < res[j].Job
		}
		return res[i].Position < res[j].Position
	})
	cfg.Matchers = set.Describe(cfg.AutoCalibration)
	return fuzz.Report{CommandLine: strings.Join(argv, " "), Config: cfg, Keywords: keywords, Results: res}
}

// write writes the report when there is one to write. A failure comes back
// for the summary to say.
func (o *fuzzOut) write(snapshot func() fuzz.Report, rep *report) error {
	if n := o.failed.Load(); n > 0 {
		rep.Notes = append(rep.Notes, fmt.Sprintf("-od: %d matches could not be written to %s", n, o.dir))
	}
	if o.file == "" {
		return nil
	}
	r := snapshot()
	if o.skipEmpty && len(r.Results) == 0 {
		rep.Notes = append(rep.Notes, "no matches and -or: "+o.file+" was not written")
		return nil
	}
	return fuzz.WriteReport(o.file, o.format, r)
}

type fuzzLook struct {
	keywords []string
	command  map[string]bool // keywords whose words come from a command: the position is shown
	verbose  bool
	colors   bool
}

// inputs is ffuf's one-line form of a result's inputs: the word, or
// "KEY : word" for each keyword when there are several.
func (l fuzzLook) inputs(r fuzz.Result) string {
	val := func(k string) string {
		if l.command[k] {
			return strconv.Itoa(r.Position)
		}
		return r.Input[k]
	}
	if len(l.keywords) == 1 {
		return val(l.keywords[0])
	}
	var b strings.Builder
	for _, k := range l.keywords {
		fmt.Fprintf(&b, "%s : %s ", k, val(k))
	}
	return b.String()
}

func (l fuzzLook) colorOf(status int) (on, off string) {
	if !l.colors {
		return "", ""
	}
	c := "\x1b[0m"
	switch {
	case status >= 200 && status < 300:
		c = "\x1b[32m"
	case status >= 300 && status < 400:
		c = "\x1b[34m"
	case status >= 400 && status < 500:
		c = "\x1b[33m"
	case status >= 500 && status < 600:
		c = "\x1b[31m"
	}
	return c, "\x1b[0m"
}

func (l fuzzLook) normal(r fuzz.Result) string {
	on, off := l.colorOf(r.Status)
	return fmt.Sprintf("%s%-23s [Status: %d, Size: %d, Words: %d, Lines: %d, Duration: %dms]%s", on, l.inputs(r), r.Status, r.Length, r.Words, r.Lines, r.Duration/int64(time.Millisecond), off)
}

func (l fuzzLook) multiline(r fuzz.Result) string {
	on, off := l.colorOf(r.Status)
	var b strings.Builder
	fmt.Fprintf(&b, "%s[Status: %d, Size: %d, Words: %d, Lines: %d, Duration: %dms]%s\n", on, r.Status, r.Length, r.Words, r.Lines, r.Duration/int64(time.Millisecond), off)
	if l.verbose {
		fmt.Fprintf(&b, "| URL | %s\n", r.URL)
		if r.RedirectLocation != "" {
			fmt.Fprintf(&b, "| --> | %s\n", r.RedirectLocation)
		}
	}
	if r.ResultFile != "" {
		fmt.Fprintf(&b, "| RES | %s\n", r.ResultFile)
	}
	for _, k := range l.keywords {
		v := r.Input[k]
		if l.command[k] {
			v = strconv.Itoa(r.Position)
		}
		fmt.Fprintf(&b, "    * %s: %s\n", k, v)
	}
	return b.String()
}

// debugLogger is -debug-log.
type debugLogger struct {
	mu sync.Mutex
	f  *os.File
}

func newDebugLog(path string) (*debugLogger, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, usagef("-debug-log %s: %v", path, err)
	}
	return &debugLogger{f: f}, nil
}

func (d *debugLogger) request(req *fuzz.Request, err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	fmt.Fprintf(d.f, "%s request failed: %s %s: %v\n", time.Now().Format(time.RFC3339), req.Method, req.URL, err)
}

func (d *debugLogger) close() { d.f.Close() }

func stderrIsTerminal() bool {
	st, err := os.Stderr.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

// fuzzProgress prints one status line to stderr a second, over itself, until
// the function returned is called. It is for a person at a terminal: the
// caller does not start it otherwise.
func fuzzProgress(ctx interface{ Done() <-chan struct{} }, p *fuzz.Progress, t0 time.Time) func() {
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		t := time.NewTicker(time.Second)
		defer t.Stop()
		lastN, lastT := p.Done.Load(), time.Now()
		for {
			select {
			case <-ctx.Done():
				return
			case <-stop:
				return
			case now := <-t.C:
				n := p.Done.Load()
				rate := float64(n-lastN) / now.Sub(lastT).Seconds()
				if rate < 0 {
					rate = 0 // a new job started counting again
				}
				lastN, lastT = n, now
				el := now.Sub(t0).Round(time.Second)
				jobs := p.Job.Load() + p.Queued.Load()
				fmt.Fprintf(os.Stderr, "\r\x1b[2K:: Progress: [%d/%d] :: Job [%d/%d] :: %.0f req/sec :: Duration: [%d:%02d:%02d] :: Errors: %d ::",
					p.Done.Load(), p.Total.Load(), p.Job.Load(), jobs, rate, int(el.Hours()), int(el.Minutes())%60, int(el.Seconds())%60, p.Errors.Load())
			}
		}
	}()
	return func() {
		close(stop)
		<-done
		fmt.Fprint(os.Stderr, "\r\x1b[2K")
	}
}

// fuzzCfgInfo is what a JSON report's config is made of.
type fuzzCfgInfo struct {
	args                                        []string
	set                                         *fuzz.Set
	tmpl                                        fuzz.Template
	lists, cmds, encs, exts, acs, acc, keywords []string
	mode                                        fuzz.Mode
	threads, timeout, maxtime, maxtimeJob       int
	rate                                        int64
	inputNum, depth                             int
	delay, inputShell, mmode, fmode, od, o, of  string
	proxy, replay, strategy, reqFile, reqProto  string
	sni, cc, ck, ack, config                    string
	follow, ignoreBody, ic, dirsearch, orSkip   bool
	raw, recursion, sa, sf, se, verbose, http2  bool
	calibrate, ach, json, silent, colors        bool
}

// fuzzReportConfig is the config object of a JSON report, with ffuf's names.
func fuzzReportConfig(i fuzzCfgInfo) fuzz.ReportConfig {
	headers := map[string]string{}
	for _, h := range i.tmpl.Headers {
		name := h.Name
		keyed := false
		for _, k := range i.keywords {
			if strings.Contains(name, k) {
				keyed = true
			}
		}
		if !keyed {
			name = textproto.CanonicalMIMEHeaderKey(name)
		}
		headers[name] = h.Value
	}
	var providers []fuzz.ReportProvider
	enc := map[string]string{}
	for _, e := range i.encs {
		if k, v, ok := strings.Cut(e, ":"); ok {
			enc[k] = v
		}
	}
	tmplMark := ""
	if i.mode == fuzz.Sniper {
		tmplMark = fuzz.SniperMark
	}
	var wordlists []string
	for _, w := range i.lists {
		path, kw := fuzz.ParseWordlist(w)
		if abs, err := filepath.Abs(path); err == nil && path != "-" {
			path = abs
		}
		wordlists = append(wordlists, path+":"+kw)
		providers = append(providers, fuzz.ReportProvider{Name: "wordlist", Keyword: kw, Value: path, Encoders: enc[kw], Template: map[bool]string{true: tmplMark}[kw == "FUZZ"]})
	}
	for _, c := range i.cmds {
		cmd, kw := splitInputCmd(c)
		providers = append(providers, fuzz.ReportProvider{Name: "command", Keyword: kw, Value: cmd, Encoders: enc[kw], Template: map[bool]string{true: tmplMark}[kw == "FUZZ"]})
	}
	strategies := i.acs
	if len(strategies) == 0 {
		strategies = []string{"basic"}
	}
	delay := "0.00"
	if i.delay != "" {
		lo, hi, isRange := strings.Cut(i.delay, "-")
		a, _ := strconv.ParseFloat(lo, 64)
		b := 0.0
		if isRange {
			b, _ = strconv.ParseFloat(hi, 64)
		}
		if a == b {
			delay = fmt.Sprintf("%.2f", a)
		} else {
			delay = fmt.Sprintf("%.2f-%.2f", a, b)
		}
	}
	return fuzz.ReportConfig{
		AutoCalibration: i.calibrate, AutoCalibrationKeyword: i.ack, AutoCalibrationPerHost: i.ach, AutoCalibrationStrategies: strategies,
		AutoCalibrationStrings: nonNil(i.acc), Colors: i.colors, CommandLine: strings.Join(i.args, " "), ConfigFile: i.config, Data: i.tmpl.Data,
		Delay: fuzz.ReportDelay{Value: delay}, DirSearchCompat: i.dirsearch, Encoders: nonNil(i.encs), Extensions: nonNil(i.exts), FilterMode: i.fmode,
		FollowRedirects: i.follow, Headers: headers, IgnoreBody: i.ignoreBody, IgnoreWordlistComments: i.ic, InputMode: string(i.mode), InputNum: i.inputNum,
		InputProviders: providers, InputShell: i.inputShell, Json: i.json, MatcherMode: i.mmode, MaxTime: i.maxtime, MaxTimeJob: i.maxtimeJob,
		Method: i.tmpl.Method, Noninteractive: false, OutputDirectory: i.od, OutputFile: i.o, OutputFormat: i.of, OutputSkipEmptyFile: i.orSkip,
		ProxyURL: i.proxy, Quiet: i.silent, Rate: i.rate, Raw: i.raw, Recursion: i.recursion, RecursionDepth: i.depth, RecursionStrategy: i.strategy,
		ReplayProxyURL: i.replay, RequestFile: i.reqFile, RequestProto: i.reqProto, Scrapers: "all", SNI: i.sni, StopOn403: i.sf || i.sa, StopOnAll: i.sa,
		StopOnErrors: i.se || i.sa, Threads: i.threads, Timeout: i.timeout, Url: i.tmpl.URL, Verbose: i.verbose, Wordlists: nonNil(wordlists), Http2: i.http2,
		ClientCert: i.cc, ClientKey: i.ck,
	}
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// flightFlags collects -preflight and -postflight files and the -…-var
// flags after each, in the order given: a variable belongs to the file before it.
type flightFlags struct{ pre, post []fuzz.FlightStep }

type flightFile struct {
	f    *flightFlags
	post bool
}

func (v flightFile) String() string { return "" }
func (v flightFile) Set(s string) error {
	if s == "" {
		return fmt.Errorf("a request file is needed")
	}
	if v.post {
		v.f.post = append(v.f.post, fuzz.FlightStep{File: s})
	} else {
		v.f.pre = append(v.f.pre, fuzz.FlightStep{File: s})
	}
	return nil
}

type flightVar struct {
	f          *flightFlags
	post, auto bool
}

func (v flightVar) String() string { return "" }
func (v flightVar) Set(s string) error {
	steps, file := &v.f.pre, "-preflight"
	if v.post {
		steps, file = &v.f.post, "-postflight"
	}
	if len(*steps) == 0 {
		return fmt.Errorf("%q comes before any %s: a variable is read from the file given before it", s, file)
	}
	fv, err := fuzz.ParseFlightVar(s, v.auto)
	if err != nil {
		return err
	}
	last := &(*steps)[len(*steps)-1]
	last.Vars = append(last.Vars, fv)
	return nil
}
