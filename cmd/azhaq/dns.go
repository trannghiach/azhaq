package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"iter"
	"net"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"github.com/trannghiach/azhaq/engine"
	"github.com/trannghiach/azhaq/internal/collectors/asncol"
	"github.com/trannghiach/azhaq/internal/dnsr"
	"github.com/trannghiach/azhaq/internal/fingerprint"
	"github.com/trannghiach/azhaq/internal/normalize"
	"github.com/trannghiach/azhaq/internal/takeover"
	"github.com/trannghiach/azhaq/scope"
	"github.com/trannghiach/azhaq/store"
	"github.com/trannghiach/azhaq/types"
)

// dnsx's output templates and its way of reading -rcode and -rtf are the
// model of the parts below that say so; dnsx is MIT licensed
// (github.com/projectdiscovery/dnsx).

// dnsKind is a record type a flag asks for.
type dnsKind struct {
	flag  string
	qtype uint16
}

// dnsKinds in the order dnsx asks them.
var dnsKinds = []dnsKind{
	{"a", dns.TypeA}, {"aaaa", dns.TypeAAAA}, {"cname", dns.TypeCNAME}, {"ptr", dns.TypePTR},
	{"soa", dns.TypeSOA}, {"any", dns.TypeANY}, {"txt", dns.TypeTXT}, {"srv", dns.TypeSRV},
	{"mx", dns.TypeMX}, {"ns", dns.TypeNS}, {"caa", dns.TypeCAA},
}

// dnsPrint is the order dnsx prints the records of a name in.
var dnsPrint = []string{"a", "aaaa", "cname", "ptr", "mx", "ns", "soa", "any", "txt", "srv", "caa"}

var rcodeNames = map[string]int{
	"noerror": 0, "formerr": 1, "servfail": 2, "nxdomain": 3, "notimp": 4, "refused": 5, "yxdomain": 6,
	"yxrrset": 7, "nxrrset": 8, "notauth": 9, "notzone": 10, "badsig": 16, "badvers": 16, "badkey": 17,
	"badtime": 18, "badmode": 19, "badname": 20, "badalg": 21, "badtrunc": 22, "badcookie": 23,
}

// dnsConf is what cmdDNS was asked.
type dnsConf struct {
	types      []uint16        // asked, in dnsx's order
	selected   map[string]bool // by flag name
	explicit   bool            // a type flag was given
	all        bool            // -all
	axfr       bool
	resp, ro   bool
	json       bool
	omitRaw    bool
	raw        bool
	template   string
	rcodes     map[int]bool
	rtf        []string
	verbose    bool
	cdn, asn   bool
	hosts      bool
	trace      bool
	traceMax   int
	noWildcard bool
	wd         string
	ptrHosts   bool // IPs are looked up (-ptr or -all)
	stream     bool
	start      int
	rules      scope.Rules
	scoped     bool
}

// cmdDNS is dnsx: resolve names, any record type, as they come.
func cmdDNS(args []string) error {
	fs := newFlags("dns")
	var c common
	c.register(fs)
	fs.Lookup("db").Usage = "keep the names that have records in this database for query, show and export (default: nothing is kept)"
	alias := func(name, as, usage string) { fs.Var(fs.Lookup(name).Value, as, usage) }
	alias("json", "j", "same as -json")
	var names, hostsArg, wordsArg stringsFlag
	fs.Var(&names, "d", "name to resolve, or with -w the domain to guess under (repeatable; a file, a comma list or - for stdin; FUZZ in it takes the words)")
	fs.Var(&hostsArg, "l", "names: a file, a comma list or - for stdin; a CIDR range or an AS number (AS13335) is expanded to addresses (repeatable)")
	fs.Var(&wordsArg, "w", "words to guess: a file, a comma list or -; with -d DOMAIN resolves WORD.DOMAIN for each (wildcard answers left out)")
	var kinds [11]*bool
	for i, k := range dnsKinds {
		usage := "ask " + strings.ToUpper(k.flag) + " records and print the names that have one"
		if k.flag == "a" {
			usage += " (the default)"
		}
		kinds[i] = fs.Bool(k.flag, false, usage)
	}
	axfr := fs.Bool("axfr", false, "ask each name server of the name, and the -resolvers you gave, for the whole zone over TCP (active; the name servers must be in scope: -allow, -scope)")
	all := fs.Bool("all", false, "ask every type but AXFR and print the records (-resp); an address gets only PTR")
	alias("all", "recon", "same as -all")
	var exclude stringsFlag
	fs.Var(&exclude, "e", "types not to ask with -all, comma-separated (repeatable)")
	resp := fs.Bool("resp", false, "print each record as: NAME [TYPE] [VALUE]")
	alias("resp", "re", "same as -resp")
	ro := fs.Bool("resp-only", false, "print the values of the records only")
	alias("resp-only", "ro", "same as -resp-only")
	rcode := fs.String("rcode", "", "print NAME [RCODE] for names whose answer has one of these codes, comma-separated (noerror, nxdomain, servfail, refused, or a number); a name with no records is shown")
	alias("rcode", "rc", "same as -rcode")
	rtf := fs.String("response-type-filter", "", "print names with no record of these types, comma-separated (a, cname, ...)")
	alias("response-type-filter", "rtf", "same as -response-type-filter")
	cdn := fs.Bool("cdn", false, "name the CDN, WAF or cloud in front of each name (cdn, cdn-name, cdn-type)")
	asn := fs.Bool("asn", false, "add the autonomous system of each address (as-number, as-name, as-country, as-range), asked of Team Cymru's DNS service")
	threads := fs.Int("t", 100, "names resolved at once")
	alias("t", "threads", "same as -t")
	rl := fs.Int("rl", 0, "names asked per second, over all resolvers; each name's types are asked together (0: no limit); see also -dns-rate")
	alias("rl", "rate-limit", "same as -rl")
	retry := fs.Int("retry", 0, "attempts per question on other resolvers (default 3; 1 asks once)")
	timeout := fs.Duration("timeout", 3*time.Second, "wait this long for each DNS answer (not the run's time, as in azhaq run: see -maxtime)")
	maxtime := fs.Float64("maxtime", 0, "stop the run after this many seconds (0: no limit); the summary says where to go on")
	start := fs.Int("start", 0, "skip this many names at the start of the input, in order after de-duplication")
	omitRaw := fs.Bool("omit-raw", false, "leave the records as text (all) out of -json")
	alias("omit-raw", "or", "same as -omit-raw")
	tmpl := fs.String("output-template", "", "print each name as this template; {{host}}, {{a}}, {{ip}} and the other -json fields, lists joined by commas")
	alias("output-template", "ot", "same as -output-template")
	raw := fs.Bool("raw", false, "print the raw DNS answers, as dig does")
	alias("raw", "debug", "same as -raw")
	stats := fs.Bool("stats", false, "print progress on stderr every 5 seconds")
	verbose := fs.Bool("v", false, "print each name that got no records, with its status, on stderr")
	fs.Bool("nc", false, "accepted: output has no colour")
	fs.Bool("duc", false, "accepted: azhaq checks for no updates")
	fs.Bool("disable-update-check", false, "same as -duc")
	hc := fs.Bool("health-check", false, "ask each resolver a known name, print how it answered and how long it took, and exit")
	alias("health-check", "hc", "same as -health-check")
	hosts := fs.Bool("hostsfile", false, "answer from the system hosts file before asking resolvers")
	alias("hostsfile", "hf", "same as -hostsfile")
	trace := fs.Bool("trace", false, "follow the delegations from the root servers to the answer (the roots are asked, so use it on names you may ask)")
	traceMax := fs.Int("trace-max-recursion", 32, "most steps of -trace")
	stream := fs.Bool("stream", false, "names come from stdin as they are written and are not de-duplicated")
	fs.Int("wildcard-threshold", 0, "accepted and not needed: each parent zone is probed for a wildcard")
	alias("wildcard-threshold", "wt", "same as -wildcard-threshold")
	fs.Bool("auto-wildcard", false, "accepted: wildcard answers are always left out, unless -no-wildcard")
	alias("auto-wildcard", "aw", "same as -auto-wildcard")
	wd := fs.String("wildcard-domain", "", "also probe this zone for a wildcard (a zone the registrable domain does not reach, such as corp.internal)")
	alias("wildcard-domain", "wd", "same as -wildcard-domain")
	noWild := fs.Bool("no-wildcard", false, "print names even when they only resolve because their zone has a wildcard")
	proxyURL := fs.String("proxy", "", "send DNS through this socks5 proxy (socks5://host:port), over TCP")
	inherit(fs, "resolvers", "dns-rate", "scope", "program", "allow", "deny")
	alias("resolvers", "r", "same as -resolvers")
	if err := parse(fs, args); err != nil {
		return err
	}

	cf := &dnsConf{selected: map[string]bool{}, axfr: *axfr, all: *all, resp: *resp, ro: *ro, json: c.json, omitRaw: *omitRaw,
		raw: *raw, template: *tmpl, cdn: *cdn, asn: *asn, hosts: *hosts, trace: *trace, traceMax: *traceMax,
		noWildcard: *noWild, verbose: *verbose, wd: normalize.Hostname(strings.TrimPrefix(*wd, "*.")), stream: *stream, start: *start}
	if cf.json && cf.template != "" || cf.raw && cf.template != "" {
		return usagef("-output-template cannot go with -json or -raw")
	}
	if cf.resp && cf.ro {
		return usagef("-resp and -resp-only cannot be used together")
	}
	if fs.Lookup("retry").Value.String() != "0" && *retry < 1 {
		return usagef("-retry must be at least 1")
	}
	if *threads < 1 {
		return usagef("-t must be at least 1")
	}
	if *rl < 0 {
		return usagef("-rl cannot be negative")
	}
	if *start < 0 {
		return usagef("-start cannot be negative")
	}
	if cf.stream && (cf.start > 0 || len(names)+len(hostsArg)+len(wordsArg) > 0) {
		return usagef("-stream reads stdin: it does not go with -d, -l, -w or -start")
	}
	for i, k := range dnsKinds {
		if *kinds[i] {
			cf.selected[k.flag] = true
			cf.explicit = true
		}
	}
	if *axfr {
		cf.axfr = true
	}
	if cf.all {
		for _, k := range dnsKinds {
			cf.selected[k.flag] = true
		}
		cf.resp = true
		delete(cf.selected, "any") // ANY is not a list of all: the types are asked one by one
		for _, e := range exclude {
			for _, x := range splitList(e) {
				delete(cf.selected, strings.ToLower(x))
			}
		}
		cf.explicit = true
	}
	for _, k := range dnsKinds {
		if cf.selected[k.flag] {
			cf.types = append(cf.types, k.qtype)
		}
	}
	if len(cf.types) == 0 {
		cf.types = []uint16{dns.TypeA}
		cf.selected["a"] = true
		if cf.wd != "" {
			cf.explicit = false
		}
	}
	cf.ptrHosts = cf.selected["ptr"]
	if *rcode != "" {
		cf.rcodes = map[int]bool{}
		for _, r := range splitList(*rcode) {
			n, ok := rcodeNames[strings.ToLower(r)]
			if !ok {
				v, err := strconv.Atoi(r)
				if err != nil {
					return usagef("-rcode: %q is not a response code", r)
				}
				n = v
			}
			cf.rcodes[n] = true
		}
	}
	for _, r := range splitList(*rtf) {
		cf.rtf = append(cf.rtf, strings.ToLower(r))
	}
	if cf.traceMax < 1 {
		return usagef("-trace-max-recursion must be at least 1")
	}
	if *proxyURL != "" {
		if err := dnsr.ProxyError(*proxyURL); err != nil {
			return usagef("-proxy: %v", err)
		}
	}
	// Scope: -allow, -deny and a program's -scope hold the names the run
	// asks about and the servers it connects to. With none, a zone
	// transfer is held to the names given.
	allow, deny := flagStrings(fs, "allow"), flagStrings(fs, "deny")
	if spec := fs.Lookup("scope").Value.String(); spec != "" {
		sc, err := loadScope(spec, fs.Lookup("program").Value.String())
		if err != nil {
			return err
		}
		allow, deny = append(allow, sc.Allow...), append(deny, sc.Deny...)
	}
	cf.rules = scope.Rules{Allow: allow, Deny: deny}
	cf.scoped = !cf.rules.Empty()

	resolvers, err := dnsr.ParseResolvers(fs.Lookup("resolvers").Value.String())
	if err != nil {
		return usagef("-resolvers: %v", err)
	}
	rate, _ := strconv.ParseFloat(fs.Lookup("dns-rate").Value.String(), 64)
	attempts := *retry
	if attempts == 0 {
		attempts = 3
	}
	pool := dnsr.New(dnsr.Options{Resolvers: resolvers, PerSecond: rate, Burst: int(rate), Timeout: *timeout, Attempts: attempts, Proxy: *proxyURL})
	if *hc {
		return healthCheck(pool, c.json)
	}

	in, err := newDNSInput(cf, names, hostsArg, wordsArg)
	if err != nil {
		return err
	}
	w, err := newWriterMode(&c, true)
	if err != nil {
		return err
	}
	rep := newReport("dns")
	rep.what = "names"
	r := &dnsRun{cf: cf, pool: pool, wild: dnsr.NewWildcards(pool), w: w, rep: rep, resolvers: resolvers, in: in, failed: map[string]*engine.Failure{}}
	r.keepOn = c.db != ""
	if cf.hosts {
		r.hostsFile = dnsr.SystemHosts()
	}
	if *rl > 0 {
		r.limiter = &perSecond{n: *rl}
	}
	if *tmpl != "" {
		r.tmpl = parseTemplate(*tmpl)
	}
	ctx, stop := stopContext()
	defer stop()
	if *maxtime > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(*maxtime*float64(time.Second)))
		defer cancel()
	}
	if *stats {
		go r.progress(ctx)
	}
	r.run(ctx, *threads)
	if err := w.close(); err != nil {
		return err
	}
	if !cf.stream && in.asked.Load() == 0 && len(in.counts) == 0 && len(in.notes) == 0 && len(in.failed) == 0 {
		return usagef("no names to resolve: give -d NAME, -l FILE or names on stdin")
	}
	if !cf.stream && in.asked.Load() == 0 && len(in.notes) == 0 && len(in.failed) == 0 && ctx.Err() == nil && in.allOutsideScope() {
		return in.outsideScope() // nothing was asked: every name was outside the scope
	}
	r.summarize(ctx, args, *maxtime)
	if c.db != "" {
		if err := r.keep(c.db); err != nil {
			return err
		}
		rep.DB = c.db
		rep.Next = append(rep.Next, "azhaq query -db "+c.db)
	}
	return rep.finish(c.json, c.silent)
}

func flagStrings(fs *flag.FlagSet, name string) []string {
	if sf, ok := fs.Lookup(name).Value.(*stringsFlag); ok {
		return append([]string(nil), *sf...)
	}
	return nil
}

// ----- input -----

// dnsInput is the names to resolve, one at a time. It is built before
// anything is asked, so a mistake in a flag is a usage error.
type dnsInput struct {
	cf      *dnsConf
	stdin   bool // names come from stdin: no resume
	sources []func() (iter.Seq[string], error)
	domains []string // brute force: the domains, and
	words   []string // the words
	brute   bool

	mu      sync.Mutex
	notes   []string
	skipped []engine.Skip
	counts  map[string]int
	failed  []engine.Failure
	asked   atomic.Int64
}

var asnInput = regexp.MustCompile(`(?i)^as\d+$`)

func newDNSInput(cf *dnsConf, names, lists, words []string) (*dnsInput, error) {
	in := &dnsInput{cf: cf, counts: map[string]int{}}
	stdinUsed := false
	open := func(arg string) (func() (iter.Seq[string], error), error) {
		arg = strings.TrimSpace(arg)
		switch {
		case arg == "-":
			if stdinUsed {
				return nil, usagef("stdin can be given to one of -d, -l and -w")
			}
			stdinUsed, in.stdin = true, true
			return func() (iter.Seq[string], error) { return lineSeq(os.Stdin), nil }, nil
		case fileExists(arg):
			return func() (iter.Seq[string], error) {
				f, err := os.Open(arg)
				if err != nil {
					return nil, err
				}
				return lineSeq(f), nil
			}, nil
		default:
			items := splitList(arg)
			return func() (iter.Seq[string], error) {
				return func(yield func(string) bool) {
					for _, x := range items {
						if !yield(x) {
							return
						}
					}
				}, nil
			}, nil
		}
	}
	if len(words) > 0 {
		in.brute = true
		if len(lists) > 0 {
			return nil, usagef("-l cannot be used with -w: give the domains with -d")
		}
		if len(names) == 0 {
			return nil, usagef("-w needs -d DOMAIN: the domain the words are guessed under")
		}
		for _, d := range names {
			src, err := open(d)
			if err != nil {
				return nil, err
			}
			seq, err := src()
			if err != nil {
				return nil, err
			}
			for x := range seq {
				h, ok := hostOf(x)
				if !ok || strings.ContainsAny(h, "/ ") {
					return nil, usagef("-d wants a domain such as example.com with -w, got %q", x)
				}
				if net.ParseIP(h) != nil {
					return nil, usagef("-d wants a domain with -w, got the address %s", x)
				}
				in.domains = append(in.domains, h)
			}
		}
		for _, wl := range words {
			src, err := open(wl)
			if err != nil {
				return nil, err
			}
			seq, err := src()
			if err != nil {
				return nil, err
			}
			for x := range seq {
				in.words = append(in.words, strings.ToLower(strings.Trim(strings.TrimSpace(x), ".")))
			}
		}
		if len(in.domains) == 0 || len(in.words) == 0 {
			return nil, usagef("-w and -d each need at least one entry")
		}
		if cf.axfr || cf.ptrHosts {
			return nil, usagef("-axfr and -ptr go with names, not with -w")
		}
		return in, nil
	}
	for _, v := range append(append([]string(nil), names...), lists...) {
		src, err := open(v)
		if err != nil {
			return nil, err
		}
		in.sources = append(in.sources, src)
	}
	if len(in.sources) == 0 {
		if !stdinPiped() {
			return nil, usagef("give -d NAME, -l FILE or names on stdin")
		}
		src, _ := open("-")
		in.sources = append(in.sources, src)
	}
	return in, nil
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}

// lineSeq is the non-blank lines of r that are not # comments, read as
// they come and closed at the end.
func lineSeq(r io.Reader) iter.Seq[string] {
	return func(yield func(string) bool) {
		if c, ok := r.(io.Closer); ok && r != os.Stdin {
			defer c.Close()
		}
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			if l := strings.TrimSpace(sc.Text()); l != "" && !strings.HasPrefix(l, "#") {
				if !yield(l) {
					return
				}
			}
		}
	}
}

// hostOf reads a name from an input line: a URL gives its host, host:port
// its host.
func hostOf(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil || u.Hostname() == "" {
			return "", false
		}
		return normalize.Hostname(u.Hostname()), true
	}
	if h, _, err := net.SplitHostPort(raw); err == nil {
		raw = h
	}
	return normalize.Hostname(strings.Trim(raw, "[]")), true
}

type dnsJob struct {
	idx  int
	name string
}

// feed sends the names to resolve, de-duplicated (except for -stream),
// until they run out or ctx ends. It closes the channel.
func (in *dnsInput) feed(ctx context.Context, out chan<- dnsJob) {
	defer close(out)
	seen := map[string]struct{}{}
	idx := 0
	send := func(name string) bool {
		if !in.cf.stream {
			if _, dup := seen[name]; dup {
				return true
			}
			seen[name] = struct{}{}
		}
		if in.cf.scoped && !in.cf.rules.Allows(name) {
			in.left("outside the scope", name)
			return true
		}
		idx++
		if idx <= in.cf.start {
			return true
		}
		select {
		case out <- dnsJob{idx: idx, name: name}:
			in.asked.Add(1)
			return true
		case <-ctx.Done():
			return false
		}
	}
	if in.brute {
		in.feedBrute(send)
		return
	}
	for _, src := range in.sources {
		seq, err := src()
		if err != nil {
			in.fail("reading the input", err.Error(), "")
			continue
		}
		for line := range seq {
			if !in.line(ctx, line, send) {
				return
			}
		}
	}
}

// line sends the names one input line stands for.
func (in *dnsInput) line(ctx context.Context, line string, send func(string) bool) bool {
	if strings.Contains(line, ",") && !strings.Contains(line, "://") {
		for _, x := range splitList(line) { // a list on one line
			if !in.line(ctx, x, send) {
				return false
			}
		}
		return true
	}
	if pf, err := netip.ParsePrefix(line); err == nil {
		return in.expand(ctx, pf, send)
	}
	if asnInput.MatchString(line) {
		prefixes, _, err := asncol.NewASN(nil).Prefixes(ctx, line)
		if err != nil {
			in.fail("looking up "+strings.ToUpper(line), err.Error(), line)
			return true
		}
		if len(prefixes) == 0 {
			in.note(fmt.Sprintf("%s announces no prefixes", strings.ToUpper(line)))
		}
		for _, p := range prefixes {
			if pf, err := netip.ParsePrefix(p); err == nil && !in.expand(ctx, pf, send) {
				return false
			}
		}
		return true
	}
	h, ok := hostOf(line)
	if !ok {
		in.left("not a name", line)
		return true
	}
	if ip, err := netip.ParseAddr(h); err == nil {
		return in.address(ip, send)
	}
	if _, ok := dns.IsDomainName(dns.Fqdn(h)); !ok || strings.ContainsAny(h, " \t") || strings.Contains(h, "..") {
		in.left("not a valid DNS name", line)
		return true
	}
	return send(h)
}

// address sends an address when it is to be looked up (-ptr).
func (in *dnsInput) address(ip netip.Addr, send func(string) bool) bool {
	if !in.cf.ptrHosts {
		in.left("an address, and no -ptr to ask for its name", ip.String())
		return true
	}
	return send(ip.String())
}

// expand sends the addresses of a prefix. One of more than 2^32 is refused:
// it would not finish.
func (in *dnsInput) expand(ctx context.Context, pf netip.Prefix, send func(string) bool) bool {
	pf = pf.Masked()
	if pf.Addr().BitLen()-pf.Bits() > 32 {
		in.note(fmt.Sprintf("%s holds more than 4 billion addresses: left out", pf))
		return true
	}
	if !in.cf.ptrHosts {
		in.left("addresses of a range, and no -ptr to ask for their names", pf.String())
		return true
	}
	for a := pf.Addr(); pf.Contains(a); a = a.Next() {
		if !send(a.String()) {
			return false
		}
		if ctx.Err() != nil {
			return false
		}
		if !a.Next().IsValid() {
			break
		}
	}
	return true
}

// feedBrute sends WORD.DOMAIN for every word and domain (or the domain
// with FUZZ replaced); words that are not DNS labels are counted.
func (in *dnsInput) feedBrute(send func(string) bool) {
	for _, d := range in.domains {
		for _, w := range in.words {
			if w == "" {
				continue
			}
			name := w + "." + d
			if strings.Contains(d, "FUZZ") || strings.Contains(d, "fuzz") {
				name = strings.NewReplacer("FUZZ", w, "fuzz", w).Replace(d)
			}
			if _, ok := dns.IsDomainName(dns.Fqdn(name)); !ok || strings.ContainsAny(name, " \t/") || strings.Contains(name, "..") || len(name) > 253 {
				in.left("words that make no DNS name", w)
				continue
			}
			if !send(name) {
				return
			}
		}
	}
}

// left counts an input not asked about, and keeps the first few.
func (in *dnsInput) left(why, what string) {
	in.mu.Lock()
	defer in.mu.Unlock()
	in.counts[why]++
	if in.counts[why] <= 3 {
		in.skipped = append(in.skipped, engine.Skip{Target: what, Reason: why})
	}
}

// allOutsideScope: every input left out was left out for the scope.
func (in *dnsInput) allOutsideScope() bool {
	in.mu.Lock()
	defer in.mu.Unlock()
	return len(in.counts) == 1 && in.counts["outside the scope"] > 0
}

// outsideScope is the usage error for names that are all outside the scope.
func (in *dnsInput) outsideScope() error {
	in.mu.Lock()
	defer in.mu.Unlock()
	var eg []string
	for _, sk := range in.skipped {
		eg = append(eg, sk.Target)
	}
	n := in.counts["outside the scope"]
	list := strings.Join(eg, ", ")
	if n > len(eg) {
		list += fmt.Sprintf(" and %d more", n-len(eg))
	}
	return usagef("every target is outside the scope (%d left out): %s; check -allow, -deny and -scope", n, list)
}

func (in *dnsInput) note(s string) {
	in.mu.Lock()
	defer in.mu.Unlock()
	in.notes = append(in.notes, s)
}

func (in *dnsInput) fail(what, err, target string) {
	in.mu.Lock()
	defer in.mu.Unlock()
	f := engine.Failure{Collector: "azhaq-dns", Error: what + ": " + err, Retryable: true, Count: 1}
	if target != "" {
		f.Targets = []string{target}
	}
	in.failed = append(in.failed, f)
}

// ----- the run -----

type dnsRun struct {
	cf        *dnsConf
	pool      *dnsr.Pool
	wild      *dnsr.Wildcards
	w         *writer
	rep       *report
	in        *dnsInput
	resolvers []string
	hostsFile *dnsr.Hosts
	limiter   *perSecond
	tmpl      tmplParts

	mu         sync.Mutex
	failed     map[string]*engine.Failure
	takeovers  []takeoverRow
	kept       []dnsKept
	watermark  int
	finished   map[int]bool
	counts     struct{ done, resolved, wildcard, failed, noAnswer, broken, otherCode atomic.Int64 }
	lastRows   atomic.Int64
	notes      []string
	axfrNotes  []string
	cut        atomic.Bool
	keepOn     bool // -db: keep the graph
	reservedN  int
	reservedEg []string
	start      time.Time
}

// dnsKept is what -db keeps of a name.
type dnsKept struct {
	host string
	p    map[string]any
}

func (r *dnsRun) run(ctx context.Context, threads int) {
	r.start = time.Now()
	jobs := make(chan dnsJob, threads*2)
	r.finished = map[int]bool{}
	r.watermark = r.cf.start
	go r.in.feed(ctx, jobs)
	var wg sync.WaitGroup
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				if ctx.Err() != nil {
					continue // drain: what is not asked is counted by the watermark
				}
				if r.limiter != nil {
					if r.limiter.wait(ctx) != nil {
						r.cut.Store(true) // the rate leaves no time for this name
						continue
					}
				}
				if r.one(ctx, j.name) {
					r.finish(j.idx)
				}
			}
		}()
	}
	wg.Wait()
}

// finish marks name number idx asked; watermark is the length of the
// asked prefix of the input, where a run is taken up again.
func (r *dnsRun) finish(idx int) {
	r.counts.done.Add(1)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.finished[idx] = true
	for r.finished[r.watermark+1] {
		delete(r.finished, r.watermark+1)
		r.watermark++
	}
}

func (r *dnsRun) progress(ctx context.Context) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			d := time.Since(r.start).Seconds()
			done := r.counts.done.Load()
			fmt.Fprintf(os.Stderr, "azhaq dns: %s | names asked %d (%d read) | %.0f names/s | %d rows | %d failed\n",
				time.Since(r.start).Round(time.Second), done, r.in.asked.Load(), float64(done)/max(d, 0.001), r.w.count(), r.counts.failed.Load())
		}
	}
}

// one asks about a name and prints what it gets. It says whether the name
// was asked: a name cut off by the end of the run is not.
func (r *dnsRun) one(ctx context.Context, name string) bool {
	cf := r.cf
	types := cf.types
	isIP := net.ParseIP(name) != nil
	if isIP {
		types = []uint16{dns.TypePTR} // an address has a reverse name; nothing else is asked of it
	} else if cf.all {
		var t []uint16
		for _, q := range types {
			if q != dns.TypePTR {
				t = append(t, q)
			}
		}
		types = t
	}
	if len(types) == 0 {
		return true
	}
	if r.pool.Reserved(name) {
		return r.reserved(ctx, name)
	}
	lctx := ctx
	if r.in.brute {
		lctx = dnsr.Bulk(ctx)
	}
	begin := time.Now()
	d := r.pool.Lookup(lctx, name, dnsr.LookupOptions{Types: types, Raw: cf.raw, Hosts: r.hostsFile})
	qt := time.Since(begin).Round(time.Millisecond).String()
	if ctx.Err() != nil {
		return false
	}
	for _, f := range d.Failures {
		if strings.Contains(f.Err.Error(), "would exceed context deadline") {
			r.cut.Store(true) // -dns-rate leaves no time for this name
			return false
		}
	}
	r.failures(name, d)
	if !d.Answered() {
		r.counts.failed.Add(1)
		r.keepRow(name, d, nil)
		return true
	}
	// -rcode: only names whose answer has one of the codes.
	if len(cf.rcodes) > 0 && !d.HostsFile && !cf.rcodes[d.StatusCodeRaw] {
		r.counts.otherCode.Add(1)
		return true
	}
	if len(d.A)+len(d.AAAA)+len(d.CNAME) > 0 && !cf.noWildcard && !isIP && r.wildcard(ctx, name, d) {
		r.counts.wildcard.Add(1)
		if !d.Any() {
			return true
		}
	}
	if cf.axfr && !isIP {
		r.transfer(ctx, name, d)
	}
	if cf.trace && !isIP {
		d.TraceData = r.pool.Trace(ctx, name, types[0], cf.traceMax)
	}
	row := &dnsRow{Data: d, QueryTime: qt}
	if cf.cdn {
		row.cdn(d)
	}
	if cf.asn {
		row.ASN = r.asnOf(ctx, d, name)
	}
	if cf.omitRaw {
		d.AllRecords = nil
	}
	row.Takeover = r.takeover(ctx, name, d)
	r.keepRow(name, d, row)
	selected := r.hasSelected(d)
	switch {
	case selected:
		r.counts.resolved.Add(1)
	case len(d.Failures) == 0:
		r.counts.noAnswer.Add(1)
		if cf.verbose {
			fmt.Fprintf(os.Stderr, "azhaq dns: %s: %s, no %s records\n", name, d.StatusCode, strings.Join(selectedNames(cf), "/"))
		}
	}
	r.output(name, d, row, selected)
	return true
}

// reserved resolves a name the resolvers are not asked about (localhost,
// *.test, a single label) through the system, and prints it if it has an
// address and A or AAAA was asked.
func (r *dnsRun) reserved(ctx context.Context, name string) bool {
	a, aaaa := r.pool.System(ctx, name)
	if ctx.Err() != nil {
		return false
	}
	r.mu.Lock()
	r.reservedN++
	if len(r.reservedEg) < 3 {
		r.reservedEg = append(r.reservedEg, name)
	}
	r.mu.Unlock()
	if len(a)+len(aaaa) == 0 {
		r.counts.noAnswer.Add(1)
		return true
	}
	d := &dnsr.Data{Host: name, A: a, AAAA: aaaa, StatusCode: "NOERROR", Timestamp: time.Now(), HostsFile: true}
	r.counts.resolved.Add(1)
	r.output(name, d, &dnsRow{Data: d}, r.hasSelected(d))
	return true
}

// wildcard says whether the answer is what a wildcard in a parent zone
// gives; the records of other types are kept.
func (r *dnsRun) wildcard(ctx context.Context, name string, d *dnsr.Data) bool {
	a := dnsr.Answer{Name: name, A: d.A, AAAA: d.AAAA, CNAME: d.CNAME}
	apexes := []string{normalize.RegistrableDomain(name)}
	if r.cf.wd != "" && (name == r.cf.wd || strings.HasSuffix(name, "."+r.cf.wd)) {
		apexes = append(apexes, r.cf.wd)
	}
	for _, apex := range apexes {
		if apex != "" && name != apex && r.wild.Match(ctx, name, apex, a) {
			d.A, d.AAAA, d.CNAME = nil, nil, nil
			return true
		}
	}
	return false
}

// failures records the questions that got no answer.
func (r *dnsRun) failures(name string, d *dnsr.Data) {
	for _, f := range d.Failures {
		// A SERVFAIL or REFUSED asked for with -rcode is a result.
		if d.Answered() && r.cf.rcodes[d.StatusCodeRaw] && (d.StatusCodeRaw == dns.RcodeServerFailure || d.StatusCodeRaw == dns.RcodeRefused) {
			continue
		}
		if dnsr.IsBroken(f.Err) {
			// Every resolver said SERVFAIL: the name's own DNS is broken. The
			// row says so (status_code SERVFAIL); it is counted, not a failure.
			r.counts.broken.Add(1)
			continue
		}
		why := shortDNSError(fmt.Sprintf("asking %s: %v", f.Type, f.Err))
		r.mu.Lock()
		e := r.failed[why]
		if e == nil {
			e = &engine.Failure{Collector: "azhaq-dns", Error: why, Retryable: true}
			r.failed[why] = e
		}
		e.Count++
		if len(e.Targets) < 100 {
			e.Targets = append(e.Targets, name)
		}
		r.mu.Unlock()
	}
}

// shortDNSError drops the address of a resolver and the numbers from an
// error, so the same failure is one line.
func shortDNSError(s string) string {
	s = regexp.MustCompile(`\b\d{1,3}(\.\d{1,3}){3}(:\d+)?\b`).ReplaceAllString(s, "a resolver")
	s = regexp.MustCompile(`\[[0-9a-f:]+\](:\d+)?`).ReplaceAllString(s, "a resolver")
	return s
}

// takeover notes a name whose CNAME points at what no longer exists.
func (r *dnsRun) takeover(ctx context.Context, host string, d *dnsr.Data) *takeover.Finding {
	if !r.cf.selected["a"] || len(d.CNAME) == 0 {
		return nil
	}
	if rc, ok := d.Rcode(dns.TypeA); !ok || rc != dns.RcodeNameError {
		return nil
	}
	target := d.CNAME[len(d.CNAME)-1]
	registered := true
	if takeover.Service(target) == "" && !normalize.SameSite(host, target) {
		if dom := takeover.Domain(target); dom != "" {
			registered = r.pool.Registered(ctx, dom)
		}
	}
	if f, ok := takeover.ByCNAME(host, d.CNAME, true, registered); ok {
		r.mu.Lock()
		r.takeovers = append(r.takeovers, takeoverRow{Host: host, Finding: f})
		r.mu.Unlock()
		return &f
	}
	return nil
}

// keepRow remembers what -db keeps: every name asked (the guesses of -w
// only when they have records), with what its answer was.
func (r *dnsRun) keepRow(host string, d *dnsr.Data, row *dnsRow) {
	if !r.keepOn || net.ParseIP(host) != nil || (r.in.brute && !d.Any()) {
		return
	}
	status := "nodata"
	switch {
	case len(d.A)+len(d.AAAA) > 0:
		status = "ok"
	case len(d.CNAME) > 0:
		status = "cname"
	}
	p := map[string]any{"fqdn": host}
	if rc, ok := d.Rcode(dns.TypeA); ok && rc == dns.RcodeNameError {
		status = "nxdomain"
		p["error"] = "nxdomain"
	}
	if !d.Answered() {
		status = "failed"
		p["error"], p["degraded"] = "no resolver answered", true
	}
	p["result"] = status
	if ips := append(append([]string(nil), d.A...), d.AAAA...); len(ips) > 0 {
		p["ips"] = ips
	}
	if len(d.CNAME) > 0 {
		p["cname"], p["cnames"] = d.CNAME[0], d.CNAME
	}
	for k, v := range map[string][]string{"mx": d.MX, "ns": d.NS, "txt": d.TXT, "srv": d.SRV, "caa": d.CAA} {
		if len(v) > 0 {
			p[k] = v
		}
	}
	if row != nil && row.CDNName != "" {
		p["cdn"], p["cdn_type"] = row.CDNName, row.CDNType
	}
	r.mu.Lock()
	for _, t := range r.takeovers {
		if t.Host == host {
			p["takeover"] = t.Finding
		}
	}
	r.kept = append(r.kept, dnsKept{host, p})
	r.mu.Unlock()
}

// hasSelected says whether the name has a record of a type that was asked.
func (r *dnsRun) hasSelected(d *dnsr.Data) bool {
	for _, k := range dnsKinds {
		if r.cf.selected[k.flag] && (d.Has(k.qtype) || k.flag == "any" && d.Any()) {
			return true
		}
	}
	return false
}

// ----- output -----

// dnsRow is a row as dnsx writes it: the records, then what -cdn and -asn add.
type dnsRow struct {
	*dnsr.Data
	IsCDN     bool    `json:"cdn,omitempty"`
	CDNName   string  `json:"cdn-name,omitempty"`
	CDNType   string  `json:"cdn-type,omitempty"`
	ASN       *dnsASN `json:"asn,omitempty"`
	QueryTime string  `json:"query-time,omitempty"`
	// Takeover is set on a name whose CNAME points at what is gone (not a dnsx field).
	Takeover *takeover.Finding `json:"takeover,omitempty"`
}

type dnsASN struct {
	Number  string   `json:"as-number,omitempty"`
	Name    string   `json:"as-name,omitempty"`
	Country string   `json:"as-country,omitempty"`
	Range   []string `json:"as-range,omitempty"`
}

func (a *dnsASN) String() string { return fmt.Sprintf("[%s, %s, %s]", a.Number, a.Name, a.Country) }

// cdn names the CDN, WAF or cloud: by address first, then by CNAME.
func (row *dnsRow) cdn(d *dnsr.Data) {
	if len(d.A)+len(d.AAAA)+len(d.CNAME) == 0 {
		return
	}
	var name, kind string
	for _, ip := range append(append([]string(nil), d.A...), d.AAAA...) {
		if name, kind = fingerprint.Network(net.ParseIP(ip)); name != "" {
			break
		}
	}
	if name == "" {
		name, kind = fingerprint.NetworkByName(d.CNAME...)
	}
	if name != "" {
		row.CDNName, row.CDNType = name, kind
		row.IsCDN = kind == "cdn"
	}
}

// output prints the name as dnsx would, given what the flags selected.
func (r *dnsRun) output(host string, d *dnsr.Data, row *dnsRow, selected bool) {
	cf := r.cf
	// JSON, -raw and templates print a name as one row; with a type flag
	// only names that have such a record, unless -rcode asked for others.
	whole := cf.json || cf.raw || cf.template != ""
	if whole && cf.explicit && !cf.all && !cf.axfr && len(cf.rcodes) == 0 && !selected && !cf.selected["any"] {
		return
	}
	if len(cf.rtf) > 0 && r.hasAny(d, cf.rtf) {
		return // -response-type-filter keeps names without those records
	}
	switch {
	case cf.template != "":
		r.w.line(r.tmpl.render(row))
		return
	case cf.json:
		raw, _ := json.Marshal(row)
		r.w.lineRaw(raw)
		return
	case cf.raw:
		r.w.line(strings.TrimRight(d.Raw, "\n"))
		return
	}
	details := ""
	if row.CDNName != "" {
		details = " [" + row.CDNName + "]"
	}
	if row.ASN != nil {
		details += " " + row.ASN.String()
	}
	if len(cf.rcodes) > 0 {
		if name, ok := dns.RcodeToString[d.StatusCodeRaw]; ok {
			r.w.line(host + " [" + name + "]")
		}
		return
	}
	printed := false
	emit := func(typ string, items []string) {
		for _, item := range items {
			item = strings.ToLower(item)
			switch {
			case cf.ro:
				r.w.line(item + details)
			case cf.resp:
				r.w.line(host + " [" + typ + "] [" + item + "]" + details)
			default:
				if !printed {
					r.w.line(host + details)
				}
				printed = true
				return // the name has one: that is the line
			}
		}
	}
	kinds := dnsPrint
	if len(cf.rtf) > 0 {
		// A name without the records filtered out shows the ones it has.
		kinds = []string{"a", "aaaa", "cname", "mx", "ns", "soa", "txt", "srv", "caa", "ptr"}
	}
	for _, kind := range kinds {
		if !cf.selected[kind] && len(cf.rtf) == 0 {
			continue
		}
		switch kind {
		case "a":
			emit("A", d.A)
		case "aaaa":
			emit("AAAA", d.AAAA)
		case "cname":
			emit("CNAME", d.CNAME)
		case "ptr":
			emit("PTR", d.PTR)
		case "mx":
			emit("MX", d.MX)
		case "ns":
			emit("NS", d.NS)
		case "soa":
			var v []string
			for _, s := range d.SOA {
				v = append(v, s.NS, s.Mbox)
			}
			emit("SOA", v)
		case "txt":
			emit("TXT", d.TXT)
		case "srv":
			emit("SRV", d.SRV)
		case "caa":
			emit("CAA", d.CAA)
		case "any":
			var v []string
			for _, soa := range d.SOA {
				v = append(v, soa.NS, soa.Mbox)
			}
			v = append(append(append(append(append(append(append(append(append(append([]string(nil), d.A...), d.AAAA...), d.CNAME...), d.MX...), d.PTR...), v...), d.NS...), d.TXT...), d.SRV...), d.CAA...)
			emit("ANY", v)
		}
	}
	if cf.axfr && d.AXFRData != nil {
		seen := map[string]bool{}
		for _, z := range d.AXFRData.Data {
			for _, rec := range z.AllRecords {
				rec = strings.Join(strings.Fields(rec), " ")
				if !seen[rec] {
					seen[rec] = true
					r.w.line(rec)
				}
			}
		}
	}
}

func (r *dnsRun) hasAny(d *dnsr.Data, kinds []string) bool {
	for _, k := range kinds {
		for _, kk := range dnsKinds {
			if kk.flag == k && d.Has(kk.qtype) {
				return true
			}
		}
	}
	return false
}

// transfer asks the name servers of host, and the resolvers the user gave,
// for the zone. A server outside the scope is not asked, and a server that
// refuses is noted.
func (r *dnsRun) transfer(ctx context.Context, host string, d *dnsr.Data) {
	rules := r.cf.rules
	if !r.cf.scoped {
		rules = scope.Rules{Allow: []string{host}} // held to the name given
	}
	denies := scope.Rules{Deny: rules.Deny}
	var servers []string
	seen := map[string]bool{}
	add := func(addr, why string) {
		if !seen[addr] {
			seen[addr] = true
			servers = append(servers, addr)
		}
	}
	ns := r.pool.Lookup(ctx, host, dnsr.LookupOptions{Types: []uint16{dns.TypeNS}})
	var out []string
	for _, n := range ns.NS {
		a := r.pool.Lookup(ctx, n, dnsr.LookupOptions{Types: []uint16{dns.TypeA}})
		for _, ip := range a.A {
			// A server is in scope by its name or by its address, and a deny
			// rule on either keeps it out.
			if !(rules.Allows(n) || rules.Allows(ip)) || !denies.Allows(n) || !denies.Allows(ip) {
				out = append(out, n+" ("+ip+")")
				continue
			}
			add(net.JoinHostPort(ip, "53"), n)
		}
	}
	if len(out) > 0 {
		r.noteAXFR(fmt.Sprintf("-axfr %s: name servers outside the scope not asked: %s (-allow them to ask)", host, strings.Join(out, ", ")))
	}
	for _, key := range r.resolvers {
		// The resolvers the user named are theirs to ask.
		if srv, err := dnsr.ParseResolver(key); err == nil && (srv.Net == dnsr.NetUDP || srv.Net == dnsr.NetTCP) {
			add(srv.Addr, "resolver")
		}
	}
	if len(servers) == 0 {
		r.noteAXFR(fmt.Sprintf("-axfr %s: no server to ask", host))
		return
	}
	chain, fails := r.pool.Transfer(ctx, host, servers)
	for _, f := range fails {
		r.noteAXFR(fmt.Sprintf("-axfr %s: %s did not transfer the zone: %v", host, f.Type, f.Err))
	}
	d.AXFRData = chain // an empty chain says it was tried, as dnsx's does
	if len(chain.Data) == 0 {
		r.noteAXFR(fmt.Sprintf("-axfr %s: no server transferred the zone", host))
	}
}

func (r *dnsRun) noteAXFR(s string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.axfrNotes) < 20 {
		r.axfrNotes = append(r.axfrNotes, s)
	}
}

// ----- ASN -----

// asnOf names the autonomous system of the first address, from Team
// Cymru's DNS service (origin.asn.cymru.com), through the run's resolvers.
func (r *dnsRun) asnOf(ctx context.Context, d *dnsr.Data, host string) *dnsASN {
	ips := d.A
	if ip := net.ParseIP(host); ip != nil {
		ips = []string{host}
	}
	for _, ip := range ips {
		a := net.ParseIP(ip).To4()
		if a == nil {
			continue
		}
		q := fmt.Sprintf("%d.%d.%d.%d.origin.asn.cymru.com", a[3], a[2], a[1], a[0])
		o := r.pool.Lookup(ctx, q, dnsr.LookupOptions{Types: []uint16{dns.TypeTXT}})
		if len(o.TXT) == 0 {
			continue
		}
		f := strings.Split(o.TXT[0], "|")
		if len(f) < 3 {
			continue
		}
		num := "AS" + strings.Fields(f[0])[0]
		out := &dnsASN{Number: num, Country: strings.TrimSpace(f[2]), Range: []string{strings.TrimSpace(f[1])}}
		if nm := r.pool.Lookup(ctx, num+".asn.cymru.com", dnsr.LookupOptions{Types: []uint16{dns.TypeTXT}}); len(nm.TXT) > 0 {
			if g := strings.Split(nm.TXT[0], "|"); len(g) >= 5 {
				out.Name = strings.TrimSpace(g[4])
			}
		}
		return out
	}
	return nil
}

// ----- template -----

type tmplPart struct {
	text string
	tag  bool
}

type tmplParts []tmplPart

func parseTemplate(t string) tmplParts {
	var out tmplParts
	for {
		i := strings.Index(t, "{{")
		if i < 0 {
			break
		}
		j := strings.Index(t[i:], "}}")
		if j < 0 {
			break
		}
		if i > 0 {
			out = append(out, tmplPart{text: t[:i]})
		}
		out = append(out, tmplPart{text: strings.TrimSpace(t[i+2 : i+j]), tag: true})
		t = t[i+j+2:]
	}
	if t != "" {
		out = append(out, tmplPart{text: t})
	}
	return out
}

// render fills the tags with the row's JSON fields: lists joined by commas,
// numbers and flags as text, and {{ip}} for A and AAAA together.
func (t tmplParts) render(row *dnsRow) string {
	raw, _ := json.Marshal(row)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	fields := map[string]string{}
	for k, v := range m {
		fields[k] = stringifyField(v)
	}
	var ips []string
	for _, k := range []string{"a", "aaaa"} {
		if fields[k] != "" {
			ips = append(ips, fields[k])
		}
	}
	fields["ip"] = strings.Join(ips, ",")
	var b strings.Builder
	for _, p := range t {
		if p.tag {
			b.WriteString(fields[p.text])
		} else {
			b.WriteString(p.text)
		}
	}
	return b.String()
}

func stringifyField(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case []any:
		parts := make([]string, 0, len(x))
		for _, i := range x {
			parts = append(parts, stringifyField(i))
		}
		return strings.Join(parts, ",")
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(x)
	case nil:
		return ""
	}
	raw, _ := json.Marshal(v)
	return string(raw)
}

// ----- the summary and the graph -----

func (r *dnsRun) summarize(ctx context.Context, args []string, maxtime float64) {
	rep, in := r.rep, r.in
	rep.Results = r.w.count()
	asked := int(in.asked.Load())
	rep.Counts = map[string]int{"asked": asked}
	if n := asked - int(r.counts.done.Load()); n > 0 {
		rep.Counts["not asked"] = n
	}
	if n := int(r.counts.noAnswer.Load()); n > 0 {
		rep.Counts["did not resolve"] = n
	}
	if n := int(r.counts.wildcard.Load()); n > 0 {
		rep.Counts["wildcard answers left out"] = n
		rep.Notes = append(rep.Notes, fmt.Sprintf("%d names answered only through a wildcard and are left out (-no-wildcard prints them)", n))
	}
	if n := int(r.counts.failed.Load()); n > 0 {
		rep.Counts["no answer"] = n
	}
	if n := int(r.counts.otherCode.Load()); n > 0 {
		rep.Counts["other codes"] = n // answered, but not with a code -rcode lists
	}
	if n := int(r.counts.broken.Load()); n > 0 {
		rep.Counts["servfail from every resolver"] = n
		rep.Notes = append(rep.Notes, fmt.Sprintf("%d questions were answered SERVFAIL by every resolver asked: the names' own DNS is broken (status_code SERVFAIL in -json, -rcode servfail lists them)", n))
	}
	in.mu.Lock()
	left := 0
	var whys []string
	for why := range in.counts {
		whys = append(whys, why)
	}
	sort.Strings(whys)
	for _, why := range whys {
		n := in.counts[why]
		left += n
		var eg []string
		for _, sk := range in.skipped {
			if sk.Reason == why {
				eg = append(eg, sk.Target)
			}
		}
		line := fmt.Sprintf("%d left out, %s: %s", n, why, strings.Join(eg, ", "))
		if n > len(eg) {
			line += ", ..."
		}
		if why == "an address, and no -ptr to ask for its name" || why == "addresses of a range, and no -ptr to ask for their names" {
			line += " (-ptr asks for the names of addresses)"
		}
		if why == "outside the scope" {
			continue // listed under skipped
		}
		rep.Notes = append(rep.Notes, line)
	}
	if left > 0 {
		rep.Counts["left out"] = left
	}
	for _, sk := range in.skipped {
		if sk.Reason == "outside the scope" {
			rep.Skipped = append(rep.Skipped, sk)
		}
	}
	rep.Notes = append(rep.Notes, in.notes...)
	rep.Failed = append(rep.Failed, in.failed...)
	in.mu.Unlock()
	r.mu.Lock()
	keys := make([]string, 0, len(r.failed))
	for k := range r.failed {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		rep.Failed = append(rep.Failed, *r.failed[k])
	}
	sort.Slice(r.takeovers, func(i, j int) bool { return r.takeovers[i].Host < r.takeovers[j].Host })
	rep.Takeover = append(rep.Takeover, r.takeovers...)
	rep.Notes = append(rep.Notes, r.axfrNotes...)
	if r.reservedN > 0 {
		rep.Notes = append(rep.Notes, fmt.Sprintf("%d names (%s) are special-use or single labels: the system's resolver was asked, not the default public resolvers (name -r resolvers to ask them)", r.reservedN, strings.Join(r.reservedEg, ", ")))
	}
	wm := r.watermark
	r.mu.Unlock()
	if ctx.Err() != nil || r.cut.Load() {
		if maxtime > 0 && (errors.Is(ctx.Err(), context.DeadlineExceeded) || r.cut.Load()) {
			rep.Stopped = fmt.Sprintf("-maxtime %gs reached", maxtime)
		} else {
			rep.Stopped = "interrupted"
		}
		left := "the names after the first " + strconv.Itoa(wm) + " were not all asked"
		rep.Notes = append(rep.Notes, left)
		if !in.stdin && !r.cf.stream {
			next := append(withoutFlag(args, "start"), "-start", strconv.Itoa(wm))
			rep.Resume = "azhaq dns " + shellJoin(next)
			rep.Notes = append(rep.Notes, "the run goes on from the first name not asked with -start "+strconv.Itoa(wm)+" (the names after it that were asked are asked again)")
		}
	}
}

// keep writes the names with records into a workspace.
func (r *dnsRun) keep(path string) error {
	st, err := store.Open(path)
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.BeginRun(newRunID(), 0, 0); err != nil {
		return err
	}
	_ = st.SetRunArgs(append([]string{"dns"}, os.Args[2:]...))
	now := time.Now().UTC()
	r.mu.Lock()
	kept := r.kept
	r.mu.Unlock()
	if !r.in.brute {
		var seeds []types.Seed // the names asked are the targets of the run
		for _, k := range kept {
			seeds = append(seeds, types.Seed{Type: types.TypeHostname, Keys: map[string]string{"fqdn": k.host}})
		}
		if err := st.SaveSeeds(seeds); err != nil {
			return err
		}
	}
	for _, k := range kept {
		ent, err := st.UpsertEntity(types.TypeHostname, k.host, now)
		if err != nil {
			return err
		}
		raw, _ := json.Marshal(k.p)
		if _, err := st.AddObservation(ent.ID, types.Observation{Collector: "azhaq-dns", Source: "dns", Kind: "dns", Payload: raw, Confidence: 0.95, ObservedAt: now}); err != nil {
			return err
		}
	}
	return nil
}

func selectedNames(cf *dnsConf) []string {
	var out []string
	for _, k := range dnsKinds {
		if cf.selected[k.flag] {
			out = append(out, strings.ToUpper(k.flag))
		}
	}
	return out
}

// perSecond lets n names through in each second, as dnsx's -rl does: the
// second starts at the first name, and the ones after the n-th wait for the
// next. (A token bucket would send n names at once and n more a moment
// later.)
type perSecond struct {
	n int

	mu    sync.Mutex
	start time.Time
	used  int
}

func (p *perSecond) wait(ctx context.Context) error {
	for {
		p.mu.Lock()
		now := time.Now()
		if p.start.IsZero() || now.Sub(p.start) >= time.Second {
			p.start, p.used = now, 0
		}
		if p.used < p.n {
			p.used++
			p.mu.Unlock()
			return nil
		}
		wait := time.Second - now.Sub(p.start)
		p.mu.Unlock()
		if dl, ok := ctx.Deadline(); ok && time.Until(dl) < wait {
			return context.DeadlineExceeded
		}
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// healthCheck asks each resolver for a known name and says how it answered.
func healthCheck(pool *dnsr.Pool, asJSON bool) error {
	bad := 0
	for _, st := range pool.Check(context.Background(), "example.com") {
		if st.Err != nil {
			bad++
		}
		if asJSON {
			row := map[string]any{"resolver": st.Server, "ok": st.Err == nil, "ms": st.Took.Milliseconds()}
			if st.Err != nil {
				row["error"] = st.Err.Error()
			}
			raw, _ := json.Marshal(row)
			fmt.Println(string(raw))
			continue
		}
		if st.Err != nil {
			fmt.Printf("%-40s FAILED %v\n", st.Server, st.Err)
		} else {
			fmt.Printf("%-40s ok %d ms, %s\n", st.Server, st.Took.Milliseconds(), st.Status)
		}
	}
	if bad > 0 {
		return exitErr{code: exitPartial}
	}
	return nil
}
