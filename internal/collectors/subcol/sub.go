// Package subcol finds subdomains of a domain through passive sources:
// certificate transparency, search engines, archives and DNS datasets.
// Most sources are subfinder's (MIT), run in-process with Azhaq's limiter
// and keys from a local provider file.
package subcol

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"

	"github.com/trannghiach/azhaq/catalog"
	"github.com/trannghiach/azhaq/internal/limit"
	"github.com/trannghiach/azhaq/internal/normalize"
	"github.com/trannghiach/azhaq/internal/timing"
	"github.com/trannghiach/azhaq/types"
)

const Name = "azhaq-subdomains"

// fanoutTimeout bounds each source for a domain derived from a URL: the
// run is about the application, and crt.sh alone can take 35 s.
var fanoutTimeout = 15 * time.Second

const (
	// DefaultMaxNames is how many names a domain keeps (-max-names): the
	// name history's cap, so what the history holds is never cut by it.
	DefaultMaxNames = 200000
	// DefaultSourceTimeout bounds each passive source apart from the run's
	// -timeout (-source-timeout): a slow one (crt.sh) is abandoned and
	// listed, retryable and non-fatal while the others answered.
	DefaultSourceTimeout = 60 * time.Second
	// lateGrace is how long after a source's deadline Run still waits for
	// it: some sources ignore the context (subfinder's crt.sh tries a
	// Postgres connection first).
	lateGrace = 2 * time.Second
	// emitGrace is how long before the run's deadline Run stops waiting on
	// sources: the engine drops what a task emits once its context has
	// ended, so what the sources gave by then is emitted while the run is
	// live, as a partial result, not thrown away.
	emitGrace      = 5 * time.Second
	defaultMaxBody = 32 << 20
)

func init() {
	// subfinder's sources log through gologger; Azhaq reports per source.
	gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
}

// Options choose sources and supply keys.
type Options struct {
	Client  *http.Client        // for sources; default: 60 s timeout, proxy from env
	Keys    map[string][]string // per source, from the provider file
	Only    []string            // run only these sources
	Exclude []string            // never run these
	All     bool                // also run sources outside the default set
	// NoHistory neither reads nor writes the name history (-no-history).
	NoHistory bool
	// SourceTimeout bounds each source (-source-timeout; default
	// DefaultSourceTimeout). It is not the run's -timeout: a source past it
	// is abandoned and listed as failed, and the others' names are kept.
	SourceTimeout time.Duration
	// Verify returns the names that resolve, not to a wildcard of domain
	// (what is kept of the names only a padding source gave or the history
	// holds), and the ones it could not check (the resolvers failed). Nil
	// checks nothing.
	Verify func(ctx context.Context, domain string, names []string) (live, failed []string)
	// NoCheck sends no DNS query for those names, whatever Verify is: they
	// are listed unverified (subs without -live).
	NoCheck bool
	// SourceRate caps each source's requests per second (-source-rate); a
	// source's own default, if lower, stays. SourceRates sets single
	// sources (-source-rates name=N/unit) and wins over both.
	SourceRate  float64
	SourceRates map[string]float64
	// MaxResults caps the names a paging source gives (-max-results).
	MaxResults int
	// MaxTime bounds the wait on all sources of a domain (-max-time).
	MaxTime time.Duration
	// MaxBody caps a source's response body in bytes (-max-body).
	MaxBody int64
	// MaxNames caps the names kept per domain (-max-names).
	MaxNames int
	// DNSPaced says the resolvers have a rate (-dns-rate): checking guesses
	// costs time, so the guessing is bounded by what the real names cost.
	DNSPaced bool
	// Recursive runs only the sources that handle subdomains of a subdomain.
	Recursive bool
	// Proxy sends every source request through this URL (-proxy).
	Proxy string
}

type Collector struct {
	opts    Options
	sources []source
	limiter *limit.Limiter
}

func New(o Options) *Collector {
	if o.Client == nil {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		if p, err := url.Parse(o.Proxy); err == nil && o.Proxy != "" {
			tr.Proxy = http.ProxyURL(p)
		}
		o.Client = &http.Client{Timeout: 60 * time.Second, Transport: tr}
	}
	// Every source's request goes through the transport that waits out a 429.
	cl := *o.Client
	if _, ok := cl.Transport.(*retryTransport); !ok {
		base := cl.Transport
		if base == nil {
			base = http.DefaultTransport
		}
		cl.Transport = &retryTransport{next: base}
	}
	o.Client = &cl
	if o.SourceTimeout <= 0 {
		o.SourceTimeout = DefaultSourceTimeout
	}
	if o.MaxNames <= 0 {
		o.MaxNames = DefaultMaxNames
	}
	if o.MaxBody <= 0 {
		o.MaxBody = defaultMaxBody
	}
	all := allSources()
	if fake := testSourcesInUse(); fake != nil {
		all = fake
	}
	l := limit.New(0, 1)
	for _, s := range all {
		rate := s.perSec
		if o.SourceRate > 0 && (rate <= 0 || o.SourceRate < rate) {
			rate = o.SourceRate
		}
		if r, ok := o.SourceRates[s.name]; ok {
			rate = r
		}
		if rate > 0 {
			l.Set(s.name, rate)
		}
	}
	return &Collector{opts: o, sources: all, limiter: l}
}

func Register(cat *catalog.Catalog, o Options) {
	cat.MustRegister(New(o))
}

func (c *Collector) Name() string { return Name }

// Info: this collector only asks third parties or DNS resolvers.
func (c *Collector) Info() catalog.Info { return catalog.Info{Kind: catalog.Passive} }

func (c *Collector) Inputs() []types.SeedType { return []types.SeedType{types.TypeDomain} }

func (c *Collector) Outputs() []string { return []string{"subdomains"} }

// Asks names the third-party sources a run asks about a domain; the name
// history is a local file.
func (c *Collector) Asks(seed types.Seed) []string {
	domain := normalize.Hostname(seed.Keys["domain"])
	if domain == "" || normalize.SpecialUse(domain) {
		return nil
	}
	run, _ := c.plan()
	out := make([]string, 0, len(run))
	for _, s := range run {
		if s.name != historyName {
			out = append(out, s.name)
		}
	}
	return out
}

// plan picks the sources for a run and says why the others are left out.
func (c *Collector) plan() (run []source, skipped map[string]string) {
	only := set(c.opts.Only)
	exclude := set(c.opts.Exclude)
	skipped = map[string]string{}
	for _, s := range c.sources {
		switch {
		case exclude[s.name], s.name == historyName && c.opts.NoHistory:
			continue
		case len(only) > 0 && !only[s.name]:
			continue
		case len(only) == 0 && !c.opts.All && !s.deflt:
			continue
		case c.opts.Recursive && !s.recurse && s.name != historyName:
			skipped[s.name] = "does not look for subdomains of subdomains (-recursive)"
			continue
		case s.need == requiredKey && len(c.opts.Keys[s.name]) == 0:
			skipped[s.name] = "needs a key"
			continue
		}
		run = append(run, s)
	}
	return run, skipped
}

type outcome struct {
	names []string
	err   error
	took  time.Duration
}

func (c *Collector) Run(ctx context.Context, seed types.Seed, emit func(types.Observation) error) (types.RunMeta, error) {
	domain := normalize.Hostname(seed.Keys["domain"])
	if domain == "" {
		return types.RunMeta{Status: types.StatusError, Error: "empty domain"}, nil
	}
	if normalize.SpecialUse(domain) {
		payload, _ := json.Marshal(map[string]any{"domain": domain, "count": 0, "skipped": "reserved"})
		return types.RunMeta{Status: types.StatusOK, EmitCount: 1}, emit(types.Observation{
			Collector: Name, Source: "subdomains", Kind: "subdomains", Payload: payload, ObservedAt: time.Now().UTC(),
		})
	}
	run, skipped := c.plan()
	if normalize.Unlisted(domain) {
		// No registry runs its TLD (azqlab.lan, corp.internal): no public
		// source can hold its names, so only the local history is asked.
		kept := run[:0]
		for _, s := range run {
			if s.name == historyName {
				kept = append(kept, s)
				continue
			}
			skipped[s.name] = "not a public domain: third-party sources only know public names"
		}
		run = kept
	}
	ext, err := subscraping.NewSubdomainExtractor(domain)
	if err != nil {
		return types.RunMeta{Status: types.StatusError, Error: err.Error()}, err
	}
	timeout := c.opts.SourceTimeout
	if seed.Derived() && timeout > fanoutTimeout {
		timeout = fanoutTimeout
	}
	// What a source still running is marked with when Run stops waiting.
	errSource := fmt.Errorf("no answer in %s (-source-timeout)", timeout)
	// wait is how long Run waits on the sources: their bound plus a grace
	// for the ones that ignore the context, but never past the run's
	// deadline, less the time to emit what was gathered.
	wait := timeout + lateGrace
	errLate := errSource
	if dl, ok := ctx.Deadline(); ok {
		left := time.Until(dl)
		grace := min(emitGrace, left/4)
		if left-grace < wait {
			wait = max(left-grace, 0)
			errLate = errors.New(types.CutShort)
		}
	}
	if mt := c.opts.MaxTime; mt > 0 && mt < wait {
		wait = mt
		errLate = fmt.Errorf("no answer in %s (-max-time)", mt)
	}
	results := make([]outcome, len(run))
	calls := make([]atomic.Int32, len(run))
	rounds := make([]roundLog, len(run))
	throttles := make([]throttle, len(run))
	partials := make([]partialNames, len(run))
	notes := make([]rowNote, len(run))
	answers := make([]answerLog, len(run))
	h := newHinter(ctx, domain, c.opts.MaxNames)
	// A padding source's guesses are resolved as its rounds arrive; that
	// needs resolvers and a reason: a source that guesses, or the history.
	var chk *checker
	if c.opts.Verify != nil && !c.opts.NoCheck {
		chk = newChecker(ctx, domain, c.opts.Verify, h.pass)
		chk.paced = c.opts.DNSPaced
	}
	var cancels []context.CancelFunc
	var wgFetch, wgSample sync.WaitGroup
	var mu sync.Mutex // results, reported
	reported := make([]bool, len(run))
	closed := false
	for i, s := range run {
		var sctx context.Context
		var cancel context.CancelFunc
		wg := &wgFetch
		if s.sampler {
			// It asks its source within its own time and resolves what it
			// gets on the run's: the DNS check is paced by -dns-rate.
			sctx, cancel = context.WithCancel(ctx)
			wg = &wgSample
		} else {
			sctx, cancel = context.WithTimeout(ctx, timeout)
		}
		cancels = append(cancels, cancel)
		sctx = context.WithValue(sctx, callsKey{}, &calls[i])
		sctx = context.WithValue(sctx, roundsKey{}, &rounds[i])
		sctx = context.WithValue(sctx, partialKey{}, &partials[i])
		sctx = withThrottle(sctx, &throttles[i])
		sctx = context.WithValue(sctx, noteKey{}, &notes[i])
		sctx = context.WithValue(sctx, answerKey{}, &answers[i])
		if chk != nil {
			sctx = context.WithValue(sctx, checkerKey{}, chk)
		}
		wg.Add(1)
		go func(i int, s source, sctx context.Context, wg *sync.WaitGroup) {
			defer wg.Done()
			sess := &subscraping.Session{
				Extractor:           ext,
				Client:              c.opts.Client,
				RequestLimiter:      c.limiter,
				Timeout:             int(timeout / time.Second),
				MaxResponseBodySize: c.opts.MaxBody,
				MaxResults:          c.opts.MaxResults,
			}
			done := timing.Start(ctx, "source."+s.name)
			t0 := time.Now()
			answered := begin(s.name, domain)
			names, err := s.collect(sctx, domain, c.opts.Keys[s.name], sess)
			answered()
			done()
			if !s.sampler && sctx.Err() != nil && ctx.Err() == nil && (err == nil || contextEnded(err)) {
				err = errSource // the names it gave by then are kept
			}
			mu.Lock()
			if !closed {
				results[i] = outcome{names: names, err: err, took: time.Since(t0)}
				reported[i] = true
			}
			mu.Unlock()
			if !s.verify {
				chk.know(cleaned(names, domain))
				h.pass(names) // a padding source's names wait for their check
			}
		}(i, s, sctx, wg)
	}
	fetched := make(chan struct{})
	go func() { wgFetch.Wait(); close(fetched) }()
	sampled := make(chan struct{})
	go func() { wgSample.Wait(); close(sampled) }()
	t0 := time.Now()
	timer := time.NewTimer(wait)
	defer timer.Stop()
	// late is what the sources still running are marked with; cut says the
	// run, not a source's bound, stopped the wait: the result is partial.
	late, cut := errSource, false
	select {
	case <-fetched:
	case <-ctx.Done():
	case <-timer.C:
		late, cut = errLate, errLate != errSource
	}
	// The sources that resolve their guesses are waited for until the run
	// must stop, less the time to emit what was gathered.
	sampleLate := errors.New(types.CutShort)
	if ctx.Err() == nil {
		var stop <-chan time.Time
		if dl, ok := ctx.Deadline(); ok {
			left := time.Until(dl)
			t := time.NewTimer(max(left-min(emitGrace, left/4), 0))
			defer t.Stop()
			stop = t.C
		}
		select {
		case <-sampled:
		case <-ctx.Done():
		case <-stop:
			cut = true
		}
	}
	if ctx.Err() != nil {
		// Ctrl-C, or the deadline came first: the sources that gave up
		// with the run are not failures of their own.
		late, cut = fmt.Errorf("stopped with the run (%v)", ctx.Err()), true
		sampleLate = late
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			late = errors.New(types.CutShort)
			sampleLate = late
		}
	}
	// The names gathered so far are emitted whatever stopped the wait: a
	// recon tool never throws away work it already did.
	mu.Lock()
	closed = true
	partial := false
	for i, s := range run {
		stopped := late
		if s.sampler {
			stopped = sampleLate
		}
		switch {
		case !reported[i]:
			results[i] = outcome{names: partials[i].snapshot(), err: stopped, took: time.Since(t0)}
			partial = partial || cut
		case ctx.Err() != nil && contextEnded(results[i].err):
			results[i].err = stopped
			partial = true
		}
	}
	mu.Unlock()
	h.stop()
	if chk != nil {
		chk.close()
	}
	for _, cancel := range cancels {
		cancel() // a source still checking stops asking
	}

	seen := map[string]bool{}
	var names []string
	cutNames := 0
	foundBy := map[string][]string{} // name → the sources that gave it
	wildcard := map[string]bool{}    // names a certificate gave as *.name
	status := map[string]any{}
	named := set(c.opts.Only)
	var failed []string
	for i, s := range run {
		r := results[i]
		row := map[string]any{"count": 0, "seconds": round(r.took.Seconds())}
		n := 0
		mine := map[string]bool{}
		for _, raw := range r.names {
			name := clean(raw, domain)
			if name != "" && strings.HasPrefix(strings.TrimSpace(raw), "*.") {
				wildcard[name] = true
			}
			if name == "" || mine[name] {
				continue
			}
			mine[name] = true
			n++
			if !seen[name] {
				if len(names) >= c.opts.MaxNames {
					cutNames++
					continue
				}
				seen[name] = true
				names = append(names, name)
			}
			foundBy[name] = append(foundBy[name], s.name)
		}
		row["count"] = n
		if !s.deflt && !named[s.name] {
			row["default"] = false // run by -all-sources: its failure is not the run's
		}
		if c := calls[i].Load(); c > 1 {
			row["calls"] = c
		}
		if est, ok := schnabel(rounds[i].snapshot()); ok {
			row["population_estimate"] = int(est + 0.5)
		}
		if st := rounds[i].statSnapshot(); len(st) > 0 {
			row["rounds"] = st
		}
		throttles[i].fields(row)
		if n := notes[i].get(); n != "" {
			row["partial"] = n
		}
		if r.err != nil {
			row["error"] = shorten(r.err.Error())
			failed = append(failed, s.name)
		}
		status[s.name] = row
	}
	for name, why := range skipped {
		status[name] = map[string]any{"skipped": why}
	}
	union := len(names)
	names, foundBy, st := c.settle(ctx, domain, run, names, foundBy, status, cut, chk)
	sort.Strings(names)
	for _, by := range foundBy {
		sort.Strings(by)
		// The history is a memory, not an answer: a name a source also gave
		// shows that source first, and "history" first means nothing else gave it.
		sort.SliceStable(by, func(i, j int) bool { return by[i] != historyName && by[j] == historyName })
	}
	payload := map[string]any{"domain": domain, "names": names, "count": len(names), "sources": status, "found_by": foundBy}
	payload["from_sources"] = union
	if st.dropped > 0 {
		payload["dropped"] = st.dropped
	}
	if len(st.unverified) > 0 {
		sort.Strings(st.unverified)
		payload["unverified"] = st.unverified
	}
	if st.asked > 0 {
		payload["checked"] = st.asked
	}
	if len(wildcard) > 0 {
		var ws []string
		for n := range wildcard {
			ws = append(ws, n)
		}
		sort.Strings(ws)
		payload["wildcard_certificate"] = ws
	}
	if cutNames > 0 {
		payload["cut"] = true
		payload["names_cut"] = cutNames
	}
	dep := map[string]bool{historyName: true}
	for _, s := range run {
		if s.verify {
			dep[s.name] = true
		}
	}
	if cov := coverage(foundBy, dep); cov != nil {
		payload["coverage"] = cov
	}
	if !c.opts.NoHistory {
		if err := remember(domain, names, foundBy, st.skip); err != nil {
			payload["history_error"] = shorten(err.Error())
		}
	}
	meta := types.RunMeta{Status: types.StatusOK, EmitCount: 1}
	if len(failed) > 0 {
		sort.Strings(failed)
		payload["warning"] = "failed: " + strings.Join(failed, ", ")
		if len(names) == 0 || partial {
			// Nothing found and something broke: not an honest zero. Or
			// the run stopped the wait: what is here is what the sources
			// gave by then, not the whole answer.
			payload["degraded"] = true
			meta.Status = types.StatusDegraded
		}
	}
	if partial {
		payload["partial"] = true
	}
	raw, _ := json.Marshal(payload)
	if err := emit(types.Observation{
		Collector: Name, Source: "subdomains", Kind: "subdomains",
		Payload: raw, Confidence: 0.8, ObservedAt: time.Now().UTC(),
	}); err != nil {
		if ctx.Err() != nil {
			// The engine takes nothing from a task whose run has ended.
			return types.RunMeta{Status: types.StatusCancelled}, ctx.Err()
		}
		return meta, err
	}
	for _, n := range names {
		if !h.was(n) {
			meta.NextHints = append(meta.NextHints, types.Seed{Type: types.TypeHostname, Keys: map[string]string{"fqdn": n}})
		}
	}
	return meta, nil
}

// settled is what became of the names a padding source or the history gave.
type settled struct {
	dropped    int             // did not resolve: left out
	unverified []string        // not checked: listed, flagged
	asked      int             // names sent to the resolvers, in all
	skip       map[string]bool // not stored in the history: never seen to resolve
}

// settle drops the names only padding sources gave (source.verify) that do
// not resolve, lists the ones it could not check, and notes in each such
// source's status how many it kept. Names a source's rounds already had
// checked are not asked again.
func (c *Collector) settle(ctx context.Context, domain string, run []source, names []string, foundBy map[string][]string, status map[string]any, cut bool, chk *checker) ([]string, map[string][]string, settled) {
	st := settled{skip: map[string]bool{}}
	padding := map[string]bool{}
	for _, s := range run {
		if s.verify {
			padding[s.name] = true
		}
	}
	if chk != nil {
		st.asked = chk.asked
	}
	if len(padding) == 0 {
		return names, foundBy, st
	}
	var check []string
	for _, n := range names {
		only := true
		for _, by := range foundBy[n] {
			if !padding[by] {
				only = false
				break
			}
		}
		if only {
			check = append(check, n)
		}
	}
	if len(check) == 0 {
		return names, foundBy, st
	}
	why := ""
	took := time.Duration(0)
	if chk != nil {
		took = chk.took
		var more []string // not asked by the rounds, or the resolvers failed
		for _, n := range check {
			if v := chk.verdict(n); v == 0 || v == nameUnchecked {
				more = append(more, n)
			}
		}
		// Near the -timeout there is no room for a DNS pass over hundreds of
		// names without blowing the deadline and losing the whole result:
		// list them unverified, emit the rest, resume later.
		vctx, skip := ctx, cut
		if dl, ok := ctx.Deadline(); ok {
			if left := time.Until(dl); left < emitGrace {
				skip = true
			} else {
				var cancel context.CancelFunc
				vctx, cancel = context.WithTimeout(ctx, left-emitGrace)
				defer cancel()
			}
		}
		if len(more) > 0 && !skip {
			chk.mu.Lock()
			for _, n := range more {
				delete(chk.state, n)
			}
			chk.mu.Unlock()
			start := time.Now()
			chk.checkWith(vctx, more, true)
			took += time.Since(start)
			st.asked = chk.asked
		} else if len(more) > 0 {
			why = types.CutShort
		}
	} else {
		why = "not asked: no -live"
	}
	drop := map[string]bool{}
	for _, n := range check {
		v := int8(0)
		if chk != nil {
			v = chk.verdict(n)
		}
		switch v {
		case nameLive:
		case nameDead:
			drop[n] = true
			delete(foundBy, n)
		default:
			st.unverified = append(st.unverified, n)
			st.skip[n] = true
		}
	}
	st.dropped = len(drop)
	kept := names[:0]
	for _, n := range names {
		if !drop[n] {
			kept = append(kept, n)
		}
	}
	for name := range padding {
		if row, ok := status[name].(map[string]any); ok {
			row["kept"] = len(check) - len(drop) - len(st.unverified)
			row["dropped_unresolved"] = len(drop)
			if len(st.unverified) > 0 {
				row["unverified"] = len(st.unverified)
			}
			if chk != nil {
				row["checked_seconds"] = round(took.Seconds()) // all the guesses at once, shared
			}
			if why != "" && chk != nil {
				// Said, not silent: these may hold a real name. azhaq resume
				// checks them.
				row["error"] = fmt.Sprintf("%d of its names not checked: %s; azhaq resume checks them", len(st.unverified), why)
			} else if chk != nil && len(st.unverified) > 0 {
				row["error"] = fmt.Sprintf("%d of its names not checked: the DNS lookups failed; azhaq resume checks them", len(st.unverified))
			}
		}
	}
	return kept, foundBy, st
}

// cleaned is the names in canonical form under domain.
func cleaned(names []string, domain string) []string {
	out := make([]string, 0, len(names))
	for _, raw := range names {
		if n := clean(raw, domain); n != "" {
			out = append(out, n)
		}
	}
	return out
}

// clean returns name in canonical form if it is domain or under it.
func clean(name, domain string) string {
	n := normalize.Hostname(strings.TrimPrefix(strings.TrimSpace(name), "*."))
	if n == "" || strings.ContainsAny(n, " /:@*") {
		return ""
	}
	if n != domain && !strings.HasSuffix(n, "."+domain) {
		return ""
	}
	return n
}

func set(xs []string) map[string]bool {
	m := map[string]bool{}
	for _, x := range xs {
		if x = strings.ToLower(strings.TrimSpace(x)); x != "" {
			m[x] = true
		}
	}
	return m
}

func round(f float64) float64 { return float64(int(f*10+0.5)) / 10 }

// contextEnded reports whether err is a context's end, not the source's
// own failure. subfinder's sources join their errors as text.
func contextEnded(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "context canceled") || strings.Contains(s, "context deadline exceeded")
}

func shorten(s string) string {
	s = keyParam.ReplaceAllString(s, "${1}…")
	if len(s) > 200 {
		return s[:200] + "…"
	}
	return s
}

// keyParam is a credential in a URL's query: sources that take their key
// there (Shodan's ?key=, hackertarget's &apikey=) name the URL in an error,
// and the error goes to the summary and the workspace.
var keyParam = regexp.MustCompile(`(?i)([?&](?:api[_-]?key|apikey|key|token|access_token|auth|password|secret)=)[^&\s"')]+`)
