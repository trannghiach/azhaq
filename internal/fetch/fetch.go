package fetch

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/trannghiach/azhaq/internal/ledger"
	"github.com/trannghiach/azhaq/internal/neterr"
	"github.com/trannghiach/azhaq/internal/normalize"
	"github.com/trannghiach/azhaq/internal/timing"
)

type Hop struct {
	URL      string `json:"url"`
	Status   int    `json:"status"`
	Location string `json:"location,omitempty"`
}

// UserAgent goes on every request to a target: a current browser's, as
// httpx and katana send, because CDN bot managers hold requests from
// anything else open without an answer (Akamai does, for curl and for a
// tool's name). -header 'User-Agent: …' replaces it.
var UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"

// ToolAgent names Azhaq to the third-party services it asks (archives,
// RDAP, RIPEstat, search APIs); the CLI sets the version.
var ToolAgent = "azhaq (+https://github.com/trannghiach/azhaq)"

const (
	// MaxBody caps HTML and other documents.
	MaxBody = 2 << 20
	// MaxScriptBody caps JavaScript, JSON and source maps: bundles of
	// several MB are normal and their routes sit anywhere in the file.
	MaxScriptBody = 16 << 20
)

type Result struct {
	RequestURL string
	Status     int // first hop: the requested URL's own status
	URL        string
	Header     http.Header // first hop headers
	Body       []byte      // final body (for title / forms)
	StatusLine string
	Hops       []Hop
	Truncated  bool
	// FinalHeader is the last hop's headers (equal to Header without redirects).
	FinalHeader http.Header
	// IP is the address the first request connected to; empty through a proxy.
	IP string
	// Elapsed covers every hop, headers and body.
	Elapsed time.Duration

	cut bool // the chain stopped before its end: the budget, a failure or an interrupt
}

// Extra is copied onto every GET. Cookie values stay on the wire, not in Extra's docs.
var Extra http.Header

// Allow, when set, is the run's scope: a host it rejects is never
// requested, not even as a redirect target.
var Allow func(host string) bool

// resolver, when set, gives the addresses to connect to for a name: the
// run's own DNS answers, so a service is reached at the address its
// names were seen to resolve to. Unset, or no answer: the system
// resolver. It is swapped whole: a request a finished run left behind
// (a source past its deadline) may still dial while the next run sets it.
var resolver atomic.Pointer[func(ctx context.Context, host string) []string]

// SetResolver sets the run's resolver; nil goes back to the system's.
func SetResolver(f func(ctx context.Context, host string) []string) {
	if f == nil {
		resolver.Store(nil)
		return
	}
	resolver.Store(&f)
}

// Resolve is the run's answer for host, or nil without a resolver.
func Resolve(ctx context.Context, host string) []string {
	if f := resolver.Load(); f != nil {
		return (*f)(ctx, host)
	}
	return nil
}

var (
	cacheMu  sync.Mutex
	cache    = map[string]cacheEnt{}
	inflight = map[string]chan struct{}{}
	hostSem  = map[string]chan struct{}{}
)

// Keeper keeps the answers of a run in its workspace, so that azhaq
// resume does not ask again what the run already asked.
type Keeper interface {
	// Load is the kept answer for raw, if any.
	Load(raw string) (Result, bool)
	// Keep records an answer.
	Keep(raw string, res Result)
}

// Keep, when set, is where answers are kept and looked up before a GET.
var Keep Keeper

// Memo is a small record kept the same way, for requests that do not go
// through Do (a path guess keeps only its status and sizes).
type Memo interface {
	Recall(key string) ([]byte, bool)
	Remember(key string, v []byte)
}

// Memos, when set, keeps such records for azhaq resume.
var Memos Memo

// HostParallel caps in-flight uncached GETs per host (-host-parallel).
var HostParallel = 10

// Delay is a pause before each uncached GET.
var Delay time.Duration

// OriginTrips is how many connects or timeouts in a row, with no answer
// between them, stop an origin for the rest of the run: its remaining
// requests are refused with neterr.ErrOriginDown, and the work waits for
// azhaq resume. A dead host would otherwise take every request the run
// has for it, each a timeout long.
var OriginTrips = 5

var (
	originMu sync.Mutex
	origins  = map[string]*origin{} // scheme://host:port → how it has been answering
)

type origin struct {
	silent int  // unanswered requests in a row
	down   bool // stopped: OriginTrips reached
}

// Reset clears the process GET cache and host gates. Tests and bench call this.
func Reset() {
	cacheMu.Lock()
	cache = map[string]cacheEnt{}
	inflight = map[string]chan struct{}{}
	hostSem = map[string]chan struct{}{}
	Extra = nil
	Allow = nil
	SetResolver(nil)
	Keep = nil
	Memos = nil
	Delay = 0
	cacheMu.Unlock()
	originMu.Lock()
	origins = map[string]*origin{}
	originMu.Unlock()
	resetProbes()
	resetDescribed()
	resetNotes()
	resetBudget()
}

// originOf is the origin raw is requested from: scheme://host:port.
func originOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return ""
	}
	port := u.Port()
	if port == "" {
		port = "80"
		if u.Scheme == "https" {
			port = "443"
		}
	}
	return strings.ToLower(u.Scheme) + "://" + net.JoinHostPort(strings.ToLower(u.Hostname()), port)
}

// originRefused is the refusal for raw when its origin has stopped
// answering, else nil. It is noted on ctx (Stopped) so the task that
// asked ends capped rather than failed.
func originRefused(ctx context.Context, raw string) error {
	o := originOf(raw)
	if o == "" {
		return nil
	}
	originMu.Lock()
	st := origins[o]
	down := st != nil && st.down
	originMu.Unlock()
	if !down {
		return nil
	}
	err := &neterr.OriginDown{Origin: o, Failures: OriginTrips}
	markStopped(ctx, err)
	return err
}

// markStopped notes on ctx that a request got the origin-stopped refusal,
// whether it was about to send one or took the refusal another request on
// the same URL had already cached: either way its task is not done, and
// azhaq resume runs it again. Harmless for any other error.
func markStopped(ctx context.Context, err error) {
	if !errors.Is(err, neterr.ErrOriginDown) {
		return
	}
	if w, _ := ctx.Value(refusedKey{}).(*watch); w != nil {
		w.mu.Lock()
		if w.down == nil {
			w.down = err
		}
		w.mu.Unlock()
	}
}

// noteOrigin counts how raw's origin answered: an answer of any kind
// starts its count over; a connect or a timeout, with the run still
// going, brings it closer to being stopped.
func noteOrigin(ctx context.Context, raw string, err error) {
	o := originOf(raw)
	if o == "" {
		return
	}
	originMu.Lock()
	defer originMu.Unlock()
	st := origins[o]
	if st == nil {
		st = &origin{}
		origins[o] = st
	}
	switch {
	case err == nil:
		st.silent = 0
	case ctx.Err() == nil && neterr.Unanswered(err):
		st.silent++
		if OriginTrips > 0 && st.silent >= OriginTrips {
			st.down = true
		}
	}
}

// OriginsDown lists the origins the run stopped sending to, sorted.
func OriginsDown() []string {
	originMu.Lock()
	defer originMu.Unlock()
	var out []string
	for o, st := range origins {
		if st.down {
			out = append(out, o)
		}
	}
	sort.Strings(out)
	return out
}

type cacheEnt struct {
	res Result
	err error
}

// Cached is the answer the process cache holds for raw, without sending
// anything: azhaq roles keeps the bodies a role's run got.
func Cached(raw string) (Result, bool) {
	cacheMu.Lock()
	defer cacheMu.Unlock()
	e, ok := cache[raw]
	return e.res, ok && e.err == nil
}

func Client(c *http.Client) *http.Client {
	if c != nil {
		return recorded(c)
	}
	// InsecureSkipVerify: we are observing whatever cert is presented (same as azhaq-tls).
	// Headers within 10 s, like httpx: CDN edges and bot managers often
	// answer slowly. The body gets longer: a 1 MB bundle on a slow link
	// is not a dead host.
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: ledger.Wrap(&http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           dial,
			TLSHandshakeTimeout:   5 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS12,
			},
		}),
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// recorded is c with its requests entered in the run's ledger: c itself when
// it already is, else a copy.
func recorded(c *http.Client) *http.Client {
	if _, ok := c.Transport.(*ledger.Transport); ok {
		return c
	}
	cp := *c
	cp.Transport = ledger.Wrap(c.Transport)
	return &cp
}

// Dial connects to addr as the run's HTTP client does: through the resolver's
// addresses for a name.
func Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	return dial(ctx, network, addr)
}

// dial connects through the resolver's addresses when it has an answer, the
// way the system would: IPv6 first where the machine has a route for it,
// IPv4 tried too after a short head start (RFC 8305). Some edges answer
// only one family from a given network.
func dial(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: 5 * time.Second}
	host, port, err := net.SplitHostPort(addr)
	if err != nil || net.ParseIP(host) != nil {
		return d.DialContext(ctx, network, addr)
	}
	ips := Resolve(ctx, host)
	if len(ips) == 0 {
		return d.DialContext(ctx, network, addr) // /etc/hosts, special-use names
	}
	var v4, v6 []string
	for _, ip := range ips {
		if strings.Contains(ip, ":") {
			v6 = append(v6, ip)
		} else {
			v4 = append(v4, ip)
		}
	}
	primary, fallback := v4, v6
	if ipv6Routable() && len(v6) > 0 {
		primary, fallback = v6, v4
	} else if !ipv6Routable() {
		fallback = nil
	}
	if len(primary) == 0 {
		primary, fallback = fallback, nil
	}
	return dialEither(ctx, d, network, port, primary, fallback)
}

// fallbackDelay is the head start of the preferred address family.
const fallbackDelay = 300 * time.Millisecond

// dialEither tries primary addresses in order and, from fallbackDelay on,
// the fallback ones alongside; the first connection wins.
func dialEither(ctx context.Context, d *net.Dialer, network, port string, primary, fallback []string) (net.Conn, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		c   net.Conn
		err error
	}
	results := make(chan result, 2)
	try := func(ips []string, wait time.Duration) {
		if wait > 0 {
			select {
			case <-ctx.Done():
				results <- result{err: ctx.Err()}
				return
			case <-time.After(wait):
			}
		}
		var last error
		for _, ip := range ips {
			c, err := d.DialContext(ctx, network, net.JoinHostPort(ip, port))
			if err == nil {
				results <- result{c: c}
				return
			}
			last = err
			if ctx.Err() != nil {
				break
			}
		}
		results <- result{err: last}
	}
	n := 1
	go try(primary, 0)
	if len(fallback) > 0 {
		n++
		go try(fallback, fallbackDelay)
	}
	var first error
	for i := 0; i < n; i++ {
		r := <-results
		if r.err == nil {
			cancel()
			// The other attempt may still connect: close what it opens.
			go func(left int) {
				for j := 0; j < left; j++ {
					if r := <-results; r.c != nil {
						r.c.Close()
					}
				}
			}(n - i - 1)
			return r.c, nil
		}
		if first == nil {
			first = r.err
		}
	}
	return nil, first
}

// IPv6Routable says whether this machine can reach IPv6 addresses on the
// internet.
func IPv6Routable() bool { return ipv6Routable() }

var ipv6Routable = sync.OnceValue(func() bool {
	// A UDP "connection" sends nothing; it only asks the kernel for a
	// route and a source address.
	c, err := net.Dial("udp6", "[2001:4860:4860::8888]:53")
	if err != nil {
		return false
	}
	defer c.Close()
	ip := c.LocalAddr().(*net.UDPAddr).IP
	return ip.IsGlobalUnicast() && !ip.IsPrivate()
})

func GET(ctx context.Context, c *http.Client, raw string) (*http.Response, []byte, error) {
	res, _, err := Do(ctx, c, raw)
	if err != nil {
		return nil, nil, err
	}
	final := res.URL
	if final == "" {
		final = res.RequestURL
	}
	resp := &http.Response{
		StatusCode: res.Status,
		Status:     res.StatusLine,
		Header:     res.Header.Clone(),
		Request:    &http.Request{URL: mustURL(final)},
	}
	return resp, res.Body, nil
}

func Do(ctx context.Context, c *http.Client, raw string) (Result, bool, error) {
	if EndsSession(raw) {
		return Result{}, false, neterr.ErrEndsSession
	}
	if !inScope(raw) {
		return Result{}, false, neterr.ErrOutOfScope
	}
	cacheMu.Lock()
	if e, ok := cache[raw]; ok {
		cacheMu.Unlock()
		markStopped(ctx, e.err)
		return e.res, true, e.err
	}
	if wait, ok := inflight[raw]; ok {
		cacheMu.Unlock()
		done := timing.Start(ctx, "fetch.wait", raw)
		select {
		case <-ctx.Done():
			done()
			return Result{}, true, ctx.Err()
		case <-wait:
		}
		done()
		cacheMu.Lock()
		e := cache[raw]
		cacheMu.Unlock()
		markStopped(ctx, e.err)
		return e.res, true, e.err
	}
	if err := originRefused(ctx, raw); err != nil {
		cacheMu.Unlock()
		return Result{}, false, err // not cached: the origin may answer again in a later run
	}
	wait := make(chan struct{})
	inflight[raw] = wait
	cacheMu.Unlock()

	if Keep != nil {
		if res, ok := Keep.Load(raw); ok {
			// Asked before this run was stopped: not sent, not counted.
			cacheMu.Lock()
			cache[raw] = cacheEnt{res: res}
			cacheHopsLocked(res)
			delete(inflight, raw)
			close(wait)
			cacheMu.Unlock()
			return res, false, nil
		}
	}
	release, err := acquireHost(ctx, raw)
	if err != nil {
		cacheMu.Lock()
		cache[raw] = cacheEnt{err: err}
		delete(inflight, raw)
		close(wait)
		cacheMu.Unlock()
		return Result{}, false, err
	}
	if err := originRefused(ctx, raw); err != nil {
		// The origin was stopped while this request waited for its turn
		// on the host: whoever waits on this URL gets the refusal too.
		release()
		cacheMu.Lock()
		cache[raw] = cacheEnt{err: err}
		delete(inflight, raw)
		close(wait)
		cacheMu.Unlock()
		return Result{}, false, err
	}
	if Delay > 0 {
		t := time.NewTimer(Delay)
		select {
		case <-ctx.Done():
			t.Stop()
			release()
			cacheMu.Lock()
			cache[raw] = cacheEnt{err: ctx.Err()}
			delete(inflight, raw)
			close(wait)
			cacheMu.Unlock()
			return Result{}, false, ctx.Err()
		case <-t.C:
		}
	}
	done := timing.Start(ctx, "fetch", raw)
	res, err := do(ctx, c, raw)
	done()
	release()
	noteOrigin(ctx, raw, err)
	cacheMu.Lock()
	cache[raw] = cacheEnt{res: res, err: err}
	var hops []Result
	if err == nil {
		hops = cacheHopsLocked(res)
	}
	delete(inflight, raw)
	close(wait)
	cacheMu.Unlock()
	if err == nil && !res.cut && ctx.Err() == nil && Keep != nil {
		Keep.Keep(raw, res)
		for _, hop := range hops {
			Keep.Keep(hop.RequestURL, hop)
		}
	}
	return res, false, err
}

// cacheHopsLocked records each hop URL so a redirect partner is not walked
// again, and returns the ones it added: a URL asked for itself keeps its
// own answer.
func cacheHopsLocked(res Result) []Result {
	var added []Result
	for _, hop := range hopResults(res) {
		if _, ok := cache[hop.RequestURL]; !ok {
			cache[hop.RequestURL] = cacheEnt{res: hop}
			added = append(added, hop)
		}
	}
	return added
}

// hopResults is the answer each later hop of a redirect chain stands for:
// asking for it would walk the rest of the chain.
func hopResults(res Result) []Result {
	var out []Result
	for i, hop := range res.Hops {
		if hop.URL == "" || hop.URL == res.RequestURL {
			continue
		}
		rest := res.Hops[i:]
		// Only the first and the last hop's headers are known: a hop in
		// between has its Location.
		header := http.Header{}
		if hop.Location != "" {
			header.Set("Location", hop.Location)
		}
		switch {
		case i == 0:
			header = res.Header
		case i == len(res.Hops)-1:
			header = res.FinalHeader
		}
		out = append(out, Result{
			RequestURL: hop.URL,
			Status:     rest[0].Status,
			URL:        res.URL,
			Header:     header,
			Body:       res.Body,
			Hops:       rest,
			Truncated:  res.Truncated,

			FinalHeader: res.FinalHeader,
		})
	}
	return out
}

func do(ctx context.Context, c *http.Client, raw string) (Result, error) {
	c = noFollow(c)
	current := raw
	var hops []Hop
	var firstHeader http.Header
	var firstLine string
	var lastBody []byte
	var lastURL string
	var lastTrunc bool
	var lastHeader http.Header
	var remoteIP string
	var cut bool
	start := time.Now()
	for i := 0; i < 6; i++ {
		rctx := ctx
		if i == 0 {
			rctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{GotConn: func(ci httptrace.GotConnInfo) {
				if ci.Conn != nil && remoteIP == "" {
					if host, _, err := net.SplitHostPort(ci.Conn.RemoteAddr().String()); err == nil {
						remoteIP = host
					}
				}
			}})
		}
		req, err := http.NewRequestWithContext(rctx, http.MethodGet, current, nil)
		if err != nil {
			return Result{}, err
		}
		ApplyHeaders(req)
		if err := Spend(ctx); err != nil {
			if i > 0 {
				cut = true
				break // the redirect is recorded; its target is not requested
			}
			return Result{}, err
		}
		resp, err := c.Do(req)
		if err != nil {
			if i > 0 {
				cut = true
				break // the redirect answered; where it points did not
			}
			return Result{}, err
		}
		body, truncated, err := readBody(resp.Body, bodyLimit(resp))
		resp.Body.Close()
		if err != nil {
			if i > 0 {
				cut = true
				break
			}
			return Result{}, err
		}
		loc := strings.TrimSpace(resp.Header.Get("Location"))
		reqURL := current
		if resp.Request != nil && resp.Request.URL != nil {
			reqURL = resp.Request.URL.String()
		}
		hops = append(hops, Hop{URL: reqURL, Status: resp.StatusCode, Location: loc})
		if firstHeader == nil {
			firstHeader = resp.Header.Clone()
			firstLine = resp.Status
		}
		lastBody = body
		lastTrunc = truncated
		lastHeader = resp.Header
		lastURL = reqURL
		if !isRedirect(resp.StatusCode) || loc == "" {
			break
		}
		next, err := resp.Request.URL.Parse(loc)
		if err != nil || !inScope(next.String()) || !followable(raw, next.String()) {
			break // the hop is recorded with its Location; the target is not requested
		}
		current = next.String()
	}
	status := 0
	if len(hops) > 0 {
		status = hops[0].Status
	}
	return Result{
		RequestURL: raw,
		Status:     status,
		StatusLine: firstLine,
		URL:        lastURL,
		Header:     firstHeader,
		Body:       lastBody,
		Hops:       hops,
		Truncated:  lastTrunc,

		FinalHeader: lastHeader,
		IP:          viaProxy(c, raw, remoteIP),
		Elapsed:     time.Since(start),
		cut:         cut,
	}, nil
}

// viaProxy drops ip when the request went through a proxy: the address
// is the proxy's, not the target's.
func viaProxy(c *http.Client, raw, ip string) string {
	rt := ledger.Unwrap(c.Transport)
	if rt == nil {
		rt = http.DefaultTransport
	}
	t, ok := rt.(*http.Transport)
	if !ok || t.Proxy == nil {
		return ip
	}
	req, err := http.NewRequest(http.MethodGet, raw, nil)
	if err != nil {
		return ip
	}
	if u, err := t.Proxy(req); err == nil && u != nil {
		return ""
	}
	return ip
}

// ErrorPage: the final answer is a "not found" or a server error, whose
// relative links point under a path that does not exist.
func ErrorPage(res Result) bool {
	st := res.Status
	if n := len(res.Hops); n > 0 {
		st = res.Hops[n-1].Status
	}
	return st == 400 || st == 404 || st == 410 || st >= 500
}

// ApplyHeaders adds -cookie/-header values and the default User-Agent.
func ApplyHeaders(req *http.Request) {
	for k, vs := range Extra {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", UserAgent)
	}
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	}
}

func readBody(r io.Reader, limit int) ([]byte, bool, error) {
	body, err := io.ReadAll(io.LimitReader(r, int64(limit)+1))
	if err != nil {
		return nil, false, err
	}
	if len(body) > limit {
		return body[:limit], true, nil
	}
	return body, false, nil
}

func bodyLimit(resp *http.Response) int {
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	if strings.Contains(ct, "javascript") || strings.Contains(ct, "ecmascript") || strings.Contains(ct, "json") {
		return MaxScriptBody
	}
	if resp.Request != nil && resp.Request.URL != nil {
		p := strings.ToLower(resp.Request.URL.Path)
		for _, ext := range []string{".js", ".mjs", ".cjs", ".json", ".map"} {
			if strings.HasSuffix(p, ext) {
				return MaxScriptBody
			}
		}
	}
	return MaxBody
}

func noFollow(c *http.Client) *http.Client {
	if c == nil {
		c = Client(nil)
	}
	cp := *recorded(c)
	cp.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &cp
}

func isRedirect(status int) bool {
	switch status {
	case 301, 302, 303, 307, 308:
		return true
	default:
		return false
	}
}

func acquireHost(ctx context.Context, raw string) (func(), error) {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return func() {}, nil
	}
	n := HostParallel
	if n <= 0 {
		n = 4
	}
	host := strings.ToLower(u.Hostname())
	cacheMu.Lock()
	sem, ok := hostSem[host]
	if !ok {
		sem = make(chan struct{}, n)
		hostSem[host] = sem
	}
	cacheMu.Unlock()
	select {
	case <-ctx.Done():
		return func() {}, ctx.Err()
	case sem <- struct{}{}:
		return func() { <-sem }, nil
	}
}

func mustURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		return &url.URL{}
	}
	return u
}

// followable says whether a redirect from raw to next is followed: when
// next is on raw's site. A redirect to a third party (an asset host, an
// identity provider) is recorded with its Location, and that party's
// page is never reported as the target's.
func followable(raw, next string) bool { return SameSite(raw, next) }

// SameSite says whether other belongs to the site of page, the way
// redirects are followed: with a scope, when the scope allows other's
// host; without one, when both hosts share a Site (an address is only
// itself). A bundle on cdn.example.com and an API on api.example.com
// belong to www.example.com; a library on a third-party CDN does not.
func SameSite(page, other string) bool {
	if Allow != nil {
		return inScope(other)
	}
	a, b := hostOf(page), hostOf(other)
	if a == "" || b == "" {
		return true
	}
	return Site(a) == Site(b)
}

// Site is what a run without a scope keeps to from a host: its
// registrable domain, or the host itself (an address, a name without one).
// Chrome is held to the sites of the pages it is pointed at the same way.
func Site(host string) string {
	host = strings.ToLower(host)
	if d := normalize.RegistrableDomain(host); d != "" {
		return d
	}
	return host
}

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

func inScope(raw string) bool {
	if Allow == nil {
		return true
	}
	u, err := url.Parse(raw)
	return err != nil || u.Hostname() == "" || Allow(u.Hostname())
}

var logoutWords = []string{"logout", "log-out", "log_out", "signout", "sign-out", "sign_out", "logoff"}

// EndsSession: a run with a session never requests a logout URL.
// HasSession says whether the run sends a session: a cookie, an
// Authorization header, or a header whose name says it carries a token
// or a key.
func HasSession() bool {
	for k, vs := range Extra {
		if len(vs) == 0 || vs[0] == "" {
			continue
		}
		k = strings.ToLower(k)
		for _, w := range []string{"cookie", "auth", "token", "session", "key", "secret", "csrf", "xsrf"} {
			if strings.Contains(k, w) {
				return true
			}
		}
	}
	return false
}

func EndsSession(raw string) bool {
	if !HasSession() {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	p := strings.ToLower(u.Path)
	for _, w := range logoutWords {
		if strings.Contains(p, w) {
			return true
		}
	}
	return false
}
