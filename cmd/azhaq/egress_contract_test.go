package main

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"

	"github.com/trannghiach/azhaq/internal/browser"
	"github.com/trannghiach/azhaq/internal/egress"
	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/internal/ledger"
	"github.com/trannghiach/azhaq/internal/neterr"
)

// The egress contract: every command that sends anything is run against
// servers of this machine only, through counters, and the counts must agree:
// what the target's server answered, what the proxy in front of it passed,
// what the ledger lists and what the summary says are one number. A request
// that went round egress shows as a server count above the proxy's; one
// that skipped the ledger, as a ledger count below it. A command added to the
// registry without an entry here fails TestEgressContractNamesEveryCommand.

// egressHarness is a target behind a counting proxy.
type egressHarness struct {
	t       *testing.T
	target  *httptest.Server
	proxy   *httptest.Server
	served  atomic.Int64 // answered by the target
	proxied atomic.Int64 // passed by the proxy
	ledger  string

	mu   sync.Mutex
	seen []string // paths the target was asked for
}

func newEgressHarness(t *testing.T) *egressHarness {
	t.Helper()
	h := &egressHarness{t: t, ledger: filepath.Join(t.TempDir(), "run.ledger.jsonl")}
	h.target = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.served.Add(1)
		h.mu.Lock()
		h.seen = append(h.seen, r.URL.Path)
		h.mu.Unlock()
		switch r.URL.Path {
		case "/":
			fmt.Fprint(w, `<html><title>home</title><a href="/a">a</a> <a href="/b">b</a> <a href="/admin/panel">admin</a></html>`)
		case "/a", "/b", "/admin/panel":
			fmt.Fprint(w, `<html><title>`+r.URL.Path+`</title></html>`)
		default:
			http.NotFound(w, r)
		}
	}))
	h.proxy = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !r.URL.IsAbs() { // a CONNECT or a request that is not a proxy request
			http.Error(w, "not a proxy request", http.StatusBadGateway)
			return
		}
		h.proxied.Add(1)
		out := r.Clone(r.Context())
		out.RequestURI = ""
		resp, err := (&http.Transport{}).RoundTrip(out)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		for k, vs := range resp.Header {
			w.Header()[k] = vs
		}
		w.WriteHeader(resp.StatusCode)
		buf := make([]byte, 32<<10)
		for {
			n, err := resp.Body.Read(buf)
			w.Write(buf[:n])
			if err != nil {
				return
			}
		}
	}))
	t.Cleanup(func() { h.proxy.Close(); h.target.Close(); fetch.Reset() })
	return h
}

func (h *egressHarness) asked(path string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, p := range h.seen {
		if p == path || strings.HasPrefix(p, path) {
			return true
		}
	}
	return false
}

// ledgerCounts is what the ledger lists, by class and kind.
type ledgerCounts struct {
	byClassKind map[string]int
	sealed      bool
}

func (c ledgerCounts) n(class, kind string) int { return c.byClassKind[class+"/"+kind] }

func (c ledgerCounts) class(class string) int {
	n := 0
	for k, v := range c.byClassKind {
		if strings.HasPrefix(k, class+"/") {
			n += v
		}
	}
	return n
}

func (h *egressHarness) counts() ledgerCounts {
	h.t.Helper()
	c := ledgerCounts{byClassKind: map[string]int{}}
	err := ledger.Read(h.ledger, func(e ledger.Entry) error {
		class := e.Class
		if class == "" {
			class = ledger.ClassTarget
		}
		c.byClassKind[class+"/"+e.Kind]++
		return nil
	})
	if err != nil {
		h.t.Fatalf("the ledger %s: %v", h.ledger, err)
	}
	chk, err := ledger.Verify(h.ledger)
	if err != nil || chk.Unsealed != 0 || chk.Seals == 0 {
		h.t.Fatalf("the ledger is not intact and sealed: %+v %v", chk, err)
	}
	c.sealed = true
	return c
}

// run runs a command in the process and gives its summary and exit code.
func (h *egressHarness) run(args ...string) (report, int) {
	h.t.Helper()
	out, errOut, code := cli(h.t, args...)
	_ = out
	return lastReport(h.t, errOut), code
}

// reconcile is the contract for a command that asks targets over HTTP,
// through the proxy: server, proxy, ledger and summary are one number.
func (h *egressHarness) reconcile(rep report) int64 {
	h.t.Helper()
	got := h.proxied.Load()
	if got == 0 {
		h.t.Fatalf("nothing went through the proxy: the command sent nothing, or sent it round the proxy")
	}
	if h.served.Load() != got {
		h.t.Errorf("the server answered %d requests, the proxy passed %d: a request went round the proxy (or was lost)", h.served.Load(), got)
	}
	c := h.counts()
	if n := int64(c.n("target", "http")); n != got {
		h.t.Errorf("the ledger lists %d target requests, the proxy passed %d: %v", n, got, c.byClassKind)
	}
	if rep.Requests != got {
		h.t.Errorf("the summary says %d requests, the proxy passed %d", rep.Requests, got)
	}
	for _, other := range []string{"source", "dns"} {
		if n := c.class(other); n != 0 {
			h.t.Errorf("%d %s lines in a run that asked no source and no resolver: %v", n, other, c.byClassKind)
		}
	}
	return got
}

// egressEntry is how one command meets the contract.
type egressEntry struct {
	// sends: "direct" has its own case; "delegates" sends only through the
	// command named in via; "silent" opens no connection.
	sends string
	via   string
	why   string
	run   func(t *testing.T, h *egressHarness)
}

var egressContract = map[string]egressEntry{
	"run": {sends: "direct", run: func(t *testing.T, h *egressHarness) {
		rep, code := h.run("run", "-url", h.target.URL+"/", "-proxy", h.proxy.URL, "-ledger", h.ledger, "-db", filepath.Join(t.TempDir(), "run.db"), "-json")
		if code != exitOK && code != exitPartial {
			t.Fatalf("exit %d: %+v", code, rep)
		}
		h.reconcile(rep)
	}},
	"probe": {sends: "direct", run: func(t *testing.T, h *egressHarness) {
		rep, _ := h.run("probe", "-u", h.target.URL+"/", "-proxy", h.proxy.URL, "-ledger", h.ledger, "-json")
		h.reconcile(rep)
	}},
	"crawl": {sends: "direct", run: func(t *testing.T, h *egressHarness) {
		rep, _ := h.run("crawl", "-u", h.target.URL+"/", "-proxy", h.proxy.URL, "-ledger", h.ledger, "-json")
		h.reconcile(rep)
	}},
	"dirs": {sends: "direct", run: func(t *testing.T, h *egressHarness) {
		// dirs has no proxy flag of its own: it is run's -dirs, which has -proxy.
		rep, _ := h.run("run", "-url", h.target.URL+"/", "-dirs", wlist(t, "a", "b", "zz"), "-proxy", h.proxy.URL, "-ledger", h.ledger, "-db", filepath.Join(t.TempDir(), "dirs.db"), "-json")
		h.reconcile(rep)
	}},
	"fuzz": {sends: "direct", run: func(t *testing.T, h *egressHarness) {
		rep, _ := h.run("fuzz", "-u", h.target.URL+"/FUZZ", "-w", wlist(t, "a", "b", "zz", "q"), "-x", h.proxy.URL, "-ledger", h.ledger, "-allow", "127.0.0.1", "-json")
		if got := h.reconcile(rep); got != 4 {
			t.Errorf("%d requests for 4 words", got)
		}
		// The policy the run built holds a request that names another host, by
		// its Host header or its SNI, before it leaves: nothing more arrives.
		before := h.proxied.Load()
		for _, hdr := range [][2]string{{"Host", "secret.lab"}, {"X-Forwarded-Host", "secret.lab"}} {
			req, _ := http.NewRequest("GET", h.target.URL+"/", nil)
			if hdr[0] == "Host" {
				req.Host = hdr[1]
			} else {
				req.Header.Set(hdr[0], hdr[1])
			}
			if _, err := egress.TargetClient(egress.TargetOptions{Proxy: mustURL(t, h.proxy.URL)}).Do(req); err == nil || !strings.Contains(err.Error(), neterr.ErrOutOfScope.Error()) {
				t.Errorf("%s: %s was not refused: %v", hdr[0], hdr[1], err)
			}
		}
		if h.proxied.Load() != before {
			t.Errorf("a request with a host outside the scope reached the proxy")
		}
	}},
	"params": {sends: "direct", run: func(t *testing.T, h *egressHarness) {
		rep, _ := h.run("params", "-u", h.target.URL+"/a", "-proxy", h.proxy.URL, "-ledger", h.ledger, "-json")
		h.reconcile(rep)
	}},
	"dns": {sends: "direct", run: func(t *testing.T, h *egressHarness) {
		var asked atomic.Int64
		addr := serveCountingZone(t, &asked, map[string]string{"app.example.test": "192.0.2.7"})
		_, errOut, code := cli(t, "dns", "-d", "app.example.test", "-r", addr, "-ledger", h.ledger, "-json")
		rep := lastReport(t, errOut)
		if code != exitOK || asked.Load() == 0 {
			t.Fatalf("exit %d, the resolver was asked %d times: %+v", code, asked.Load(), rep)
		}
		c := h.counts()
		if int64(c.n("dns", "dns")) != asked.Load() {
			t.Errorf("the ledger lists %d queries, the resolver was asked %d times", c.n("dns", "dns"), asked.Load())
		}
		if c.class("target") != 0 || c.class("source") != 0 {
			t.Errorf("a dns command sent to a target or a source: %v", c.byClassKind)
		}
	}},
	"urls": {sends: "direct", run: func(t *testing.T, h *egressHarness) {
		flags, asked := archiveMirror(t)
		db := filepath.Join(t.TempDir(), "urls.db")
		h.ledger = db + ".ledger.jsonl" // a workspace keeps its ledger next to it
		args := append([]string{"urls", "-d", "example.org", "-silent", "-urls-pause", "0", "-proxy", h.proxy.URL, "-db", db}, flags...)
		if _, _, code := cli(t, args...); code != exitOK && code != exitPartial {
			t.Fatalf("exit %d", code)
		}
		got := int64(len(asked()))
		c := h.counts()
		if got == 0 || h.proxied.Load() != got || int64(c.n("source", "http")) != got {
			t.Errorf("the archives were asked %d times, the proxy passed %d, the ledger lists %d: %v", got, h.proxied.Load(), c.n("source", "http"), c.byClassKind)
		}
		if c.class("target") != 0 {
			t.Errorf("an archive request is listed as a target's: %v", c.byClassKind)
		}
	}},
	"ports": {sends: "direct", run: func(t *testing.T, h *egressHarness) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		var accepted atomic.Int64
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				accepted.Add(1)
				c.Close()
			}
		}()
		port := fmt.Sprint(ln.Addr().(*net.TCPAddr).Port)
		_, errOut, code := cli(t, "ports", "-host", "127.0.0.1", "-p", port, "-detect", "none", "-ledger", h.ledger, "-json")
		rep := lastReport(t, errOut)
		if code != exitOK || accepted.Load() == 0 {
			t.Fatalf("exit %d, %d connections: %+v", code, accepted.Load(), rep)
		}
		c := h.counts()
		if int64(c.n("target", "tcp")) != accepted.Load() || rep.Requests != accepted.Load() {
			t.Errorf("the listener accepted %d connections, the ledger lists %d, the summary says %d", accepted.Load(), c.n("target", "tcp"), rep.Requests)
		}
	}},
	"shots": {sends: "direct", run: func(t *testing.T, h *egressHarness) {
		if _, err := browser.Find(); err != nil {
			t.Skip(err)
		}
		db := filepath.Join(t.TempDir(), "s.db")
		h.ledger = db + ".ledger.jsonl"
		// Chrome's own connections go through the egress guard to the proxy
		// given: what it sent, the proxy passed, the target answered and the
		// ledger lists as chrome lines.
		_, errOut, code := cli(t, "shots", "-u", h.target.URL+"/", "-dir", filepath.Join(t.TempDir(), "shots"), "-db", db, "-chrome-proxy", h.proxy.URL, "-proxy", h.proxy.URL, "-json")
		rep := lastReport(t, errOut)
		if code != exitOK && code != exitPartial {
			t.Skipf("Chrome did not run here: exit %d %v", code, rep.Notes)
		}
		got := h.proxied.Load()
		c := h.counts()
		if got == 0 || h.served.Load() != got || int64(c.n("target", "chrome")+c.n("target", "http")) != got || rep.Requests != got {
			t.Errorf("the proxy passed %d, the target answered %d, the ledger lists %v, the summary says %d", got, h.served.Load(), c.byClassKind, rep.Requests)
		}
	}},
	"plan": {sends: "silent", why: "lists what a run would send without sending it", run: func(t *testing.T, h *egressHarness) {
		_, _, code := cli(t, "plan", "-url", h.target.URL+"/")
		if code != exitOK || h.served.Load() != 0 || h.proxied.Load() != 0 {
			t.Errorf("plan: exit %d, the target was asked %d times", code, h.served.Load())
		}
	}},
	"scope":   {sends: "delegates", via: "run", why: "reads a file; only -scope PLATFORM asks the platform, through egress.SourceClient like every source (rules_test.go, scopefile_test)"},
	"roles":   {sends: "delegates", via: "run", why: "runs `run` once per role through fetch.Client (target clients) and replays through the same; its own ledger is roles.ledger.jsonl"},
	"report":  {sends: "silent", why: "writes reports from the evidence of a roles run"},
	"subs":    {sends: "delegates", via: "dns", why: "passive sources are source clients (subcol tests), resolving goes through the dns pool"},
	"asn":     {sends: "delegates", via: "urls", why: "RIPEstat is a source client, like the archives of urls"},
	"notify":  {sends: "delegates", via: "urls", why: "a notification is a source request (notify tests); the command has no ledger of its own"},
	"query":   {sends: "silent", why: "reads a workspace"},
	"show":    {sends: "silent", why: "reads a workspace"},
	"gallery": {sends: "silent", why: "serves a workspace to the user's own browser; no outbound connection"},
	"hunt":    {sends: "silent", why: "reads a workspace"},
	"watch":   {sends: "delegates", via: "run", why: "runs `run` again on a schedule and notifies through source clients"},
	"new":     {sends: "silent", why: "reads a workspace"},
	"diff":    {sends: "silent", why: "reads workspaces"},
	"export":  {sends: "silent", why: "reads a workspace"},
	"ingest":  {sends: "silent", why: "reads files"},
	"ledger":  {sends: "silent", why: "reads a ledger"},
	"resume":  {sends: "delegates", via: "run", why: "continues a run: its requests are the run's own"},
	"mcp":     {sends: "delegates", via: "run", why: "runs the commands as tools in the same process, under the same policy"},
	"worker":  {sends: "delegates", via: "run", why: "does a run's tasks for it; its link to the run is egress.OwnClient"},
	"docs":    {sends: "silent", why: "prints pages"},
	"version": {sends: "silent", why: "prints the version"},
	"help":    {sends: "silent", why: "prints help"},
	"bench":   {sends: "silent", why: "a self-test against a server it starts on loopback"},
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// serveCountingZone is a resolver that answers A questions from names and
// counts every question it gets.
func serveCountingZone(t *testing.T, asked *atomic.Int64, names map[string]string) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		asked.Add(1)
		m := new(dns.Msg)
		m.SetReply(r)
		name := strings.TrimSuffix(strings.ToLower(r.Question[0].Name), ".")
		if ip, ok := names[name]; ok && r.Question[0].Qtype == dns.TypeA {
			rr, _ := dns.NewRR(name + ". 60 IN A " + ip)
			m.Answer = append(m.Answer, rr)
		} else if !ok {
			m.Rcode = dns.RcodeNameError
		}
		_ = w.WriteMsg(m)
	})}
	go srv.ActivateAndServe()
	t.Cleanup(func() { srv.Shutdown() })
	return pc.LocalAddr().String()
}

func TestEgressContractNamesEveryCommand(t *testing.T) {
	known := map[string]bool{}
	for _, c := range commands {
		known[c.name] = true
		e, ok := egressContract[c.name]
		if !ok {
			t.Errorf("the command %q has no entry in egressContract: say how it sends (direct, with a case), delegates, or is silent", c.name)
			continue
		}
		switch e.sends {
		case "direct":
			if e.run == nil {
				t.Errorf("%s: direct, but no case", c.name)
			}
		case "delegates":
			if v, ok := egressContract[e.via]; !ok || v.sends != "direct" || e.why == "" {
				t.Errorf("%s: delegates to %q, which must be a direct entry, and say why", c.name, e.via)
			}
		case "silent":
			if e.why == "" {
				t.Errorf("%s: silent, and says nothing of why", c.name)
			}
		default:
			t.Errorf("%s: sends %q is none of direct, delegates, silent", c.name, e.sends)
		}
	}
	var stale []string
	for name := range egressContract {
		if !known[name] {
			stale = append(stale, name)
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Errorf("egressContract names commands that are not there: %v", stale)
	}
}

func TestEgressContract(t *testing.T) {
	var names []string
	for name, e := range egressContract {
		if e.run != nil {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		e := egressContract[name]
		if e.run == nil {
			continue
		}
		t.Run(name, func(t *testing.T) {
			e.run(t, newEgressHarness(t))
		})
	}
}

// The controls of the policy, measured at the counters: the budget stops at
// its number, -deny-path keeps a path from ever being sent, and a kill file
// that exists before the run sends nothing.
func TestEgressContractControls(t *testing.T) {
	t.Run("budget", func(t *testing.T) {
		h := newEgressHarness(t)
		rep, code := h.run("run", "-url", h.target.URL+"/", "-max-requests", "2", "-proxy", h.proxy.URL, "-ledger", h.ledger, "-db", filepath.Join(t.TempDir(), "b.db"), "-json")
		if code != exitLimit {
			t.Errorf("exit %d, want %d: the budget was spent", code, exitLimit)
		}
		if got := h.reconcile(rep); got != 2 {
			t.Errorf("%d requests went out, the budget was 2", got)
		}
	})
	t.Run("deny-path", func(t *testing.T) {
		h := newEgressHarness(t)
		rep, _ := h.run("run", "-url", h.target.URL+"/", "-deny-path", "^/admin", "-proxy", h.proxy.URL, "-ledger", h.ledger, "-db", filepath.Join(t.TempDir(), "d.db"), "-json")
		h.reconcile(rep)
		if h.asked("/admin") {
			t.Errorf("the target was asked for /admin: %v", h.seen)
		}
		if !h.asked("/a") {
			t.Errorf("the page the rule does not touch was not asked: %v", h.seen)
		}
		listed := false
		for _, s := range rep.Skipped {
			listed = listed || strings.Contains(s.Reason, "-deny-path")
		}
		if !listed {
			t.Errorf("the path kept out is not listed as skipped: %+v", rep.Skipped)
		}
	})
	t.Run("kill file", func(t *testing.T) {
		h := newEgressHarness(t)
		kill := filepath.Join(t.TempDir(), "run.stop")
		if err := os.WriteFile(kill, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		_, code := h.run("run", "-url", h.target.URL+"/", "-kill-file", kill, "-proxy", h.proxy.URL, "-ledger", h.ledger, "-db", filepath.Join(t.TempDir(), "k.db"), "-json")
		if code != exitLimit || h.served.Load() != 0 || h.proxied.Load() != 0 {
			t.Errorf("exit %d, the target was asked %d times, the proxy passed %d", code, h.served.Load(), h.proxied.Load())
		}
	})
	t.Run("scope", func(t *testing.T) {
		h := newEgressHarness(t)
		// A target whose host is outside the scope is not sent to: the command refuses (exit 2).
		_, code := h.run("run", "-url", h.target.URL+"/", "-allow", "example.org", "-proxy", h.proxy.URL, "-ledger", h.ledger, "-db", filepath.Join(t.TempDir(), "s.db"), "-json")
		if code != exitUsage || h.served.Load() != 0 {
			t.Errorf("exit %d, the target was asked %d times", code, h.served.Load())
		}
	})
}
