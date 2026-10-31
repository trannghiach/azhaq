package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/trannghiach/azhaq/internal/browser"
	"github.com/trannghiach/azhaq/types"
)

// shots marks a page that was drawn without the assets of a host outside
// the scope as partial, in the text line, the JSON row and the summary,
// and names the host to allow. The scope is the user's: the exit code stays 0.
func TestShotsMarksOffScopeAssetsPartial(t *testing.T) {
	if _, err := browser.Find(); err != nil {
		t.Skip(err)
	}
	cdn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "x") }))
	defer cdn.Close()
	cu, _ := url.Parse(cdn.URL)
	o := "http://localhost:" + cu.Port()
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><head><title>app</title><link rel=stylesheet href="%s/bootstrap.css"></head><body><h1>hi</h1><img src="%s/logo.png"></body></html>`, o, o)
	}))
	defer site.Close()

	text, errOut, err := captureBoth(t, func() error {
		return cmdShots([]string{"-u", site.URL + "/", "-dir", filepath.Join(t.TempDir(), "s"), "-db", filepath.Join(t.TempDir(), "w.db")})
	})
	if err != nil {
		t.Fatalf("exit %d (%v), want 0: the scope is the user's, not a failure\n%s", exitCode(err), err, errOut)
	}
	if !strings.Contains(text, "  partial (2 off-scope assets blocked: localhost)") {
		t.Errorf("the text line does not say so:\n%s", text)
	}
	if !strings.Contains(errOut, "outside the scope were blocked") || !strings.Contains(errOut, "-allow localhost loads them") {
		t.Errorf("the summary lacks the note:\n%s", errOut)
	}

	js, _, err := captureBoth(t, func() error {
		return cmdShots([]string{"-u", site.URL + "/", "-dir", filepath.Join(t.TempDir(), "s"), "-db", filepath.Join(t.TempDir(), "w.db"), "-json"})
	})
	if err != nil {
		t.Fatalf("exit %d (%v), want 0", exitCode(err), err)
	}
	var row struct {
		Partial      bool
		Blocked      int
		BlockedHosts []string `json:"blocked_hosts"`
	}
	if err := json.Unmarshal([]byte(strings.SplitN(js, "\n", 2)[0]), &row); err != nil || !row.Partial || row.Blocked != 2 || len(row.BlockedHosts) != 1 || row.BlockedHosts[0] != "localhost" {
		t.Errorf("row %+v (%v): %s", row, err, js)
	}
}

// partialShots counts a picture whose own assets did not load, and not one
// that is partial only for the scope.
func TestPartialShotsExitRule(t *testing.T) {
	shot := func(payload string) []types.StoredObservation {
		return []types.StoredObservation{{Observation: types.Observation{Collector: "azhaq-shots", Kind: "screenshot", Payload: json.RawMessage(payload)}}}
	}
	for payload, want := range map[string]bool{
		`{"partial":true,"blocked":3,"blocked_hosts":["cdn.test"]}`: false, // the scope only
		`{"partial":true,"unloaded":2,"resources":9}`:               true,  // its own assets did not load
		`{"partial":true,"unloaded":2,"resources":9,"blocked":3}`:   true,  // both
		`{"partial":true}`:  true, // an older row
		`{"title":"whole"}`: false,
	} {
		if got := partialShots(shot(payload)); got != want {
			t.Errorf("%s: %v, want %v", payload, got, want)
		}
	}
}

// bothSchemes serves one port over plain HTTP and TLS: a connection that
// opens with a TLS handshake goes to the TLS side.
func bothSchemes(t *testing.T, h http.Handler) string {
	t.Helper()
	ts := httptest.NewTLSServer(h)
	cfg := ts.TLS.Clone()
	ts.Close()
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	plain, secure := make(chan net.Conn), make(chan net.Conn)
	done := make(chan struct{})
	go func() {
		for {
			c, err := raw.Accept()
			if err != nil {
				return
			}
			go func() {
				br := bufio.NewReader(c)
				b, err := br.Peek(1)
				if err != nil {
					c.Close()
					return
				}
				pc := &peeked{Conn: c, r: br}
				ch := plain
				if b[0] == 0x16 {
					ch = secure
				}
				select {
				case ch <- pc:
				case <-done:
					c.Close()
				}
			}()
		}
	}()
	go (&http.Server{Handler: h}).Serve(&chanListener{ch: plain, addr: raw.Addr(), done: done})
	go (&http.Server{Handler: h}).Serve(tls.NewListener(&chanListener{ch: secure, addr: raw.Addr(), done: done}, cfg))
	t.Cleanup(func() { close(done); raw.Close() })
	return raw.Addr().String()
}

type peeked struct {
	net.Conn
	r *bufio.Reader
}

func (p *peeked) Read(b []byte) (int, error) { return p.r.Read(b) }

type chanListener struct {
	ch   chan net.Conn
	addr net.Addr
	done chan struct{}
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}
func (l *chanListener) Close() error   { return nil }
func (l *chanListener) Addr() net.Addr { return l.addr }

// A URL with a scheme is one screenshot target: the name in it is not also
// tried on the other scheme, which gave a second row for the same page.
func TestShotsOfAnExplicitURLIsOneRow(t *testing.T) {
	if _, err := browser.Find(); err != nil {
		t.Skip(err)
	}
	addr := bothSchemes(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><head><title>both</title></head><body><h1>hi</h1></body></html>`)
	}))
	_, port, _ := net.SplitHostPort(addr)
	js, errOut, err := captureBoth(t, func() error {
		return cmdShots([]string{"-u", "http://localhost:" + port + "/", "-p", port, "-dir", filepath.Join(t.TempDir(), "s"), "-db", filepath.Join(t.TempDir(), "w.db"), "-json"})
	})
	if err != nil {
		t.Fatalf("exit %d (%v)\n%s", exitCode(err), err, errOut)
	}
	var rows []string
	for _, l := range strings.Split(strings.TrimSpace(js), "\n") {
		var r struct{ URL, Type string }
		if json.Unmarshal([]byte(l), &r) == nil && r.Type == "" && r.URL != "" {
			rows = append(rows, r.URL)
		}
	}
	if len(rows) != 1 || rows[0] != "http://localhost:"+port+"/" {
		t.Errorf("rows %v, want only the URL given", rows)
	}
}

// nmap names a web port by guesses: Juice Shop's is "nessus". shots tries
// every open port of the scan, as gowitness does, and says how many it tried.
func TestShotsNmapTriesAWebPortNamedOddly(t *testing.T) {
	if _, err := browser.Find(); err != nil {
		t.Skip(err)
	}
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><head><title>shop</title></head><body><h1>juice</h1></body></html>`)
	}))
	defer site.Close()
	su, _ := url.Parse(site.URL)
	dead, err := net.Listen("tcp", "127.0.0.1:0") // an open port that speaks nothing
	if err != nil {
		t.Fatal(err)
	}
	defer dead.Close()
	go func() {
		for {
			c, err := dead.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	_, dp, _ := net.SplitHostPort(dead.Addr().String())
	xml := filepath.Join(t.TempDir(), "scan.xml")
	body := fmt.Sprintf(`<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="%s"><state state="open"/><service name="nessus"/></port>
<port protocol="tcp" portid="%s"><state state="open"/><service name="ssh"/></port>
</ports></host></nmaprun>`, su.Port(), dp)
	if err := os.WriteFile(xml, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	text, errOut, err := captureBoth(t, func() error {
		return cmdShots([]string{"-nmap", xml, "-dir", filepath.Join(t.TempDir(), "s"), "-db", filepath.Join(t.TempDir(), "w.db")})
	})
	if exitCode(err) != exitOK {
		t.Fatalf("exit %d, want 0: a port nmap did not name a web service is fan-out\n%s", exitCode(err), errOut)
	}
	if !strings.Contains(text, "http://127.0.0.1:"+su.Port()+"/") {
		t.Errorf("the port nmap called nessus was not shot:\n%s\n%s", text, errOut)
	}
	if !strings.Contains(errOut, "nmap files: 2 ports tried, 1 answered with a page") {
		t.Errorf("the summary does not count the ports:\n%s", errOut)
	}
	// -service narrows to what the user names.
	_, _, err = captureBoth(t, func() error {
		return cmdShots([]string{"-nmap", xml, "-service", "http", "-dir", filepath.Join(t.TempDir(), "s"), "-db", filepath.Join(t.TempDir(), "w.db")})
	})
	if exitCode(err) != exitUsage {
		t.Errorf("-service http names no port of this scan: exit %d, want 2", exitCode(err))
	}
}

// A port nmap named http that does not answer is an ordinary failure:
// exit 3. The same port named ssh is fan-out, listed in the summary.
func TestShotsNmapDeadHTTPPortFailsButGuessedPortDoesNot(t *testing.T) {
	if _, err := browser.Find(); err != nil {
		t.Skip(err)
	}
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, dp, _ := net.SplitHostPort(dead.Addr().String())
	dead.Close() // nothing listens: the port does not answer
	xml := filepath.Join(t.TempDir(), "scan.xml")
	for _, c := range []struct {
		svc  string
		exit int
	}{{"http", exitPartial}, {"ssh", exitOK}} {
		body := fmt.Sprintf(`<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="%s"><state state="open"/><service name="%s"/></port></ports></host></nmaprun>`, dp, c.svc)
		if err := os.WriteFile(xml, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		_, errOut, err := captureBoth(t, func() error {
			return cmdShots([]string{"-nmap", xml, "-dir", filepath.Join(t.TempDir(), "s"), "-db", filepath.Join(t.TempDir(), "w.db"), "-json"})
		})
		rep := lastReport(t, errOut)
		if exitCode(err) != c.exit || rep.Exit != c.exit {
			t.Errorf("port named %s: exit %d, want %d\n%s", c.svc, exitCode(err), c.exit, errOut)
		}
		fan := false
		for _, f := range rep.Failed {
			fan = fan || f.Fanout
		}
		if (c.svc == "ssh") != fan || len(rep.Failed) == 0 || len(rep.Unreachable) > 0 && c.svc == "ssh" {
			t.Errorf("port named %s: failures %+v unreachable %v", c.svc, rep.Failed, rep.Unreachable)
		}
	}
}
