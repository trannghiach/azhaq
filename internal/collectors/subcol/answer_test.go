package subcol

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// toServer sends every request, whatever its host, to one test server.
type toServer struct{ host string }

func (t toServer) RoundTrip(req *http.Request) (*http.Response, error) {
	r := req.Clone(req.Context())
	r.URL.Scheme, r.URL.Host = "http", t.host
	return http.DefaultTransport.RoundTrip(r)
}

func answering(t *testing.T, body string) *http.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(strings.TrimSpace(body), "{") || strings.HasPrefix(strings.TrimSpace(body), "[") {
			w.Header().Set("Content-Type", "application/json")
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return &http.Client{Transport: toServer{strings.TrimPrefix(srv.URL, "http://")}, Timeout: 10 * time.Second}
}

func sourceNamed(t *testing.T, name string) source {
	t.Helper()
	for _, s := range allSources() {
		if s.name == name {
			return s
		}
	}
	t.Fatalf("no source %s", name)
	return source{}
}

// collectFrom runs one real source against a server that answers body.
func collectFrom(t *testing.T, name, body string) ([]string, error) {
	t.Helper()
	c := New(Options{Client: answering(t, body)})
	ext, err := subscraping.NewSubdomainExtractor("example.org")
	if err != nil {
		t.Fatal(err)
	}
	sess := &subscraping.Session{Extractor: ext, Client: c.opts.Client, RequestLimiter: c.limiter, Timeout: 5}
	ctx := context.WithValue(context.Background(), answerKey{}, &answerLog{})
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	return sourceNamed(t, name).collect(ctx, "example.org", nil, sess)
}

// Every source that asks no key, given a quota page, a JSON error or a
// challenge page with status 200, has failed: it is not "0 names".
func TestKeylessSourcesFailOnAnErrorAnswer(t *testing.T) {
	bodies := map[string]string{
		"quota text":      "API count exceeded - Increase Quota with Membership",
		"search error":    "error check your search parameter",
		"json error":      `{"error":"quota exceeded"}`,
		"json message":    `{"message":"Too Many Requests"}`,
		"challenge":       `<html><head><title>Just a moment...</title></head><body>Checking your browser</body></html>`,
		"html short text": `<html><body><h1>Rate limit exceeded</h1></body></html>`,
	}
	keyless := []string{"anubis", "commoncrawl", "crtname", "digitorus", "hackertarget", "hudsonrock", "rapiddns", "reconcloud",
		"riddler", "scanmalware", "shodanct", "sitedossier", "subdomaincenter", "submd", "thc", "threatcrowd", "threatminer",
		"waybackarchive", "crtsh", "certspotter"}
	for _, name := range keyless {
		for what, body := range bodies {
			names, err := collectFrom(t, name, body)
			if err == nil {
				t.Errorf("%s given %s: no failure (%d names)", name, what, len(names))
			} else if testing.Verbose() {
				t.Logf("%s given %s: %v", name, what, err)
			}
		}
	}
}

// What is not an error is not a failure: an empty list, an empty page, a
// "no records" line are honest zeros.
func TestKeylessSourcesAcceptAnEmptyAnswer(t *testing.T) {
	bodies := map[string]string{
		"empty":      "",
		"no records": "No records found",
		"empty list": "[]",
		"empty page": `<html><head><title>Subdomain Finder: example.org - RapidDNS.io</title></head><body>nothing here</body></html>`,
	}
	for _, name := range []string{"hackertarget", "crtname", "rapiddns", "waybackarchive", "sitedossier", "digitorus", "riddler"} {
		for what, body := range bodies {
			if names, err := collectFrom(t, name, body); err != nil || len(names) != 0 {
				t.Errorf("%s given %s: %v %v", name, what, names, err)
			}
		}
	}
}

// hackertarget's quota page (200, "API count exceeded") is a failed source
// with the page's words, and a run with no other names is degraded, not an
// honest zero.
func TestRunSaysAQuotaPageFailedTheSource(t *testing.T) {
	c := collector(Options{Client: answering(t, "API count exceeded - Increase Quota with Membership"), NoHistory: true}, sourceNamed(t, "hackertarget"))
	payload, meta := run(t, c, context.Background())
	row, _ := payload["sources"].(map[string]any)["hackertarget"].(map[string]any)
	if e, _ := row["error"].(string); !strings.Contains(e, "API count exceeded") {
		t.Errorf("row %v", row)
	}
	if payload["warning"] != "failed: hackertarget" || payload["degraded"] != true || meta.Status != "degraded" {
		t.Errorf("payload %v status %s", payload, meta.Status)
	}
}

// An error page after names were given is said, not hidden, and the names
// stay.
func TestAnErrorPageAfterNamesIsANote(t *testing.T) {
	var n int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		if r.URL.Query().Get("page") == "2" || n > 1 {
			w.Write([]byte(`<html><head><title>Too Many Requests</title></head></html>`))
			return
		}
		w.Write([]byte(`<html><title>Subdomain Finder: example.org</title><table><tr><td>a.example.org</td></tr></table><a class="page-link" href="/subdomain/example.org?page=2">2</a></html>`))
	}))
	defer srv.Close()
	cl := &http.Client{Transport: toServer{strings.TrimPrefix(srv.URL, "http://")}}
	c := collector(Options{Client: cl, NoHistory: true}, sourceNamed(t, "rapiddns"))
	payload, _ := run(t, c, context.Background())
	row, _ := payload["sources"].(map[string]any)["rapiddns"].(map[string]any)
	if row["count"] != 1.0 || row["error"] != nil || !strings.Contains(row["partial"].(string), "Too Many Requests") {
		t.Errorf("row %v", row)
	}
}

// A source still being waited for is named while it is, and not after.
func TestWaitingNamesTheSlowSource(t *testing.T) {
	defer UseTestSources(
		TestSource{Name: "fast", Default: true, Names: []string{"a.example.org"}},
		TestSource{Name: "slow", Default: true, Delay: 400 * time.Millisecond, Names: []string{"b.example.org"}},
	)()
	c := New(Options{NoHistory: true})
	done := make(chan struct{})
	go func() {
		run(t, c, context.Background())
		close(done)
	}()
	var seen []Wait
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline) && len(seen) == 0; time.Sleep(20 * time.Millisecond) {
		seen = Waiting()
	}
	if len(seen) != 1 || seen[0].Source != "slow" || seen[0].Domains != 1 {
		t.Errorf("waiting %v", seen)
	}
	<-done
	if w := Waiting(); len(w) != 0 {
		t.Errorf("still waiting %v after the run", w)
	}
}
