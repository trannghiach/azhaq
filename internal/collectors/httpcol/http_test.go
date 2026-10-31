package httpcol

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/internal/fingerprint"
	"github.com/trannghiach/azhaq/types"
)

var icon, _ = base64.StdEncoding.DecodeString("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGNgYGD4DwABBAEAwS2OUAAAAABJRU5ErkJggg==")

func TestTargets(t *testing.T) {
	c := &Collector{}
	host := types.Seed{Type: types.TypeHostname, Keys: map[string]string{"fqdn": "app.example.org"}}
	if got := c.targets(host); !reflect.DeepEqual(got, [][]string{{"https://app.example.org/", "http://app.example.org/"}}) {
		t.Errorf("default %v", got)
	}
	c.Ports = []int{80, 443, 8443}
	want := [][]string{
		{"http://app.example.org/", "https://app.example.org:80/"},
		{"https://app.example.org/", "http://app.example.org:443/"},
		{"https://app.example.org:8443/", "http://app.example.org:8443/"},
	}
	if got := c.targets(host); !reflect.DeepEqual(got, want) {
		t.Errorf("ports %v", got)
	}
	for in, want := range map[string][]string{
		"https://10.0.0.5/":      {"https://10.0.0.5/", "http://10.0.0.5/"},
		"https://10.0.0.5:8443/": {"https://10.0.0.5:8443/", "http://10.0.0.5:8443/"},
		"http://10.0.0.5:8080/":  {"http://10.0.0.5:8080/"},
	} {
		seed := types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": in, FallbackKey: "http"}}
		if got := c.targets(seed); !reflect.DeepEqual(got, [][]string{want}) {
			t.Errorf("%s: %v", in, got)
		}
	}
}

func payloadOf(t *testing.T, c *Collector, seed types.Seed) map[string]any {
	t.Helper()
	var out map[string]any
	meta, err := c.Run(context.Background(), seed, func(o types.Observation) error {
		return json.Unmarshal(o.Payload, &out)
	})
	if err != nil || meta.EmitCount != 1 {
		t.Fatalf("meta %+v err %v", meta, err)
	}
	return out
}

func TestProbeFields(t *testing.T) {
	fetch.Reset()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			http.Redirect(w, r, "/home/", http.StatusFound)
		case "/home/":
			w.Header().Set("Server", "nginx/1.18.0")
			_, _ = w.Write([]byte("<html><head><title>Tom &amp; Jerry</title><link rel=\"icon\" href=\"/static/i.png\"></head>\n<body>a b</body></html>"))
		case "/static/i.png":
			_, _ = w.Write(icon)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c := New(srv.Client())
	p := payloadOf(t, c, types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/"}})
	if p["status"].(float64) != 302 || p["final_status"].(float64) != 200 || p["title"] != "Tom & Jerry" {
		t.Errorf("status/title %v %v %q", p["status"], p["final_status"], p["title"])
	}
	if tech, _ := p["tech"].([]any); len(tech) == 0 || tech[0] != "Nginx:1.18.0" {
		t.Errorf("tech %v", p["tech"])
	}
	want, _ := fingerprint.Favicon(icon)
	if p["favicon"] != want || !strings.HasSuffix(p["favicon_url"].(string), "/static/i.png") {
		t.Errorf("favicon %v from %v, want %s", p["favicon"], p["favicon_url"], want)
	}
	if p["ip"] != "127.0.0.1" || p["lines"].(float64) != 2 || p["length"].(float64) < 50 {
		t.Errorf("ip %v lines %v length %v", p["ip"], p["lines"], p["length"])
	}
}

func TestFallbackToHTTP(t *testing.T) {
	fetch.Reset()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<title>plain</title>"))
	}))
	defer srv.Close()
	hostport := strings.TrimPrefix(srv.URL, "http://")
	c := New(srv.Client())
	c.NoFavicon = true
	p := payloadOf(t, c, types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": "https://" + hostport + "/", FallbackKey: "http"}})
	if p["url"] != "http://"+hostport+"/" || p["title"] != "plain" {
		t.Errorf("payload %v", p)
	}
}

func TestRedirectToAnotherSiteIsNotFollowed(t *testing.T) {
	fetch.Reset()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redirect":
			http.Redirect(w, r, r.URL.Query().Get("to"), http.StatusFound)
		default:
			w.Write([]byte("<title>t</title>"))
		}
	}))
	defer srv.Close()
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("<title>other</title>")) }))
	defer other.Close()
	elsewhere := strings.Replace(other.URL, "127.0.0.1", "localhost", 1) + "/elsewhere" // another site, still local
	c := New(srv.Client())
	c.NoFavicon = true
	for to, follow := range map[string]bool{"/inside": true, elsewhere: false} {
		var hints []types.Seed
		meta, _ := c.Run(context.Background(), types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/redirect?to=" + to}}, func(types.Observation) error { return nil })
		hints = meta.NextHints
		if (len(hints) > 0) != follow {
			t.Errorf("redirect to %s: hints %v", to, hints)
		}
	}
}

// A 5xx's body that gives something away (an SQL error, a stack trace)
// is noted by kind, with the text that says so; a plain error page is not,
// and a 200 never is.
func TestServerErrorBodyIsNoted(t *testing.T) {
	fetch.Reset()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/sql":
			w.WriteHeader(500)
			_, _ = w.Write([]byte(`{"error":{"message":"SQLITE_ERROR: near \"'\": syntax error"}}`))
		case "/trace":
			w.WriteHeader(500)
			_, _ = w.Write([]byte("<pre>TypeError: x is undefined\n    at Object.f (/app/a.js:1:2)</pre>"))
		case "/plain":
			w.WriteHeader(500)
			_, _ = w.Write([]byte("<html><title>Error</title>Internal Server Error</html>"))
		default:
			_, _ = w.Write([]byte("SQLITE_ERROR in a page that answered 200"))
		}
	}))
	defer srv.Close()
	c := New(srv.Client())
	for path, want := range map[string]string{"/sql": "sql", "/trace": "stack", "/plain": "", "/ok": ""} {
		p := payloadOf(t, c, types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + path}})
		got, _ := p["error_text"].(string)
		if got != want {
			t.Errorf("%s: error_text %q, want %q", path, got, want)
		}
		if want != "" && p["error_sample"] == "" {
			t.Errorf("%s: no sample", path)
		}
	}
}

// A renewed session replaces the headers while requests are described.
func TestDescribeWhileTheSessionIsRenewed(t *testing.T) {
	t.Cleanup(func() { fetch.SetExtra(nil) })
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			fetch.SetExtra(http.Header{"Cookie": {"sid=" + strings.Repeat("x", i%7+1)}})
		}
	}()
	for i := 0; i < 200; i++ {
		describe("http://app.example.org/", "http://app.example.org/", fetch.Result{Status: 200, Body: []byte("x")}, "", false, false)
	}
	close(stop)
	<-done
}
