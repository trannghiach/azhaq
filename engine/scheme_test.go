package engine_test

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/trannghiach/azhaq/catalog"
	"github.com/trannghiach/azhaq/engine"
	"github.com/trannghiach/azhaq/internal/collectors/httpcol"
	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/store"
	"github.com/trannghiach/azhaq/types"
)

// archived hands on, for https://example.com/, URLs an archive kept over
// plain http.
type archived struct{ urls []string }

func (a *archived) Name() string              { return "test-archive" }
func (a *archived) Info() catalog.Info        { return catalog.Info{Kind: catalog.Passive} }
func (a *archived) Inputs() []types.SeedType  { return []types.SeedType{types.TypeURL} }
func (a *archived) Outputs() []string         { return []string{"url"} }
func (a *archived) Skip(seed types.Seed) bool { return seed.Keys["url"] != "https://example.com/" }
func (a *archived) Run(_ context.Context, _ types.Seed, emit func(types.Observation) error) (types.RunMeta, error) {
	var hints []types.Seed
	for _, u := range a.urls {
		payload, _ := json.Marshal(map[string]string{"url": u, "via": "archive"})
		if err := emit(types.Observation{Collector: "test-archive", Kind: "url", Payload: payload}); err != nil {
			return types.RunMeta{}, err
		}
		hints = append(hints, types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": u}})
	}
	return types.RunMeta{Status: types.StatusOK, NextHints: hints}, nil
}

// twoSchemes maps https://example.com/ (given) with archived http URLs,
// port 443 of example.com answered by a site and port 80 by plain (nil:
// nothing listens). It returns the map's URLs with their coverage and the
// host and path port 80 was asked.
func twoSchemes(t *testing.T, plain http.HandlerFunc, archive ...string) ([]string, []string) {
	fetch.Reset()
	site := http.NewServeMux()
	site.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/", "/login.jsp", "/index.jsp":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><head><title>Altoro Mutual</title></head><body><a href="https://example.com/index.jsp">home</a></body></html>`))
		default:
			http.NotFound(w, r)
		}
	})
	secure := httptest.NewTLSServer(site)
	t.Cleanup(secure.Close)
	var mu sync.Mutex
	var asked []string
	open := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		asked = append(asked, r.Host+r.URL.Path)
		mu.Unlock()
		plain(w, r)
	}))
	t.Cleanup(open.Close)
	if plain == nil {
		open.Close() // nothing listens on port 80
	}
	tr := secure.Client().Transport.(*http.Transport).Clone()
	tr.TLSClientConfig.InsecureSkipVerify = true // the test certificate names example.com only
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		switch {
		case strings.HasSuffix(addr, ":443"):
			addr = secure.Listener.Addr().String()
		case strings.HasSuffix(addr, ":80"):
			addr = open.Listener.Addr().String()
		}
		return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, network, addr)
	}
	client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	cat := catalog.New()
	httpcol.Register(cat, client)
	if len(archive) == 0 {
		archive = []string{"http://example.com/login.jsp", "http://example.com/index.jsp?content=a.htm"}
	}
	cat.MustRegister(&archived{urls: archive})
	eng := &engine.Engine{Cat: cat, Store: st, Client: client}
	seed := types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": "https://example.com/"}}
	if err := eng.RunLocal(context.Background(), []types.Seed{seed}, engine.Budgets{MaxDepth: 2, MaxItems: 32}); err != nil {
		t.Fatal(err)
	}
	ents, _ := st.Entities()
	obs, _ := st.Observations()
	var urls []string
	for _, r := range engine.BuildMap(ents, []types.Seed{seed}, obs, nil, false) {
		if r.Entity.Type == types.TypeURL {
			urls = append(urls, r.Entity.Key+" "+r.Coverage)
		}
	}
	slices.Sort(urls)
	mu.Lock()
	defer mu.Unlock()
	return urls, slices.Clone(asked)
}

func TestHTTPURLsOfAnHTTPSSite(t *testing.T) {
	want := "https://example.com/ visited|https://example.com/index.jsp?content=a.htm visited|https://example.com/login.jsp visited"
	t.Run("redirects to https", func(t *testing.T) {
		urls, asked := twoSchemes(t, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://example.com"+r.URL.RequestURI(), http.StatusMovedPermanently)
		})
		if strings.Join(urls, "|") != want || strings.Join(asked, " ") != "example.com/" {
			t.Errorf("urls %v; port 80 asked %v", urls, asked)
		}
	})
	t.Run("serves the same site", func(t *testing.T) {
		urls, asked := twoSchemes(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><head><title>Altoro Mutual</title></head><body><a href="http://example.com/index.jsp">home</a></body></html>`))
		})
		if strings.Join(urls, "|") != want || strings.Join(asked, " ") != "example.com/" {
			t.Errorf("urls %v; port 80 asked %v", urls, asked)
		}
	})
	t.Run("another name of the domain", func(t *testing.T) {
		urls, asked := twoSchemes(t, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://"+r.Host+r.URL.RequestURI(), http.StatusFound)
		}, "http://www.example.com/login.jsp", "http://other.test/x")
		if !slices.Contains(urls, "https://www.example.com/login.jsp visited") || slices.Contains(urls, "http://www.example.com/login.jsp hint") {
			t.Errorf("www: %v", urls)
		}
		// Not the target's domain: not asked about, requested as found.
		if slices.ContainsFunc(urls, func(u string) bool { return strings.HasPrefix(u, "https://other.test/") }) || !slices.Contains(asked, "www.example.com/") || slices.Contains(asked, "other.test/") || !slices.Contains(asked, "other.test/x") {
			t.Errorf("other.test: %v; port 80 asked %v", urls, asked)
		}
	})
	t.Run("nothing on port 80", func(t *testing.T) {
		if urls, _ := twoSchemes(t, nil); strings.Join(urls, "|") != want {
			t.Errorf("urls %v", urls)
		}
	})
	t.Run("another service", func(t *testing.T) {
		urls, _ := twoSchemes(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><head><title>Legacy intranet</title></head><body>old</body></html>`))
		})
		if !slices.Contains(urls, "http://example.com/login.jsp catchall") || slices.Contains(urls, "https://example.com/login.jsp visited") {
			t.Errorf("an http service of its own lost its URLs: %v", urls)
		}
	})
}
