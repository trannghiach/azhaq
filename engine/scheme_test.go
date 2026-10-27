package engine_test

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
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

// altoro is the https site of twoSchemes.
func altoro(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/", "/login.jsp", "/index.jsp":
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><head><title>Altoro Mutual</title></head><body><a href="https://example.com/index.jsp">home</a></body></html>`))
	default:
		http.NotFound(w, r)
	}
}

// twoSchemes maps https://example.com/ (given) with archived http URLs,
// port 443 of example.com answered by a site and port 80 by plain (nil:
// nothing listens). It returns the map's URLs with their coverage and the
// host and path port 80 was asked.
func twoSchemes(t *testing.T, plain http.HandlerFunc, archive ...string) ([]string, []string) {
	if len(archive) == 0 {
		archive = []string{"http://example.com/login.jsp", "http://example.com/index.jsp?content=a.htm"}
	}
	return onPort80(t, altoro, plain, nil, archive)
}

// onPort80 maps with secure on port 443 and plain on port 80 (nil:
// nothing listens), and returns the map's URLs and what port 80 was asked.
func onPort80(t *testing.T, secure, plain http.HandlerFunc, tune func(*http.Transport), archive []string) ([]string, []string) {
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
	urls := mapSchemes(t, schemeSetup{secure: secure, plain: open.Listener.Addr().String(), tune: tune, archive: archive})
	mu.Lock()
	defer mu.Unlock()
	return urls, slices.Clone(asked)
}

// schemeSetup is what answers for example.com: secure on port 443, the
// listener at the address plain on port 80. dial80, when set, replaces
// the connect to port 80; tune changes the client's transport.
type schemeSetup struct {
	secure  http.Handler
	plain   string
	dial80  func(ctx context.Context, network, addr string) (net.Conn, error)
	tune    func(*http.Transport)
	archive []string
}

// mapSchemes maps https://example.com/ (given) with the archived http
// URLs of s, and returns the map's URLs with their coverage.
func mapSchemes(t *testing.T, s schemeSetup) []string {
	t.Helper()
	fetch.Reset()
	secure := httptest.NewTLSServer(s.secure)
	t.Cleanup(secure.Close)
	tr := secure.Client().Transport.(*http.Transport).Clone()
	tr.TLSClientConfig.InsecureSkipVerify = true // the test certificate names example.com only
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		switch {
		case strings.HasSuffix(addr, ":443"):
			addr = secure.Listener.Addr().String()
		case strings.HasSuffix(addr, ":80") && s.dial80 != nil:
			return s.dial80(ctx, network, addr)
		case strings.HasSuffix(addr, ":80"):
			addr = s.plain
		}
		return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, network, addr)
	}
	if s.tune != nil {
		s.tune(tr)
	}
	client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	cat := catalog.New()
	httpcol.Register(cat, client)
	cat.MustRegister(&archived{urls: s.archive})
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
	return urls
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

// Both front pages send the visitor to /login: port 80 is another
// application (a legacy portal) with pages of its own, or the same site.
func TestHTTPSiteBehindALoginRedirect(t *testing.T) {
	shop := func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			http.Redirect(w, r, "/login", http.StatusFound)
		case "/login":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><head><title>Shop</title></head><body><form action="/login" method="post">shop login</form></body></html>`))
		default:
			http.NotFound(w, r)
		}
	}
	archive := []string{"http://example.com/legacy/report.jsp"}
	t.Run("another application", func(t *testing.T) {
		urls, asked := onPort80(t, shop, func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/":
				http.Redirect(w, r, "/login", http.StatusFound)
			case "/login", "/legacy/report.jsp":
				w.Header().Set("Content-Type", "text/html")
				_, _ = w.Write([]byte(`<html><head><title>Legacy portal</title></head><body>legacy ` + r.URL.Path + `</body></html>`))
			default:
				http.NotFound(w, r)
			}
		}, nil, archive)
		if !slices.Contains(asked, "example.com/legacy/report.jsp") || !slices.Contains(urls, "http://example.com/legacy/report.jsp visited") {
			t.Errorf("the http application's page was not asked on port 80: %v; port 80 asked %v", urls, asked)
		}
	})
	t.Run("the same site", func(t *testing.T) {
		urls, asked := onPort80(t, shop, shop, nil, archive)
		if !slices.Contains(urls, "https://example.com/legacy/report.jsp gone") || slices.Contains(asked, "example.com/legacy/report.jsp") {
			t.Errorf("urls %v; port 80 asked %v", urls, asked)
		}
	})
}

// Something listens on port 80 but its answer to / is slow or not HTTP:
// the http URLs stay http, and are asked there.
func TestHTTPSlowOrOddOnPort80(t *testing.T) {
	archive := []string{"http://example.com/legacy/report.jsp"}
	onHTTPS := func(u string) bool { return strings.HasPrefix(u, "https://example.com/legacy/") }
	t.Run("headers time out", func(t *testing.T) {
		urls, asked := onPort80(t, altoro, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/" {
				time.Sleep(600 * time.Millisecond)
			}
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><head><title>Legacy</title></head><body>legacy</body></html>`))
		}, func(tr *http.Transport) { tr.ResponseHeaderTimeout = 200 * time.Millisecond }, archive)
		if !slices.Contains(asked, "example.com/legacy/report.jsp") || slices.ContainsFunc(urls, onHTTPS) {
			t.Errorf("a slow service on port 80 was taken for the https site: %v; port 80 asked %v", urls, asked)
		}
	})
	t.Run("not HTTP", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		var mu sync.Mutex
		var asked []string
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go func(c net.Conn) {
					defer c.Close()
					req, err := http.ReadRequest(bufio.NewReader(c))
					if err != nil {
						return
					}
					mu.Lock()
					asked = append(asked, req.URL.Path)
					mu.Unlock()
					if req.URL.Path == "/" {
						_, _ = c.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n"))
						return
					}
					body := "<html><head><title>Legacy</title></head><body>legacy</body></html>"
					_, _ = fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
				}(c)
			}
		}()
		urls := mapSchemes(t, schemeSetup{secure: http.HandlerFunc(altoro), plain: ln.Addr().String(), archive: archive})
		mu.Lock()
		defer mu.Unlock()
		if !slices.Contains(asked, "/legacy/report.jsp") || slices.ContainsFunc(urls, onHTTPS) {
			t.Errorf("an odd service on port 80 was taken for the https site: %v; port 80 asked %v", urls, asked)
		}
	})
}

// Connects to port 80 that time out: twice is a port that drops them,
// once is the network.
func TestHTTPConnectTimesOut(t *testing.T) {
	timedOut := &net.OpError{Op: "dial", Net: "tcp", Err: os.ErrDeadlineExceeded}
	t.Run("twice", func(t *testing.T) {
		var dials atomic.Int32
		urls := mapSchemes(t, schemeSetup{secure: http.HandlerFunc(altoro), archive: []string{"http://example.com/login.jsp"},
			dial80: func(context.Context, string, string) (net.Conn, error) {
				dials.Add(1)
				return nil, timedOut
			}})
		if strings.Join(urls, "|") != "https://example.com/ visited|https://example.com/login.jsp visited" || dials.Load() != 2 {
			t.Errorf("urls %v; %d connects to port 80", urls, dials.Load())
		}
	})
	t.Run("once", func(t *testing.T) {
		legacy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/" && r.URL.Path != "/login.jsp" {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><head><title>Legacy</title></head><body>legacy ` + r.URL.Path + `</body></html>`))
		}))
		t.Cleanup(legacy.Close)
		var dials atomic.Int32
		urls := mapSchemes(t, schemeSetup{secure: http.HandlerFunc(altoro), archive: []string{"http://example.com/login.jsp"},
			dial80: func(ctx context.Context, network, _ string) (net.Conn, error) {
				if dials.Add(1) == 1 {
					return nil, timedOut
				}
				return (&net.Dialer{}).DialContext(ctx, network, legacy.Listener.Addr().String())
			}})
		if !slices.Contains(urls, "http://example.com/login.jsp visited") {
			t.Errorf("the service that answered the second connect lost its URLs: %v", urls)
		}
	})
}
