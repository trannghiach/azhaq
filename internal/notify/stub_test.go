package notify

import (
	"context"
	"crypto/tls"
	"io"
	"mime"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// A recorded request: everything a provider put on the wire.
type seen struct {
	Method, Host, Path, Query string
	Header                    http.Header
	Body                      string
}

// stub is a local server that records each request and answers from reply.
// Requests to port 443 of any name go to its TLS side, every other port to
// its plain side, so a provider that posts to a real host is caught here.
type stub struct {
	mu    sync.Mutex
	reqs  []seen
	reply func(n int, r *seen) (status int, headers map[string]string, body string)
	tls   *httptest.Server
	plain *httptest.Server
}

func newStub(t *testing.T) *stub {
	s := &stub{}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		rec := seen{r.Method, r.Host, r.URL.Path, r.URL.RawQuery, r.Header.Clone(), string(b)}
		s.reqs = append(s.reqs, rec)
		n := len(s.reqs)
		s.mu.Unlock()
		status, hdr, body := http.StatusOK, map[string]string(nil), "ok"
		if s.reply != nil {
			status, hdr, body = s.reply(n, &rec)
		}
		for k, v := range hdr {
			w.Header().Set(k, v)
		}
		w.WriteHeader(status)
		io.WriteString(w, body)
	})
	s.tls = httptest.NewTLSServer(h)
	s.plain = httptest.NewServer(h)
	t.Cleanup(func() { s.tls.Close(); s.plain.Close() })
	return s
}

// client returns a client whose connections all end here.
func (s *stub) client() *Client {
	var d net.Dialer
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			_, port, _ := net.SplitHostPort(addr)
			to := s.plain.Listener.Addr().String()
			if port == "443" {
				to = s.tls.Listener.Addr().String()
			}
			return d.DialContext(ctx, "tcp", to)
		},
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	return &Client{HTTP: &http.Client{Transport: tr, CheckRedirect: sameHost}, Backoff: time.Millisecond, MaxWait: time.Second}
}

func (s *stub) got() []seen {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]seen(nil), s.reqs...)
}

func writeFile(p, s string) error { return os.WriteFile(p, []byte(s), 0o600) }

var mimeDecoder mime.WordDecoder

func bufioCopy(w *strings.Builder, r io.Reader) (int64, error) { return io.Copy(w, r) }
