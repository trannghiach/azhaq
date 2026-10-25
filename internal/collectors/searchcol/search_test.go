package searchcol

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/trannghiach/azhaq/types"
)

func TestEnginesAndKeys(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		switch r.URL.Path {
		case "/shodan/host/search":
			if q.Get("key") != "sk" || q.Get("query") != "hostname:example.com" {
				http.Error(w, `{"error":"bad"}`, http.StatusUnauthorized)
				return
			}
			fmt.Fprint(w, `{"total":2,"matches":[{"ip_str":"192.0.2.10","port":8443,"hostnames":["admin.example.com","cdn.other.net"]},{"ip_str":"192.0.2.11","port":80,"hostnames":[]}]}`)
		case "/api/v1/search/all":
			dec, _ := base64.StdEncoding.DecodeString(q.Get("qbase64"))
			if q.Get("email") != "me@x.test" || string(dec) != `domain="example.com"` {
				fmt.Fprint(w, `{"error":true,"errmsg":"bad key"}`)
				return
			}
			fmt.Fprint(w, `{"error":false,"size":1,"results":[["192.0.2.12","443","https://shop.example.com"]]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	old := Bases
	defer func() { Bases = old }()
	Bases = map[string]string{"shodan": srv.URL, "fofa": srv.URL, "netlas": srv.URL}

	c := New(map[string][]string{"shodan": {"sk"}, "fofa": {"me@x.test:fk"}})
	c.Client = srv.Client()
	var got map[string]any
	meta, err := c.Run(context.Background(), types.Seed{Type: types.TypeDomain, Keys: map[string]string{"domain": "example.com"}}, func(o types.Observation) error {
		return json.Unmarshal(o.Payload, &got)
	})
	if err != nil {
		t.Fatal(err)
	}
	engines := got["engines"].(map[string]any)
	if engines["netlas"].(map[string]any)["skipped"] != "needs a key" {
		t.Errorf("netlas without a key: %v", engines["netlas"])
	}
	hosts := fmt.Sprint(got["hosts"])
	if hosts != "[admin.example.com shop.example.com]" {
		t.Errorf("hosts %s (names outside the domain must not count)", hosts)
	}
	var urls []string
	for _, h := range meta.NextHints {
		if h.Type == types.TypeURL {
			urls = append(urls, h.Keys["url"])
		}
	}
	if j := strings.Join(urls, " "); !strings.Contains(j, "https://192.0.2.10:8443/") || !strings.Contains(j, "http://192.0.2.11/") {
		t.Errorf("service hints %v", urls)
	}
}
