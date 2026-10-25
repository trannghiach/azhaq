package asncol

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/trannghiach/azhaq/types"
)

func TestASNPrefixes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("resource") != "AS64500" {
			http.Error(w, "no", http.StatusBadRequest)
			return
		}
		switch r.URL.Path {
		case "/data/announced-prefixes/data.json":
			fmt.Fprint(w, `{"data":{"prefixes":[{"prefix":"192.0.2.0/24"},{"prefix":"198.51.100.0/25"},{"prefix":"192.0.2.0/24"},{"prefix":"2001:db8::/32"}]}}`)
		case "/data/as-overview/data.json":
			fmt.Fprint(w, `{"data":{"holder":"EXAMPLE-AS"}}`)
		}
	}))
	defer srv.Close()
	a := NewASN(srv.Client())
	a.Base = srv.URL
	var got map[string]any
	meta, err := a.Run(context.Background(), types.Seed{Type: types.TypeASN, Keys: map[string]string{"asn": "as64500"}}, func(o types.Observation) error {
		return json.Unmarshal(o.Payload, &got)
	})
	if err != nil || got["holder"] != "EXAMPLE-AS" || got["count"].(float64) != 3 || len(meta.NextHints) != 3 {
		t.Fatalf("got %v hints %v err %v", got, meta.NextHints, err)
	}
	if _, ok := NormalizeASN("AS0"); ok {
		t.Error("AS0 accepted")
	}
}

func TestPrefixBudget(t *testing.T) {
	p := &Prefix{MaxIPs: 300}
	hints := 0
	for _, pf := range []string{"192.0.2.0/24", "198.51.100.0/24"} {
		var got map[string]any
		meta, _ := p.Run(context.Background(), types.Seed{Type: types.TypePrefix, Keys: map[string]string{"prefix": pf}}, func(o types.Observation) error {
			return json.Unmarshal(o.Payload, &got)
		})
		hints += len(meta.NextHints)
		if pf == "198.51.100.0/24" && !strings.Contains(fmt.Sprint(got["warning"]), "expanded 44 of 256") {
			t.Errorf("second prefix %v", got)
		}
	}
	if hints != 300 {
		t.Errorf("%d addresses, want the budget of 300", hints)
	}
}

func TestGenericReverseNames(t *testing.T) {
	ip := net.ParseIP("192.0.2.7")
	for name, want := range map[string]bool{
		"ec2-192-0-2-7.compute-1.amazonaws.com": true,
		"7.2.0.192.static.example.net":          true,
		"host-192-0-2-7.isp.example":            true,
		"mail.example.com":                      false,
		"vpn.example.com":                       false,
	} {
		if got := Generic(name, ip); got != want {
			t.Errorf("%s: %v", name, got)
		}
	}
}
