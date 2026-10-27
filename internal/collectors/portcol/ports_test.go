package portcol

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/trannghiach/azhaq/internal/dnsr"
	"github.com/trannghiach/azhaq/internal/portscan"
	"github.com/trannghiach/azhaq/types"
)

// A name's IPv6 addresses this machine cannot reach are not scanned, and
// the summary says for how many names; a port the probe found HTTP on is
// handed on as http://, without an HTTPS try first.
func TestIPv6NotScannedAndHTTPHint(t *testing.T) {
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer web.Close()
	_, p, _ := net.SplitHostPort(web.Listener.Addr().String())
	port, _ := strconv.Atoi(p)

	pool := dnsr.New(dnsr.Options{Resolvers: []string{"192.0.2.1"}, PerSecond: -1})
	pool.Exchange = func(_ context.Context, q *dns.Msg, _ string) (*dns.Msg, error) {
		m := new(dns.Msg)
		m.SetReply(q)
		name, qt := q.Question[0].Name, q.Question[0].Qtype
		switch {
		case qt == dns.TypeA && name == "dual.example.org.":
			rr, _ := dns.NewRR(name + " 60 IN A 127.0.0.1")
			m.Answer = append(m.Answer, rr)
		case qt == dns.TypeAAAA && (name == "dual.example.org." || name == "six.example.org."):
			rr, _ := dns.NewRR(name + " 60 IN AAAA 2001:db8::1")
			m.Answer = append(m.Answer, rr)
		}
		return m, nil
	}
	c := New(pool, []int{port}, 1000)
	c.Scanner.Banner = 200 * time.Millisecond
	c.IPv6 = func() bool { return false }

	var obs []types.StoredObservation
	emit := func(o types.Observation) error {
		obs = append(obs, types.StoredObservation{Observation: o})
		return nil
	}
	meta, err := c.Run(context.Background(), types.Seed{Type: types.TypeHostname, Keys: map[string]string{"fqdn": "dual.example.org"}}, emit)
	if err != nil || meta.EmitCount != 1 {
		t.Fatalf("dual: %+v %v", meta, err)
	}
	var row struct {
		IP       string          `json:"ip"`
		Open     []int           `json:"open"`
		Services []portscan.Open `json:"services"`
		Unrouted []string        `json:"ipv6_not_scanned"`
	}
	_ = json.Unmarshal(obs[0].Payload, &row)
	if row.IP != "127.0.0.1" || len(row.Open) != 1 || row.Services[0].Service != "http" || len(row.Unrouted) != 1 || row.Unrouted[0] != "2001:db8::1" {
		t.Errorf("dual row %s", obs[0].Payload)
	}
	if len(meta.NextHints) != 1 || meta.NextHints[0].Keys["url"] != "http://dual.example.org:"+p+"/" || meta.NextHints[0].Keys["fallback"] != "" {
		t.Errorf("hints %+v", meta.NextHints)
	}
	if _, err := c.Run(context.Background(), types.Seed{Type: types.TypeHostname, Keys: map[string]string{"fqdn": "six.example.org"}}, emit); err != nil {
		t.Fatal(err)
	}
	if len(obs) != 2 {
		t.Fatalf("an IPv6-only name left no row: %d", len(obs))
	}
	got := Notes(obs)
	if len(got) != 1 || got[0] != "IPv6 addresses of 2 names not scanned: no IPv6 route from this machine" {
		t.Errorf("notes %q", got)
	}
	if n := Notes(obs[:1]); len(n) != 1 || n[0] != "IPv6 addresses of 1 name not scanned: no IPv6 route from this machine" {
		t.Errorf("notes %q", n)
	}
}
