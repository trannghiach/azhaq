package portcol

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"

	"github.com/trannghiach/azhaq/internal/dnsr"
	"github.com/trannghiach/azhaq/internal/portscan"
	"github.com/trannghiach/azhaq/types"
)

func rows(t *testing.T, obs []types.Observation) []map[string]any {
	var out []map[string]any
	for _, o := range obs {
		var m map[string]any
		if err := json.Unmarshal(o.Payload, &m); err != nil {
			t.Fatal(err)
		}
		out = append(out, m)
	}
	return out
}

func serve(t *testing.T, addr string) int {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	return l.Addr().(*net.TCPAddr).Port
}

// A name that CNAMEs to a CDN is asked on four ports by default, on all
// of them with CDNFull, and the row says which.
func TestCDNRuleAndFlag(t *testing.T) {
	port := serve(t, "127.0.0.1:0")
	pool := dnsr.New(dnsr.Options{Resolvers: []string{"192.0.2.1"}, PerSecond: -1})
	pool.Exchange = func(_ context.Context, q *dns.Msg, _ string) (*dns.Msg, error) {
		m := new(dns.Msg)
		m.SetReply(q)
		if q.Question[0].Qtype == dns.TypeA {
			c, _ := dns.NewRR(q.Question[0].Name + " 60 IN CNAME x.cloudfront.net.")
			a, _ := dns.NewRR("x.cloudfront.net. 60 IN A 127.0.0.1")
			m.Answer = append(m.Answer, c, a)
		}
		return m, nil
	}
	for _, full := range []bool{false, true} {
		var asked atomic.Int32
		c := New(pool, []int{port, 1, 2, 3, 4, 5}, 0)
		c.Scanner.Take = func() error { asked.Add(1); return nil }
		c.Scanner.Detect = portscan.DetectNone
		c.IPv6 = func() bool { return false }
		c.CDNFull = full
		var obs []types.Observation
		_, err := c.Run(context.Background(), types.Seed{Type: types.TypeHostname, Keys: map[string]string{"fqdn": "shop.example.org"}}, func(o types.Observation) error { obs = append(obs, o); return nil })
		if err != nil {
			t.Fatal(err)
		}
		r := rows(t, obs)[0]
		wantAsked := 4
		if full {
			wantAsked = 6
		}
		if int(asked.Load()) != wantAsked || r["cdn"] == nil || !strings.Contains(r["note"].(string), map[bool]string{false: "web ports only", true: "in full"}[full]) {
			t.Errorf("full=%v: %d connects, row %v", full, asked.Load(), r)
		}
	}
}

// A range is asked address by address without a name lookup, and the
// addresses that answer are the rows; a range row counts the rest.
func TestRangeScan(t *testing.T) {
	port := serve(t, "127.0.0.2:0")
	pf := netip.MustParsePrefix("127.0.0.0/29")
	var asked atomic.Int32
	c := New(nil, []int{port}, 0)
	c.Scanner.Take = func() error { asked.Add(1); return nil }
	c.Scanner.Detect = portscan.DetectNone
	var obs []types.Observation
	meta, err := c.Run(context.Background(), types.Seed{Type: types.TypePrefix, Keys: map[string]string{"prefix": pf.String()}}, func(o types.Observation) error { obs = append(obs, o); return nil })
	if err != nil || asked.Load() != 8 {
		t.Fatalf("%d connects, %v", asked.Load(), err)
	}
	rs := rows(t, obs)
	if len(rs) != 2 || rs[0]["ip"] != "127.0.0.2" && rs[1]["ip"] != "127.0.0.2" {
		t.Fatalf("rows %v", rs)
	}
	var rng map[string]any
	for _, r := range rs {
		if r["range"] == true {
			rng = r
		}
	}
	if rng == nil || rng["addresses"] != float64(8) || rng["with_open"] != float64(1) {
		t.Errorf("range row %v", rng)
	}
	if meta.EmitCount != 2 {
		t.Errorf("%+v", meta)
	}
}

// -sn: addresses that answer a connect are listed and no port is asked.
func TestDiscoveryOnly(t *testing.T) {
	var asked atomic.Int32
	c := New(nil, []int{9}, 0)
	c.Scanner.Take = func() error { asked.Add(1); return nil }
	c.Discover = DiscoverOnly
	var obs []types.Observation
	_, err := c.Run(context.Background(), types.Seed{Type: types.TypePrefix, Keys: map[string]string{"prefix": "127.0.0.1/32"}}, func(o types.Observation) error { obs = append(obs, o); return nil })
	if err != nil {
		t.Fatal(err)
	}
	var up bool
	for _, r := range rows(t, obs) {
		if r["ip"] == "127.0.0.1" && r["up"] == true && r["scanned"] == float64(0) {
			up = true
		}
	}
	// 127.0.0.1 refuses 80 and 443 here (or accepts): either way it is up.
	if !up || asked.Load() != 2 {
		t.Errorf("up %v, %d connects: %v", up, asked.Load(), rows(t, obs))
	}
}

func TestBlocksSplitBigRanges(t *testing.T) {
	bs, err := Blocks(netip.MustParsePrefix("10.0.0.0/22"))
	if err != nil || len(bs) != 4 || bs[3].String() != "10.0.3.0/24" {
		t.Fatalf("%v %v", bs, err)
	}
	if _, err := Blocks(netip.MustParsePrefix("2001:db8::/64")); err == nil {
		t.Error("an IPv6 /64 was accepted")
	}
	if bs, err := Blocks(netip.MustParsePrefix("2001:db8::/120")); err != nil || len(bs) != 1 {
		t.Errorf("%v %v", bs, err)
	}
}

// An address of a range that answered is not scanned again when its
// seed follows.
func TestRangeAddressNotScannedTwice(t *testing.T) {
	port := serve(t, "127.0.0.2:0")
	var asked atomic.Int32
	c := New(nil, []int{port}, 0)
	c.Scanner.Take = func() error { asked.Add(1); return nil }
	c.Scanner.Detect = portscan.DetectNone
	emit := func(types.Observation) error { return nil }
	meta, err := c.Run(context.Background(), types.Seed{Type: types.TypePrefix, Keys: map[string]string{"prefix": "127.0.0.0/30"}}, emit)
	if err != nil || asked.Load() != 4 {
		t.Fatalf("%d %v", asked.Load(), err)
	}
	var ipSeed *types.Seed
	for i, h := range meta.NextHints {
		if h.Type == types.TypeIPAddress {
			ipSeed = &meta.NextHints[i]
		}
	}
	if ipSeed == nil || ipSeed.Keys["ip"] != "127.0.0.2" {
		t.Fatalf("hints %+v", meta.NextHints)
	}
	if _, err := c.Run(context.Background(), *ipSeed, emit); err != nil || asked.Load() != 4 {
		t.Fatalf("the address was asked again: %d %v", asked.Load(), err)
	}
}
