package cdnranges

import (
	"encoding/json"
	"net"
	"net/netip"
	"testing"

	"github.com/projectdiscovery/cdncheck"
)

// The copy gives the answers cdncheck gives, for the addresses and names
// azhaq asks about and for the edges of every range in the data.
func TestParityIPs(t *testing.T) {
	up := cdncheck.New()
	ips := []string{
		"2400:cb00::1", "173.245.48.12", "::1", "127.0.0.1", "49.229.94.1", "10.0.0.1", "192.168.1.1",
		"1.1.1.1", "8.8.8.8", "104.16.0.1", "104.16.132.229", "172.67.0.1", "13.32.0.1", "52.84.1.1",
		"3.5.140.2", "52.95.0.1", "151.101.1.1", "199.232.0.1", "23.235.32.1", "34.64.0.1", "35.190.0.1",
		"20.33.0.1", "40.126.0.1", "13.107.6.152", "104.40.0.1", "198.41.128.1", "192.0.2.1", "203.0.113.9",
		"2606:4700::1", "2a06:98c0::1", "2001:db8::1", "::ffff:104.16.0.1", "255.255.255.255", "0.0.0.0",
	}
	for _, s := range ips {
		ip := net.ParseIP(s)
		wm, wp, wk, werr := up.Check(ip)
		gm, gp, gk, gerr := Check(ip)
		if wm != gm || (wp != gp && !overlaps(netip.MustParseAddr(ip.String()), wk)) || wk != gk || (werr == nil) != (gerr == nil) {
			t.Errorf("%s: upstream %v %q %q %v, copy %v %q %q %v", s, wm, wp, wk, werr, gm, gp, gk, gerr)
		}
	}
	// A nil address is an error in both.
	if _, _, _, err := Check(nil); err == nil {
		t.Error("nil address: no error")
	}
}

func TestParityRangeEdges(t *testing.T) {
	up := cdncheck.New()
	var in struct{ CDN, WAF, Cloud map[string][]string }
	if err := json.Unmarshal(sourcesData, &in); err != nil {
		t.Fatal(err)
	}
	n, skipped := 0, 0
	for _, kind := range []map[string][]string{in.CDN, in.WAF, in.Cloud} {
		for _, cidrs := range kind {
			for _, c := range cidrs {
				p, err := netip.ParsePrefix(c)
				if err != nil {
					continue
				}
				p = p.Masked()
				first := p.Addr()
				last := lastAddr(p)
				for _, a := range []netip.Addr{first, last, first.Prev(), last.Next()} {
					if !a.IsValid() {
						continue
					}
					ip := net.IP(a.AsSlice())
					wm, wp, wk, _ := up.Check(ip)
					gm, gp, gk, _ := Check(ip)
					n++
					// An address in two providers of one kind has no single
					// upstream answer (it walks a map): only its kind must agree.
					if wm != gm || wk != gk || (wp != gp && !overlaps(a, wk)) {
						t.Fatalf("%s: upstream %v %q %q, copy %v %q %q", a, wm, wp, wk, gm, gp, gk)
					}
					if wp != gp {
						skipped++
					}
				}
			}
		}
	}
	t.Logf("%d addresses compared, %d in more than one provider of a kind", n, skipped)
}

// overlaps says a is in the ranges of two providers of kind.
func overlaps(a netip.Addr, kind string) bool {
	d := load()
	tab := map[string]tables{"cdn": d.cdn, "waf": d.waf, "cloud": d.cloud}[kind]
	hits := 0
	for _, name := range tab.names {
		if _, ok := tab.by[name].Lookup(a); ok {
			hits++
		}
	}
	return hits > 1
}

func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Addr().AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 1 << (7 - i%8)
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

func TestParityNames(t *testing.T) {
	up := cdncheck.New()
	cases := [][]string{
		{"d111111abcdef8.cloudfront.net"},
		{"foo.akamaiedge.net"},
		{"e1234.a.akamaiedge.net."},
		{"x.edgekey.net"},
		{"www.example.com"},
		{"example.com"},
		{"foo.bar.cloudflare.com"},
		{"abc.impervadns.net"},
		{"a.fastly.net"},
		{"s3.amazonaws.com"},
		{"co.uk"},
		{"com"},
		{""},
		{"localhost"},
		{"www.example.com", "x.fastly.net"},
		{"www.example.com", "y.example.org"},
		{"foo.wsglb0.com"},
		{"a.b.cdn.jiashule.com"},
		{"UPPER.CLOUDFRONT.NET"},
		{"foo.edgecastcdn.net"},
	}
	for _, c := range cases {
		wm, wp, wk, werr := up.CheckSuffix(c...)
		gm, gp, gk, gerr := CheckSuffix(c...)
		if wm != gm || wp != gp || wk != gk || (werr == nil) != (gerr == nil) || (werr != nil && werr.Error() != gerr.Error()) {
			t.Errorf("%v: upstream %v %q %q %v, copy %v %q %q %v", c, wm, wp, wk, werr, gm, gp, gk, gerr)
		}
	}
}

// edgesuite.net is listed under akamai and edgecast: upstream answers with
// either, by map order; the copy always names akamai.
func TestSuffixInTwoSources(t *testing.T) {
	for i := 0; i < 5; i++ {
		if _, p, _, _ := CheckSuffix("bar.edgesuite.net"); p != "akamai" {
			t.Fatalf("got %q", p)
		}
	}
}

func TestMostSpecificRange(t *testing.T) {
	// azure holds 40.126.0.0/26 inside the /18 that office365 also lists.
	for i := 0; i < 5; i++ {
		if _, p, _, _ := Check(net.ParseIP("40.126.0.1")); p != "azure" {
			t.Fatalf("got %q", p)
		}
	}
}
