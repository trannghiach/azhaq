package cdnranges

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"

	"github.com/gaissmai/bart"
	"golang.org/x/net/publicsuffix"
)

//go:embed sources_data.json
var sourcesData []byte

// tables are the ranges of one kind, a prefix table per provider, with
// the provider names in the order they are tried.
type tables struct {
	names []string
	by    map[string]*bart.Table[struct{}]
}

type db struct {
	cdn, waf, cloud tables
	suffix          map[string]string // known suffix → provider
}

var load = sync.OnceValue(func() *db {
	var in struct {
		CDN, WAF, Cloud, Common map[string][]string
	}
	if err := json.Unmarshal(sourcesData, &in); err != nil {
		panic("cdnranges: sources_data.json: " + err.Error())
	}
	d := &db{cdn: build(in.CDN), waf: build(in.WAF), cloud: build(in.Cloud), suffix: map[string]string{}}
	sources := make([]string, 0, len(in.Common))
	for s := range in.Common {
		sources = append(sources, s)
	}
	sort.Strings(sources)
	for _, s := range sources {
		for _, suffix := range in.Common[s] {
			if _, taken := d.suffix[suffix]; !taken {
				d.suffix[suffix] = s // upstream's last write wins, in map order
			}
		}
	}
	return d
})

func build(ranges map[string][]string) tables {
	t := tables{by: make(map[string]*bart.Table[struct{}], len(ranges))}
	for provider, cidrs := range ranges {
		tab := new(bart.Table[struct{}])
		for _, c := range cidrs {
			if p, err := netip.ParsePrefix(c); err == nil {
				tab.Insert(p, struct{}{})
			}
		}
		t.by[provider] = tab
		t.names = append(t.names, provider)
	}
	sort.Strings(t.names)
	return t
}

// match is the provider holding the most specific range around ip (the
// first by name among equals): upstream answers with whichever of them
// its map gives first.
func (t tables) match(ip netip.Addr) (bool, string) {
	best, bits := "", -1
	for _, name := range t.names {
		if p, _, ok := t.by[name].LookupPrefixLPM(netip.PrefixFrom(ip, ip.BitLen())); ok && p.Bits() > bits {
			best, bits = name, p.Bits()
		}
	}
	return bits >= 0, best
}

// Check says whether ip is in a CDN, WAF or cloud range, in that order:
// the provider and "cdn", "waf" or "cloud". A nil or malformed address is
// an error.
func Check(ip net.IP) (matched bool, provider, kind string, err error) {
	addr, err := netip.ParseAddr(ip.String())
	if err != nil {
		return false, "", "", err
	}
	d := load()
	if ok, p := d.cdn.match(addr); ok && p != "" {
		return true, p, "cdn", nil
	}
	if ok, p := d.waf.match(addr); ok && p != "" {
		return true, p, "waf", nil
	}
	if ok, p := d.cloud.match(addr); ok && p != "" {
		return true, p, "cloud", nil
	}
	return false, "", "", nil
}

// CheckSuffix says whether one of fqdns ends in a known CDN or WAF suffix
// (its public suffix, or its registered domain).
func CheckSuffix(fqdns ...string) (matched bool, provider, kind string, err error) {
	d := load()
	for _, fqdn := range fqdns {
		tld, sld, err := split(fqdn)
		if err != nil {
			return false, "", "", &parseError{err}
		}
		if p, ok := d.suffix[tld]; ok {
			return true, p, "waf", nil
		}
		if p, ok := d.suffix[sld+"."+tld]; ok {
			return true, p, "waf", nil
		}
	}
	return false, "", "", nil
}

type parseError struct{ err error }

func (e *parseError) Error() string { return "could not parse fqdn: " + e.err.Error() }
func (e *parseError) Unwrap() error { return e.err }

// split is a name's public suffix (private entries such as cloudfront.net
// included, as the list upstream reads) and the label before it.
func split(name string) (suffix, label string, err error) {
	n := strings.ToLower(name)
	switch {
	case n == "":
		return "", "", errors.New("name is blank")
	case n[0] == '.':
		return "", "", fmt.Errorf("name %s starts with a dot", n)
	}
	suffix, _ = publicsuffix.PublicSuffix(n)
	// A name with its root dot is refused, as upstream refuses it.
	if suffix == n || strings.HasSuffix(n, ".") {
		return "", "", fmt.Errorf("%s is a suffix", n)
	}
	left := strings.TrimSuffix(n, "."+suffix)
	if i := strings.LastIndexByte(left, '.'); i >= 0 {
		left = left[i+1:]
	}
	return suffix, left, nil
}
