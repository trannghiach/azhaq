// Package asncol starts from networks instead of names: the prefixes an
// autonomous system announces (RIPEstat), the addresses in a prefix, and
// the names those addresses' reverse DNS gives.
package asncol

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/trannghiach/azhaq/catalog"
	"github.com/trannghiach/azhaq/internal/dnsr"
	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/internal/normalize"
	"github.com/trannghiach/azhaq/types"
)

const (
	ASNName    = "azhaq-asn"
	PrefixName = "azhaq-prefix"
	PTRName    = "azhaq-ptr"

	// FromPrefix marks an address that came from expanding a prefix: the
	// HTTP and TLS collectors probe those, not every address a URL implies.
	FromPrefix = "prefix"
)

// ASN lists the prefixes an autonomous system announces.
type ASN struct {
	Client *http.Client
	Base   string // RIPEstat; tests point it elsewhere
}

func NewASN(client *http.Client) *ASN {
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}
	return &ASN{Client: client, Base: "https://stat.ripe.net"}
}

func (a *ASN) Name() string { return ASNName }

// Info: asks RIPEstat only.
func (a *ASN) Info() catalog.Info { return catalog.Info{Kind: catalog.Passive} }

func (a *ASN) Inputs() []types.SeedType { return []types.SeedType{types.TypeASN} }

func (a *ASN) Outputs() []string { return []string{"prefixes"} }

// Asks: RIPEstat, for the prefixes and the holder's name.
func (a *ASN) Asks(seed types.Seed) []string {
	if _, ok := NormalizeASN(seed.Key()); !ok {
		return nil
	}
	return []string{"RIPEstat"}
}

// NormalizeASN reads "AS64500", "as64500" or "64500".
func NormalizeASN(s string) (string, bool) {
	n := strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(s)), "AS")
	if v, err := strconv.ParseUint(n, 10, 32); err != nil || v == 0 {
		return "", false
	}
	return "AS" + n, true
}

func (a *ASN) Run(ctx context.Context, seed types.Seed, emit func(types.Observation) error) (types.RunMeta, error) {
	asn, ok := NormalizeASN(seed.Key())
	if !ok {
		return types.RunMeta{Status: types.StatusError, Error: "not an AS number"}, nil
	}
	prefixes, holder, err := a.announced(ctx, asn)
	row := map[string]any{"asn": asn, "count": len(prefixes), "prefixes": prefixes, "source": "RIPEstat"}
	if holder != "" {
		row["holder"] = holder
	}
	meta := types.RunMeta{Status: types.StatusOK, EmitCount: 1}
	if err != nil {
		row["error"], row["degraded"] = err.Error(), true
		meta.Status = types.StatusDegraded
	}
	raw, _ := json.Marshal(row)
	if err := emit(types.Observation{Collector: ASNName, Source: "stat.ripe.net", Kind: "prefixes", Payload: raw, Confidence: 0.9, ObservedAt: time.Now().UTC()}); err != nil {
		return meta, err
	}
	for _, p := range prefixes {
		meta.NextHints = append(meta.NextHints, types.Seed{Type: types.TypePrefix, Keys: map[string]string{"prefix": p}})
	}
	return meta, nil
}

// Prefixes are the prefixes asn (AS64500) announces, and its holder.
func (a *ASN) Prefixes(ctx context.Context, asn string) ([]string, string, error) {
	n, ok := NormalizeASN(asn)
	if !ok {
		return nil, "", fmt.Errorf("%q is not an AS number", asn)
	}
	return a.announced(ctx, n)
}

func (a *ASN) announced(ctx context.Context, asn string) ([]string, string, error) {
	var data struct {
		Data struct {
			Prefixes []struct {
				Prefix string `json:"prefix"`
			} `json:"prefixes"`
		} `json:"data"`
	}
	if err := a.get(ctx, "/data/announced-prefixes/data.json?resource="+asn+"&sourceapp=azhaq", &data); err != nil {
		return nil, "", err
	}
	var out []string
	seen := map[string]bool{}
	for _, p := range data.Data.Prefixes {
		if pf, err := netip.ParsePrefix(p.Prefix); err == nil && !seen[pf.String()] {
			seen[pf.String()] = true
			out = append(out, pf.Masked().String())
		}
	}
	sort.Strings(out)
	var overview struct {
		Data struct {
			Holder string `json:"holder"`
		} `json:"data"`
	}
	_ = a.get(ctx, "/data/as-overview/data.json?resource="+asn+"&sourceapp=azhaq", &overview)
	return out, overview.Data.Holder, nil
}

func (a *ASN) get(ctx context.Context, path string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(a.Base, "/")+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", fetch.ToolAgent)
	resp, err := a.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("RIPEstat answered %d", resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(v)
}

// Prefix turns a prefix into its addresses, up to a budget for the run.
type Prefix struct {
	MaxIPs int // across the run; default 4096
	// Scanned: the run scans ports, which asks each address of a prefix
	// itself, so the prefix is not expanded here (and no reverse lookup is
	// made for addresses nothing answered on).
	Scanned bool

	mu   sync.Mutex
	used int
}

func (p *Prefix) Name() string { return PrefixName }

// prefixSize is the number of addresses in pf, as a float for IPv6.
func prefixSize(pf netip.Prefix) float64 { return math.Ldexp(1, pf.Addr().BitLen()-pf.Bits()) }

// Info: arithmetic only.
func (p *Prefix) Info() catalog.Info { return catalog.Info{Kind: catalog.Passive} }

// Asks nobody.
func (p *Prefix) Asks(types.Seed) []string { return nil }

func (p *Prefix) Inputs() []types.SeedType { return []types.SeedType{types.TypePrefix} }

func (p *Prefix) Outputs() []string { return []string{"addresses"} }

func (p *Prefix) Run(_ context.Context, seed types.Seed, emit func(types.Observation) error) (types.RunMeta, error) {
	pf, err := netip.ParsePrefix(strings.TrimSpace(seed.Key()))
	if err != nil {
		return types.RunMeta{Status: types.StatusError, Error: err.Error()}, nil
	}
	pf = pf.Masked()
	row := map[string]any{"prefix": pf.String()}
	meta := types.RunMeta{Status: types.StatusOK, EmitCount: 1}
	if p.Scanned {
		row["size"] = prefixSize(pf)
		row["note"] = "its ports are scanned address by address; the ones that answer are followed"
	} else if !pf.Addr().Is4() {
		row["skipped"] = "IPv6 prefixes are not expanded"
	} else {
		size := 1 << (32 - pf.Bits())
		p.mu.Lock()
		budget := p.MaxIPs
		if budget <= 0 {
			budget = 4096
		}
		take := min(size, budget-p.used)
		if take > 0 {
			p.used += take
		}
		p.mu.Unlock()
		row["size"], row["expanded"] = size, max(take, 0)
		if take < size {
			row["warning"] = fmt.Sprintf("expanded %d of %d addresses (-max-ips %d for the run)", max(take, 0), size, budget)
		}
		addr := pf.Addr()
		for i := 0; i < take; i++ {
			meta.NextHints = append(meta.NextHints, types.Seed{Type: types.TypeIPAddress, Keys: map[string]string{"ip": addr.String(), "from": FromPrefix}})
			addr = addr.Next()
		}
	}
	raw, _ := json.Marshal(row)
	return meta, emit(types.Observation{Collector: PrefixName, Source: "prefix", Kind: "addresses", Payload: raw, Confidence: 1, ObservedAt: time.Now().UTC()})
}

// PTR looks up the reverse DNS name of addresses, in batches.
type PTR struct {
	Pool *dnsr.Pool
}

func (r *PTR) Name() string { return PTRName }

// Info: asks DNS resolvers only.
func (r *PTR) Info() catalog.Info { return catalog.Info{Kind: catalog.Passive} }

// Asks no source: an address is looked up on the run's resolvers.
func (r *PTR) Asks(types.Seed) []string { return nil }

func (r *PTR) Inputs() []types.SeedType { return []types.SeedType{types.TypeIPAddress} }

func (r *PTR) Outputs() []string { return []string{"ptr"} }

func (r *PTR) BatchSize() int { return 256 }

// Skip: reverse names matter for addresses found by network, not for the
// address of every URL.
func (r *PTR) Skip(seed types.Seed) bool { return seed.Keys["from"] != FromPrefix }

func (r *PTR) Run(ctx context.Context, seed types.Seed, emit func(types.Observation) error) (types.RunMeta, error) {
	metas, err := r.RunBatch(ctx, []types.Seed{seed}, func(_ types.Seed, o types.Observation) error { return emit(o) })
	if len(metas) == 0 {
		return types.RunMeta{Status: types.StatusOK}, err
	}
	return metas[0], err
}

func (r *PTR) RunBatch(ctx context.Context, seeds []types.Seed, emit func(types.Seed, types.Observation) error) ([]types.RunMeta, error) {
	metas := make([]types.RunMeta, len(seeds))
	var mu sync.Mutex
	sem := make(chan struct{}, 64)
	var wg sync.WaitGroup
	for i, seed := range seeds {
		metas[i] = types.RunMeta{Status: types.StatusOK}
		ip := net.ParseIP(seed.Key())
		if ip == nil || r.Skip(seed) {
			continue
		}
		wg.Add(1)
		go func(i int, seed types.Seed, ip net.IP) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			rev, err := dns.ReverseAddr(ip.String())
			if err != nil {
				return
			}
			// A reverse zone's servers often throttle a whole range asked at
			// once: a failure or SERVFAIL is asked again, through another
			// resolver of the pool.
			var m *dns.Msg
			for try := 0; try < 3; try++ {
				if try > 0 {
					select {
					case <-ctx.Done():
						return
					case <-time.After(time.Duration(try) * 700 * time.Millisecond):
					}
				}
				m, err = r.Pool.Query(ctx, rev, dns.TypePTR)
				if err == nil && m.Rcode != dns.RcodeServerFailure {
					break
				}
			}
			if err != nil || m == nil || m.Rcode != dns.RcodeSuccess {
				return
			}
			var names []string
			for _, rr := range m.Answer {
				if p, ok := rr.(*dns.PTR); ok {
					if n := normalize.Hostname(p.Ptr); n != "" {
						names = append(names, n)
					}
				}
			}
			if len(names) == 0 {
				return
			}
			raw, _ := json.Marshal(map[string]any{"ip": ip.String(), "ptr": names})
			mu.Lock()
			defer mu.Unlock()
			if err := emit(seed, types.Observation{Collector: PTRName, Source: "ptr", Kind: "ptr", Payload: raw, Confidence: 0.9, ObservedAt: time.Now().UTC()}); err != nil {
				return
			}
			metas[i].EmitCount = 1
			for _, n := range names {
				if !Generic(n, ip) {
					metas[i].NextHints = append(metas[i].NextHints, types.Seed{Type: types.TypeHostname, Keys: map[string]string{"fqdn": n, "from": FromPrefix}})
				}
			}
		}(i, seed, ip)
	}
	wg.Wait()
	return metas, ctx.Err()
}

// Generic is true for a reverse name a provider derives from the address
// (ec2-192-0-2-7.compute-1.amazonaws.com, 7.2.0.192.static.example.net):
// it names the network, not a service of the target.
func Generic(name string, ip net.IP) bool {
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	o := []string{strconv.Itoa(int(v4[0])), strconv.Itoa(int(v4[1])), strconv.Itoa(int(v4[2])), strconv.Itoa(int(v4[3]))}
	flat := strings.NewReplacer(".", "-", "_", "-").Replace(name)
	for _, form := range []string{strings.Join(o, "-"), o[3] + "-" + o[2] + "-" + o[1] + "-" + o[0]} {
		if strings.Contains(flat, form) {
			return true
		}
	}
	return normalize.SharedSuffix(name) != ""
}
