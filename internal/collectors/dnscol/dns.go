package dnscol

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/trannghiach/azhaq/catalog"
	"github.com/trannghiach/azhaq/internal/dnsr"
	"github.com/trannghiach/azhaq/internal/fingerprint"
	"github.com/trannghiach/azhaq/internal/normalize"
	"github.com/trannghiach/azhaq/types"
)

const Name = "azhaq-dns"

// Collector resolves hostnames in batches through a resolver pool and
// drops names that do not resolve or only answer through a wildcard, so
// nothing probes them over HTTP.
type Collector struct {
	Pool    *dnsr.Pool
	Wild    *dnsr.Wildcards
	Workers int
}

// New returns a collector on pool, or on the default resolvers when nil.
func New(pool *dnsr.Pool) *Collector {
	if pool == nil {
		pool = dnsr.New(dnsr.Options{})
	}
	return &Collector{Pool: pool, Wild: dnsr.NewWildcards(pool), Workers: 128}
}

func Register(cat *catalog.Catalog) {
	cat.MustRegister(New(nil))
}

func (c *Collector) Name() string { return Name }

// Info: this collector only asks third parties or DNS resolvers.
func (c *Collector) Info() catalog.Info { return catalog.Info{Kind: catalog.Passive} }

func (c *Collector) Inputs() []types.SeedType { return []types.SeedType{types.TypeHostname} }

func (c *Collector) Outputs() []string { return []string{"dns"} }

// Asks no source: a name is looked up on the run's resolvers.
func (c *Collector) Asks(types.Seed) []string { return nil }

func (c *Collector) BatchSize() int { return 256 }

func (c *Collector) Run(ctx context.Context, seed types.Seed, emit func(types.Observation) error) (types.RunMeta, error) {
	metas, err := c.RunBatch(ctx, []types.Seed{seed}, func(_ types.Seed, o types.Observation) error { return emit(o) })
	if len(metas) == 0 {
		return types.RunMeta{Status: types.StatusOK}, err
	}
	return metas[0], err
}

func (c *Collector) RunBatch(ctx context.Context, seeds []types.Seed, emit func(types.Seed, types.Observation) error) ([]types.RunMeta, error) {
	hosts := make([]string, len(seeds))
	var names []string
	for i, s := range seeds {
		hosts[i] = hostOnly(s.Keys["fqdn"])
		if hosts[i] != "" && net.ParseIP(hosts[i]) == nil {
			names = append(names, hosts[i])
		}
	}
	answers := map[string]dnsr.Answer{}
	for _, a := range c.Pool.ResolveMany(ctx, names, c.Workers) {
		answers[a.Name] = a
	}
	metas := make([]types.RunMeta, len(seeds))
	for i, seed := range seeds {
		host := hosts[i]
		meta := types.RunMeta{Status: types.StatusOK}
		payload := map[string]any{"fqdn": host}
		switch {
		case host == "":
			meta.Status, meta.Error = types.StatusError, "empty host"
			metas[i] = meta
			continue
		case net.ParseIP(host) != nil:
			payload["ips"] = []string{host}
		default:
			c.describe(ctx, host, answers[host], payload, &meta)
		}
		raw, _ := json.Marshal(payload)
		if err := emit(seed, types.Observation{
			Collector: Name, Source: "dns", Kind: "dns",
			Payload: raw, Confidence: 0.95, ObservedAt: time.Now().UTC(),
		}); err != nil {
			return metas, err
		}
		meta.EmitCount = 1
		metas[i] = meta
	}
	return metas, ctx.Err()
}

// describe fills payload and meta from one answer.
func (c *Collector) describe(ctx context.Context, host string, a dnsr.Answer, payload map[string]any, meta *types.RunMeta) {
	payload["result"] = a.Status
	if len(a.CNAME) > 0 {
		payload["cname"] = a.CNAME[0]
		payload["cnames"] = a.CNAME
		if cn := a.CNAME[0]; cn != host && normalize.SameSite(host, cn) {
			meta.NextHints = append(meta.NextHints, types.Seed{Type: types.TypeHostname, Keys: map[string]string{"fqdn": cn}})
		}
	}
	switch a.Status {
	case dnsr.StatusReserved:
		payload["skipped"] = "reserved" // may still be in /etc/hosts: let HTTP try
	case dnsr.StatusFailed:
		payload["error"] = a.Err
		payload["degraded"] = true // a resolver problem, not an answer
	case dnsr.StatusNXDomain:
		payload["error"] = "nxdomain"
		meta.Drop = true
	case dnsr.StatusBroken:
		// Resolvers answered, all alike: the name resolves for nobody.
		payload["error"] = a.Err
		meta.Drop = true
	case dnsr.StatusNoData, dnsr.StatusCNAME:
		meta.Drop = true
	case dnsr.StatusOK:
		payload["ips"] = a.IPs()
		if name, kind := network(a); name != "" {
			payload["cdn"], payload["cdn_type"] = name, kind
		}
		apex := normalize.RegistrableDomain(host)
		if apex != "" && host != apex && c.Wild.Match(ctx, host, apex, a) {
			payload["wildcard"] = true
			meta.Drop = true
			meta.NextHints = nil
			return
		}
		if host == apex {
			c.extras(ctx, host, payload)
		}
	}
}

// extras adds MX, TXT and NS records; asked for registrable domains only.
func (c *Collector) extras(ctx context.Context, host string, payload map[string]any) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, qt := range []uint16{dns.TypeMX, dns.TypeTXT, dns.TypeNS} {
		wg.Add(1)
		go func(qt uint16) {
			defer wg.Done()
			m, err := c.Pool.Query(ctx, host, qt)
			if err != nil || m.Rcode != dns.RcodeSuccess {
				return
			}
			var hosts, txt []string
			for _, rr := range m.Answer {
				switch r := rr.(type) {
				case *dns.MX:
					hosts = append(hosts, r.Mx)
				case *dns.NS:
					hosts = append(hosts, r.Ns)
				case *dns.TXT:
					txt = append(txt, strings.Join(r.Txt, ""))
				}
			}
			mu.Lock()
			defer mu.Unlock()
			switch qt {
			case dns.TypeMX:
				payload["mx"] = recordHosts(hosts)
			case dns.TypeNS:
				payload["ns"] = recordHosts(hosts)
			case dns.TypeTXT:
				if len(txt) > 0 {
					payload["txt"] = txt
				}
			}
		}(qt)
	}
	wg.Wait()
}

func hostOnly(raw string) string {
	h := normalize.Hostname(raw)
	if host, _, err := net.SplitHostPort(h); err == nil {
		return host
	}
	return h
}

// recordHosts drops empty and "."-only names so JSON is [] rather than [""].
func recordHosts(xs []string) []string {
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		if h := normalize.Hostname(x); h != "" {
			out = append(out, h)
		}
	}
	return out
}

// network names the CDN, WAF or cloud in front of a name: by address
// first, then by CNAME target.
func network(a dnsr.Answer) (name, kind string) {
	for _, ip := range a.IPs() {
		if name, kind = fingerprint.Network(net.ParseIP(ip)); name != "" {
			return name, kind
		}
	}
	return fingerprint.NetworkByName(a.CNAME...)
}
