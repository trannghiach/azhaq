package dnscol

import (
	"context"
	"encoding/json"
	"net"
	"sync"
	"time"

	"azhaq/internal/catalog"
	"azhaq/internal/neterr"
	"azhaq/internal/normalize"
	"azhaq/internal/timing"
	"azhaq/internal/types"
)

const Name = "azhaq-dns"

type Collector struct {
	Resolver *net.Resolver
}

func New() *Collector {
	return &Collector{Resolver: net.DefaultResolver}
}

func Register(cat *catalog.Catalog) {
	cat.MustRegister(New())
}

func (c *Collector) Name() string { return Name }

func (c *Collector) Inputs() []types.SeedType { return []types.SeedType{types.TypeHostname} }

func (c *Collector) Outputs() []string { return []string{"dns"} }

func (c *Collector) Run(ctx context.Context, seed types.Seed, emit func(types.Observation) error) (types.RunMeta, error) {
	host := normalize.Hostname(seed.Keys["fqdn"])
	if host == "" {
		return types.RunMeta{Status: types.StatusError, Error: "empty host"}, nil
	}
	r := c.Resolver
	if r == nil {
		r = net.DefaultResolver
	}

	payload := map[string]any{"fqdn": host}
	var hints []types.Seed

	if ip := net.ParseIP(host); ip != nil {
		payload["ips"] = []string{ip.String()}
	} else {
		// ip4 first: LookupIP("ip") waits for AAAA too, which often stalls.
		aDone := timing.Start(ctx, "dns.a", host)
		ips, err := r.LookupIP(ctx, "ip4", host)
		if err != nil {
			ips, err = r.LookupIP(ctx, "ip6", host)
			if err != nil {
				aDone()
				if neterr.UnknownHost(err) {
					payload["error"] = "nxdomain"
					raw, _ := json.Marshal(payload)
					_ = emit(types.Observation{
						Collector: Name, Source: "dns", Kind: "dns",
						Payload: raw, Confidence: 0.9, ObservedAt: time.Now().UTC(),
					})
					return types.RunMeta{Status: types.StatusOK, EmitCount: 1}, nil
				}
				return types.RunMeta{Status: types.StatusError, Error: err.Error()}, err
			}
		}
		aDone()
		var s []string
		for _, ip := range ips {
			s = append(s, ip.String())
		}
		payload["ips"] = s
		extraDone := timing.Start(ctx, "dns.extra", host)
		fillExtra(ctx, r, host, payload)
		extraDone()
		if cname, _ := payload["cname"].(string); cname != "" && cname != host && normalize.SameSite(host, cname) {
			hints = append(hints, types.Seed{Type: types.TypeHostname, Keys: map[string]string{"fqdn": cname}})
		}
	}

	raw, _ := json.Marshal(payload)
	err := emit(types.Observation{
		Collector:  Name,
		Source:     "dns",
		Kind:       "dns",
		Payload:    raw,
		Confidence: 0.95,
		ObservedAt: time.Now().UTC(),
	})
	return types.RunMeta{Status: types.StatusOK, EmitCount: 1, NextHints: hints}, err
}

func fillExtra(ctx context.Context, r *net.Resolver, host string, payload map[string]any) {
	ctx, cancel := context.WithTimeout(ctx, 1200*time.Millisecond)
	defer cancel()
	var mu sync.Mutex
	var wg sync.WaitGroup
	goLookup := func(fn func()) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fn()
		}()
	}
	goLookup(func() {
		if cname, err := r.LookupCNAME(ctx, host); err == nil && cname != "" {
			mu.Lock()
			payload["cname"] = normalize.Hostname(cname)
			mu.Unlock()
		}
	})
	goLookup(func() {
		if mx, err := r.LookupMX(ctx, host); err == nil {
			var raw []string
			for _, m := range mx {
				if m != nil {
					raw = append(raw, m.Host)
				}
			}
			mu.Lock()
			payload["mx"] = recordHosts(raw)
			mu.Unlock()
		}
	})
	goLookup(func() {
		if txt, err := r.LookupTXT(ctx, host); err == nil && len(txt) > 0 {
			mu.Lock()
			payload["txt"] = txt
			mu.Unlock()
		}
	})
	goLookup(func() {
		if ns, err := r.LookupNS(ctx, host); err == nil {
			var raw []string
			for _, n := range ns {
				if n != nil {
					raw = append(raw, n.Host)
				}
			}
			mu.Lock()
			payload["ns"] = recordHosts(raw)
			mu.Unlock()
		}
	})
	wg.Wait()
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
