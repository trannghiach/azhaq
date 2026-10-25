package ctcol

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/trannghiach/azhaq/internal/catalog"
	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/internal/normalize"
	"github.com/trannghiach/azhaq/internal/timing"
	"github.com/trannghiach/azhaq/internal/types"
)

const Name = "azhaq-ct"

const (
	maxNames   = 150
	tryTimeout = 4 * time.Second
)

type Collector struct {
	Client  *http.Client
	BaseURL string // if set, only this host is queried (tests)
}

func New(client *http.Client) *Collector {
	c := fetch.Client(client)
	c.Timeout = tryTimeout
	return &Collector{Client: c, BaseURL: "https://crt.sh"}
}

func Register(cat *catalog.Catalog, client *http.Client) {
	cat.MustRegister(New(client))
}

func liveCT(base string) bool {
	return base == "" || strings.Contains(base, "crt.sh")
}

func (c *Collector) Name() string { return Name }

func (c *Collector) Inputs() []types.SeedType { return []types.SeedType{types.TypeDomain} }

func (c *Collector) Outputs() []string { return []string{"hostname"} }

type crtRow struct {
	NameValue string `json:"name_value"`
}

type spotterRow struct {
	DNSNames []string `json:"dns_names"`
}

func (c *Collector) Run(ctx context.Context, seed types.Seed, emit func(types.Observation) error) (types.RunMeta, error) {
	domain := normalize.Hostname(seed.Keys["domain"])
	if domain == "" {
		return types.RunMeta{Status: types.StatusError, Error: "empty domain"}, nil
	}
	if normalize.SpecialUse(domain) && liveCT(c.BaseURL) {
		payload, _ := json.Marshal(map[string]any{"domain": domain, "count": 0, "skipped": "reserved"})
		_ = emit(types.Observation{
			Collector: Name, Source: "ct", Kind: "ct",
			Payload: payload, Confidence: 0, ObservedAt: time.Now().UTC(),
		})
		return types.RunMeta{Status: types.StatusOK, EmitCount: 1}, nil
	}

	var (
		names  []string
		source string
		err    error
	)
	if c.BaseURL != "" && !strings.Contains(c.BaseURL, "crt.sh") {
		names, source, err = c.pullCrt(ctx, c.BaseURL+"/?q="+url.QueryEscape(domain)+"&output=json", domain)
	} else {
		names, source, err = c.pullAny(ctx, domain)
	}
	if err != nil {
		payload := map[string]any{"domain": domain, "count": 0, "error": err.Error()}
		st := statusFromErr(err)
		if st > 0 {
			payload["status"] = st
		}
		raw, _ := json.Marshal(payload)
		_ = emit(types.Observation{
			Collector: Name, Source: "ct", Kind: "ct",
			Payload: raw, Confidence: 0, ObservedAt: time.Now().UTC(),
		})
		meta := types.RunMeta{Status: types.StatusOK, EmitCount: 1}
		if st == http.StatusTooManyRequests || st == http.StatusServiceUnavailable || st == http.StatusForbidden {
			meta.Status = types.StatusDegraded
		}
		return meta, nil
	}

	payload, _ := json.Marshal(map[string]any{"domain": domain, "names": names, "count": len(names)})
	if err := emit(types.Observation{
		Collector:  Name,
		Source:     source,
		Kind:       "ct",
		Payload:    payload,
		Confidence: 0.8,
		ObservedAt: time.Now().UTC(),
	}); err != nil {
		return types.RunMeta{}, err
	}
	var hints []types.Seed
	for _, n := range names {
		if n == domain {
			continue
		}
		hints = append(hints, types.Seed{Type: types.TypeHostname, Keys: map[string]string{"fqdn": n}})
	}
	return types.RunMeta{Status: types.StatusOK, EmitCount: 1, NextHints: hints}, nil
}

func (c *Collector) pullAny(ctx context.Context, domain string) ([]string, string, error) {
	// crt.sh is often multi-second even when it works. Race it with Cert Spotter
	// and take the first non-empty set. Wildcard crt.sh only if both miss.
	names, src, err := firstNonEmpty(ctx, domain, c.fromCrtPlain, c.fromCertspotter)
	if err == nil && len(names) > 0 {
		return names, src, nil
	}
	if err != nil {
		return nil, "", err
	}
	if wn, ws, werr := c.fromCrtWildcard(ctx, domain); werr == nil {
		return wn, ws, nil
	}
	return names, src, nil
}

type pullFn func(context.Context, string) ([]string, string, error)

func firstNonEmpty(ctx context.Context, domain string, fns ...pullFn) ([]string, string, error) {
	if len(fns) == 0 {
		return nil, "", fmt.Errorf("no CT source")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type res struct {
		names []string
		src   string
		err   error
	}
	ch := make(chan res, len(fns))
	for _, fn := range fns {
		fn := fn
		go func() {
			names, src, err := fn(ctx, domain)
			ch <- res{names: names, src: src, err: err}
		}()
	}
	var last error
	emptySrc := ""
	for i := 0; i < len(fns); i++ {
		select {
		case <-ctx.Done():
			if last != nil {
				return nil, "", last
			}
			return nil, "", ctx.Err()
		case r := <-ch:
			if r.err != nil {
				last = r.err
				continue
			}
			if len(r.names) > 0 {
				cancel()
				return r.names, r.src, nil
			}
			emptySrc = r.src
		}
	}
	if emptySrc != "" {
		return nil, emptySrc, nil
	}
	if last == nil {
		last = fmt.Errorf("no CT source")
	}
	return nil, "", last
}

func (c *Collector) fromCrtPlain(ctx context.Context, domain string) ([]string, string, error) {
	u := "https://crt.sh/?q=" + url.QueryEscape(domain) + "&output=json"
	return c.pullCrt(ctx, u, domain)
}

func (c *Collector) fromCrtWildcard(ctx context.Context, domain string) ([]string, string, error) {
	u := "https://crt.sh/?q=" + url.QueryEscape("%."+domain) + "&output=json"
	return c.pullCrt(ctx, u, domain)
}

func (c *Collector) fromCertspotter(ctx context.Context, domain string) ([]string, string, error) {
	u := "https://api.certspotter.com/v1/issuances?domain=" + url.QueryEscape(domain) + "&include_subdomains=true&expand=dns_names"
	body, err := c.get(ctx, u)
	if err != nil {
		return nil, u, err
	}
	var rows []spotterRow
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, u, err
	}
	return filterNames(rowsToNames(rows), domain), u, nil
}

func rowsToNames(rows []spotterRow) []string {
	var out []string
	for _, r := range rows {
		out = append(out, r.DNSNames...)
	}
	return out
}

func (c *Collector) pullCrt(ctx context.Context, rawURL, domain string) ([]string, string, error) {
	body, err := c.get(ctx, rawURL)
	if err != nil {
		return nil, rawURL, err
	}
	var rows []crtRow
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, rawURL, err
	}
	var raw []string
	for _, row := range rows {
		raw = append(raw, strings.Split(row.NameValue, "\n")...)
	}
	return filterNames(raw, domain), rawURL, nil
}

func (c *Collector) get(ctx context.Context, raw string) ([]byte, error) {
	host := "ct"
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		host = u.Host
	}
	done := timing.Start(ctx, "ct."+host)
	defer done()
	ctx, cancel := context.WithTimeout(ctx, tryTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", fetch.UserAgent)
	req.Header.Set("Accept", "application/json")
	cli := c.Client
	if cli == nil {
		cli = fetch.Client(nil)
		cli.Timeout = tryTimeout
	}
	resp, err := cli.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s %d", resp.Request.URL.Host, resp.StatusCode)
	}
	return body, nil
}

func statusFromErr(err error) int {
	if err == nil {
		return 0
	}
	parts := strings.Fields(err.Error())
	if len(parts) == 0 {
		return 0
	}
	var n int
	_, _ = fmt.Sscanf(parts[len(parts)-1], "%d", &n)
	return n
}

func filterNames(in []string, domain string) []string {
	if normalize.SharedSuffix(domain) == domain {
		return nil
	}
	seen := map[string]bool{}
	suffix := "." + domain
	var out []string
	for _, part := range in {
		n := normalize.Hostname(strings.TrimPrefix(strings.TrimSpace(part), "*."))
		if n == "" || seen[n] {
			continue
		}
		if n != domain && !strings.HasSuffix(n, suffix) {
			continue
		}
		seen[n] = true
		out = append(out, n)
		if len(out) >= maxNames {
			break
		}
	}
	return out
}
