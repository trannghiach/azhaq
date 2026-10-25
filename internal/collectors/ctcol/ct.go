package ctcol

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/trannghiach/azhaq/internal/catalog"
	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/internal/normalize"
	"github.com/trannghiach/azhaq/internal/timing"
	"github.com/trannghiach/azhaq/internal/types"
)

const Name = "azhaq-ct"

const maxNames = 1000

// crt.sh often needs tens of seconds for a wildcard query and fails with
// 502 under load; one retry fixes most of those. A query that timed out is
// not retried: that would double the wait of every run.
var (
	crtTimeout     = 25 * time.Second
	spotterTimeout = 10 * time.Second
	retryWait      = 2 * time.Second
)

type Collector struct {
	Client  *http.Client
	BaseURL string // if set, only this crt.sh-compatible host is queried (tests)
	srcs    []source
}

func New(client *http.Client) *Collector {
	c := fetch.Client(client)
	c.Timeout = crtTimeout
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

// source is one CT log search. Every source is asked; the names are the
// union, and each source's outcome is recorded so a failure is visible.
type source struct {
	name string
	pull func(context.Context, string) ([]string, error)
}

func (c *Collector) sources() []source {
	if c.srcs != nil {
		return c.srcs
	}
	if c.BaseURL != "" && !liveCT(c.BaseURL) {
		return []source{{"crt.sh", c.fromCrt}}
	}
	return []source{
		{"crt.sh", c.fromCrt},
		{"certspotter", c.fromCertspotter},
	}
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

	srcs := c.sources()
	results := pullAll(ctx, domain, srcs)
	var all []string
	status := map[string]any{}
	var failed []string
	httpStatus := 0
	for i, r := range results {
		name := srcs[i].name
		if r.err != nil {
			status[name] = map[string]any{"error": r.err.Error()}
			failed = append(failed, name+": "+r.err.Error())
			if st := statusFromErr(r.err); st > 0 && httpStatus == 0 {
				httpStatus = st
			}
			continue
		}
		status[name] = map[string]any{"count": len(r.names)}
		all = append(all, r.names...)
	}
	names := filterNames(all, domain)
	row := map[string]any{"domain": domain, "names": names, "count": len(names), "sources": status}
	meta := types.RunMeta{Status: types.StatusOK, EmitCount: 1}
	if len(failed) > 0 {
		// A source that failed may hold names the others lack.
		row["degraded"] = true
		row["warning"] = strings.Join(failed, "; ")
		meta.Status = types.StatusDegraded
	}
	if len(failed) == len(srcs) {
		row["error"] = strings.Join(failed, "; ")
		if httpStatus > 0 {
			row["status"] = httpStatus
		}
	}
	payload, _ := json.Marshal(row)
	if err := emit(types.Observation{
		Collector:  Name,
		Source:     "ct",
		Kind:       "ct",
		Payload:    payload,
		Confidence: 0.8,
		ObservedAt: time.Now().UTC(),
	}); err != nil {
		return types.RunMeta{}, err
	}
	for _, n := range names {
		if n == domain {
			continue
		}
		meta.NextHints = append(meta.NextHints, types.Seed{Type: types.TypeHostname, Keys: map[string]string{"fqdn": n}})
	}
	return meta, nil
}

type pullResult struct {
	names []string
	err   error
}

func pullAll(ctx context.Context, domain string, srcs []source) []pullResult {
	out := make([]pullResult, len(srcs))
	var wg sync.WaitGroup
	for i, src := range srcs {
		wg.Add(1)
		go func(i int, src source) {
			defer wg.Done()
			names, err := src.pull(ctx, domain)
			out[i] = pullResult{names: names, err: err}
		}(i, src)
	}
	wg.Wait()
	return out
}

func (c *Collector) fromCrt(ctx context.Context, domain string) ([]string, error) {
	base := "https://crt.sh"
	if c.BaseURL != "" && !liveCT(c.BaseURL) {
		base = c.BaseURL
	}
	u := base + "/?q=" + url.QueryEscape("%."+domain) + "&output=json"
	names, err := c.pullCrt(ctx, u, domain)
	if err == nil || ctx.Err() != nil || !retryable(err) {
		return names, err
	}
	select {
	case <-ctx.Done():
		return nil, err
	case <-time.After(retryWait):
	}
	return c.pullCrt(ctx, u, domain)
}

func retryable(err error) bool {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return false
	}
	st := statusFromErr(err)
	return st == 0 || st >= 500 || st == http.StatusTooManyRequests
}

func (c *Collector) fromCertspotter(ctx context.Context, domain string) ([]string, error) {
	u := "https://api.certspotter.com/v1/issuances?domain=" + url.QueryEscape(domain) + "&include_subdomains=true&expand=dns_names"
	body, err := c.get(ctx, u, spotterTimeout)
	if err != nil {
		return nil, err
	}
	var rows []spotterRow
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, err
	}
	return filterNames(rowsToNames(rows), domain), nil
}

func rowsToNames(rows []spotterRow) []string {
	var out []string
	for _, r := range rows {
		out = append(out, r.DNSNames...)
	}
	return out
}

func (c *Collector) pullCrt(ctx context.Context, rawURL, domain string) ([]string, error) {
	body, err := c.get(ctx, rawURL, crtTimeout)
	if err != nil {
		return nil, err
	}
	var rows []crtRow
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, err
	}
	var raw []string
	for _, row := range rows {
		raw = append(raw, strings.Split(row.NameValue, "\n")...)
	}
	return filterNames(raw, domain), nil
}

func (c *Collector) get(ctx context.Context, raw string, timeout time.Duration) ([]byte, error) {
	host := "ct"
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		host = u.Host
	}
	done := timing.Start(ctx, "ct."+host)
	defer done()
	ctx, cancel := context.WithTimeout(ctx, timeout)
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
	}
	cp := *cli
	cp.Timeout = timeout
	resp, err := cp.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
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
