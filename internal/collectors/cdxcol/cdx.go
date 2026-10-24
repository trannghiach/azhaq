package cdxcol

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"azhaq/internal/catalog"
	"azhaq/internal/fetch"
	"azhaq/internal/normalize"
	"azhaq/internal/timing"
	"azhaq/internal/types"
	"azhaq/internal/webextract"
)

const Name = "azhaq-cdx"

const (
	maxEmit    = 80
	maxHints   = 40
	tryTimeout = 6 * time.Second
)

type Collector struct {
	Client   *http.Client
	BaseURL  string
	Fallback string // tests; live default is arquivo.pt
}

func New(client *http.Client) *Collector {
	c := fetch.Client(client)
	c.Timeout = tryTimeout
	return &Collector{Client: c, BaseURL: "https://web.archive.org"}
}

func Register(cat *catalog.Catalog, client *http.Client) {
	cat.MustRegister(New(client))
}

func liveCDX(base string) bool {
	return base == "" || strings.Contains(base, "web.archive.org")
}

func (c *Collector) Name() string { return Name }

func (c *Collector) Inputs() []types.SeedType { return []types.SeedType{types.TypeDomain} }

func (c *Collector) Outputs() []string { return []string{"url"} }

func (c *Collector) Run(ctx context.Context, seed types.Seed, emit func(types.Observation) error) (types.RunMeta, error) {
	domain := normalize.Hostname(seed.Keys["domain"])
	if domain == "" {
		return types.RunMeta{Status: types.StatusError, Error: "empty domain"}, nil
	}
	if normalize.SpecialUse(domain) && liveCDX(c.BaseURL) {
		payload, _ := json.Marshal(map[string]any{"domain": domain, "count": 0, "skipped": "reserved"})
		_ = emit(types.Observation{
			Collector: Name, Source: "cdx", Kind: "cdx",
			Payload: payload, Confidence: 0, ObservedAt: time.Now().UTC(),
		})
		return types.RunMeta{Status: types.StatusOK, EmitCount: 1}, nil
	}
	base := c.BaseURL
	if base == "" {
		base = "https://web.archive.org"
	}
	rawURL := cdxURL(base, domain)

	rows, src, status, err := c.pull(ctx, rawURL, false)
	if err != nil || status == http.StatusTooManyRequests || status == http.StatusServiceUnavailable || len(rows) == 0 {
		if fb := c.fallbackBase(); fb != "" && fb != base {
			frows, fsrc, fstatus, ferr := c.pull(ctx, cdxURL(fb, domain), false)
			if ferr == nil && (len(frows) > 0 || fstatus == http.StatusOK) {
				rows, src, status, err = frows, fsrc, fstatus, nil
			}
		}
	}
	if err != nil {
		return types.RunMeta{Status: types.StatusError, Error: err.Error()}, err
	}

	summary, _ := json.Marshal(map[string]any{
		"domain": domain,
		"count":  len(rows),
		"source": src,
		"status": status,
	})
	if err := emit(types.Observation{
		Collector:  Name,
		Source:     src,
		Kind:       "cdx",
		Payload:    summary,
		Confidence: 0.7,
		ObservedAt: time.Now().UTC(),
	}); err != nil {
		return types.RunMeta{}, err
	}
	meta := types.RunMeta{Status: types.StatusOK, EmitCount: 1}
	if status == http.StatusTooManyRequests || status == http.StatusServiceUnavailable {
		meta.Status = types.StatusDegraded
	}
	seen := map[string]bool{}
	for _, row := range rows {
		if meta.EmitCount >= maxEmit {
			break
		}
		u, err := normalize.URL(row.URL)
		if err != nil || seen[u] {
			continue
		}
		host := normalize.HostFromURL(u)
		if host != domain && !normalize.SameSite(host, domain) {
			continue
		}
		seen[u] = true
		payload, _ := json.Marshal(map[string]any{
			"url":       u,
			"via":       "cdx",
			"status":    row.Status,
			"timestamp": row.Timestamp,
		})
		if err := emit(types.Observation{
			Collector:  Name,
			Source:     src,
			Kind:       "url",
			Payload:    payload,
			Confidence: 0.7,
			ObservedAt: time.Now().UTC(),
		}); err != nil {
			return meta, err
		}
		meta.EmitCount++
		if len(meta.NextHints) < maxHints && webextract.Hintable(u) {
			meta.NextHints = append(meta.NextHints, types.Seed{
				Type: types.TypeURL,
				Keys: map[string]string{"url": u},
			})
		}
	}
	return meta, nil
}

type cdxRow struct {
	URL       string
	Status    string
	Timestamp string
}

func cdxURL(base, domain string) string {
	q := url.Values{
		"url":      {"*." + domain + "/*"},
		"output":   {"json"},
		"fl":       {"original,statuscode,mimetype,timestamp"},
		"collapse": {"urlkey"},
		"limit":    {"150"},
	}
	base = strings.TrimRight(base, "/")
	if strings.Contains(base, "arquivo.pt") {
		return base + "/cdx?" + q.Encode()
	}
	return base + "/cdx/search/cdx?" + q.Encode()
}

func (c *Collector) fallbackBase() string {
	if c.Fallback != "" {
		return c.Fallback
	}
	if liveCDX(c.BaseURL) {
		return "https://arquivo.pt/wayback"
	}
	return ""
}

func (c *Collector) pull(ctx context.Context, rawURL string, retry bool) ([]cdxRow, string, int, error) {
	tries := 1
	if retry {
		tries = 3
	}
	var lastRows []cdxRow
	var lastSrc string
	var lastStatus int
	var lastErr error
	for i := 0; i < tries; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return lastRows, lastSrc, lastStatus, ctx.Err()
			case <-time.After(time.Duration(i) * 400 * time.Millisecond):
			}
		}
		rows, src, status, err := c.pullOnce(ctx, rawURL)
		lastRows, lastSrc, lastStatus, lastErr = rows, src, status, err
		if err == nil && status != http.StatusTooManyRequests && status != http.StatusServiceUnavailable {
			return rows, src, status, nil
		}
	}
	return lastRows, lastSrc, lastStatus, lastErr
}

func (c *Collector) pullOnce(ctx context.Context, rawURL string) ([]cdxRow, string, int, error) {
	done := timing.Start(ctx, "cdx.wayback")
	defer done()
	ctx, cancel := context.WithTimeout(ctx, tryTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, rawURL, 0, err
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
		return nil, rawURL, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, rawURL, resp.StatusCode, err
	}
	switch resp.StatusCode {
	case http.StatusOK:
		rows, err := parseCDX(body)
		return rows, rawURL, resp.StatusCode, err
	case http.StatusNotFound, http.StatusTooManyRequests, http.StatusServiceUnavailable:
		return nil, rawURL, resp.StatusCode, nil
	default:
		return nil, rawURL, resp.StatusCode, fmt.Errorf("%s %d", resp.Request.URL.Host, resp.StatusCode)
	}
}

func parseCDX(body []byte) ([]cdxRow, error) {
	body = []byte(strings.TrimSpace(string(body)))
	if len(body) == 0 || string(body) == "[]" {
		return nil, nil
	}
	var table [][]string
	if err := json.Unmarshal(body, &table); err != nil {
		return nil, err
	}
	var out []cdxRow
	for i, row := range table {
		if i == 0 && looksHeader(row) {
			continue
		}
		r := rowFrom(row)
		if r.URL == "" {
			continue
		}
		out = append(out, r)
	}
	return out, nil
}

func looksHeader(row []string) bool {
	if len(row) == 0 {
		return false
	}
	h := strings.ToLower(row[0])
	return h == "original" || h == "urlkey" || h == "url"
}

func rowFrom(row []string) cdxRow {
	// fl=original,statuscode,mimetype,timestamp
	r := cdxRow{}
	if len(row) > 0 {
		r.URL = row[0]
	}
	if len(row) > 1 {
		r.Status = row[1]
	}
	if len(row) > 3 {
		r.Timestamp = row[3]
	}
	return r
}
