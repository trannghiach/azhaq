package cdxcol

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/trannghiach/azhaq/internal/catalog"
	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/internal/normalize"
	"github.com/trannghiach/azhaq/internal/timing"
	"github.com/trannghiach/azhaq/internal/types"
	"github.com/trannghiach/azhaq/internal/webextract"
)

const Name = "azhaq-cdx"

const (
	maxEmit    = 80
	maxHints   = 40
	tryTimeout = 12 * time.Second
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

// Info: this collector only asks third parties or DNS resolvers.
func (c *Collector) Info() catalog.Info { return catalog.Info{Kind: catalog.Passive} }

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
	sources := map[string]any{}
	var failed []string
	try := func(b string) ([]cdxRow, string, int, bool) {
		name := hostOf(b)
		rows, src, status, err := c.pull(ctx, cdxURL(b, domain), true)
		switch {
		case err != nil:
			sources[name] = map[string]any{"error": err.Error()}
			failed = append(failed, name+": "+err.Error())
			return nil, src, status, false
		case status == http.StatusTooManyRequests || status == http.StatusServiceUnavailable:
			sources[name] = map[string]any{"status": status}
			failed = append(failed, fmt.Sprintf("%s: %d after retries", name, status))
			return nil, src, status, false
		}
		sources[name] = map[string]any{"status": status, "count": len(rows)}
		return rows, src, status, true
	}
	rows, src, status, ok := try(base)
	if !ok || len(rows) == 0 {
		if fb := c.fallbackBase(); fb != "" && fb != base {
			if frows, fsrc, fstatus, fok := try(fb); fok && (len(frows) > 0 || !ok) {
				rows, src, status, ok = frows, fsrc, fstatus, true
			}
		}
	}

	row := map[string]any{
		"domain":  domain,
		"count":   len(rows),
		"source":  src,
		"status":  status,
		"sources": sources,
	}
	meta := types.RunMeta{Status: types.StatusOK, EmitCount: 1}
	if len(failed) > 0 {
		// An archive that refused may hold URLs the other lacks.
		row["degraded"] = true
		row["warning"] = strings.Join(failed, "; ")
		meta.Status = types.StatusDegraded
	}
	if !ok {
		row["error"] = strings.Join(failed, "; ")
	}
	summary, _ := json.Marshal(row)
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
		// pywb: one JSON object per line, and fl= is not supported.
		q.Del("fl")
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

// retryWait is the first backoff after a 429 or 503 when the archive sends
// no Retry-After; later tries wait longer.
var retryWait = time.Second

// maxRetryAfter caps a server's Retry-After: a run does not wait minutes
// for one archive.
const maxRetryAfter = 5 * time.Second

func (c *Collector) pull(ctx context.Context, rawURL string, retry bool) ([]cdxRow, string, int, error) {
	tries := 1
	if retry {
		tries = 3
	}
	var (
		rows   []cdxRow
		status int
		wait   time.Duration
		err    error
	)
	for i := 0; i < tries; i++ {
		if i > 0 {
			if wait <= 0 {
				wait = retryWait * time.Duration(i)
			}
			select {
			case <-ctx.Done():
				return rows, rawURL, status, ctx.Err()
			case <-time.After(wait):
			}
		}
		rows, status, wait, err = c.pullOnce(ctx, rawURL)
		if err != nil {
			return rows, rawURL, status, err // a timeout already took long enough
		}
		if status != http.StatusTooManyRequests && status != http.StatusServiceUnavailable {
			return rows, rawURL, status, nil
		}
	}
	return rows, rawURL, status, err
}

func (c *Collector) pullOnce(ctx context.Context, rawURL string) ([]cdxRow, int, time.Duration, error) {
	done := timing.Start(ctx, "cdx."+hostOf(rawURL))
	defer done()
	ctx, cancel := context.WithTimeout(ctx, tryTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, 0, 0, err
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
		return nil, 0, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, resp.StatusCode, 0, err
	}
	switch resp.StatusCode {
	case http.StatusOK:
		rows, err := parseCDX(body)
		return rows, resp.StatusCode, 0, err
	case http.StatusNotFound:
		return nil, resp.StatusCode, 0, nil
	case http.StatusTooManyRequests, http.StatusServiceUnavailable:
		return nil, resp.StatusCode, retryAfter(resp.Header.Get("Retry-After")), nil
	default:
		return nil, resp.StatusCode, 0, fmt.Errorf("%s %d", resp.Request.URL.Host, resp.StatusCode)
	}
}

func retryAfter(v string) time.Duration {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n <= 0 {
		return 0
	}
	return min(time.Duration(n)*time.Second, maxRetryAfter)
}

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw
	}
	return u.Host
}

func parseCDX(body []byte) ([]cdxRow, error) {
	body = []byte(strings.TrimSpace(string(body)))
	if len(body) == 0 || string(body) == "[]" {
		return nil, nil
	}
	if body[0] == '{' {
		return parseCDXLines(body)
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

// parseCDXLines reads pywb output (arquivo.pt): one JSON object per line.
func parseCDXLines(body []byte) ([]cdxRow, error) {
	var out []cdxRow
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var o struct {
			URL       string `json:"url"`
			Original  string `json:"original"`
			Status    string `json:"status"`
			Timestamp string `json:"timestamp"`
		}
		if err := json.Unmarshal([]byte(line), &o); err != nil {
			return out, err
		}
		if o.URL == "" {
			o.URL = o.Original
		}
		if o.URL != "" {
			out = append(out, cdxRow{URL: o.URL, Status: o.Status, Timestamp: o.Timestamp})
		}
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
