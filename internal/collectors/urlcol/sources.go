package urlcol

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

	"github.com/trannghiach/azhaq/internal/fetch"
)

// source lists the archived URLs of a domain and its subdomains, page by
// page. add receives each page as it comes, so a source that fails half
// way keeps what it got.
type source struct {
	name  string
	needs string // provider key name; "" when none is needed
	fetch func(ctx context.Context, g *getter, domain string, key string, add func([]string)) (pages int, err error)
}

func allSources() []source {
	return []source{
		{name: "wayback", fetch: wayback},
		{name: "commoncrawl", fetch: commonCrawl},
		{name: "otx", fetch: otx},
		{name: "urlscan", fetch: urlscan},
		{name: "arquivo", fetch: arquivo},
	}
}

// getter sends the requests of one source: a pause between requests,
// backoff on 429 and 503, and a cap on pages.
type getter struct {
	client   *http.Client
	pause    time.Duration
	maxPages int
	retries  int
	last     time.Time
	header   http.Header
}

// errLimited is a source that kept answering 429 or 503.
type errLimited struct {
	status int
	pages  int
}

func (e errLimited) Error() string {
	return fmt.Sprintf("rate limited (%d) after %d pages", e.status, e.pages)
}

var backoff = []time.Duration{2 * time.Second, 5 * time.Second, 10 * time.Second}

const maxRetryAfter = 20 * time.Second

func (g *getter) get(ctx context.Context, raw string) ([]byte, error) {
	for attempt := 0; ; attempt++ {
		if wait := g.pause - time.Since(g.last); wait > 0 {
			if err := sleep(ctx, wait); err != nil {
				return nil, err
			}
		}
		g.last = time.Now()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", fetch.UserAgent)
		req.Header.Set("Accept", "application/json")
		for k, vs := range g.header {
			req.Header[k] = vs
		}
		resp, err := g.client.Do(req)
		if err != nil {
			return nil, err
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
		resp.Body.Close()
		switch {
		case err != nil:
			return nil, err
		case resp.StatusCode == http.StatusOK:
			return body, nil
		case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable:
			if attempt >= g.retries || attempt >= len(backoff) {
				return nil, errLimited{status: resp.StatusCode}
			}
			wait := backoff[attempt]
			if n, err := strconv.Atoi(strings.TrimSpace(resp.Header.Get("Retry-After"))); err == nil && n > 0 {
				wait = min(time.Duration(n)*time.Second, maxRetryAfter)
			}
			if err := sleep(ctx, wait); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("%s answered %d", hostOf(raw), resp.StatusCode)
		}
	}
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func hostOf(raw string) string {
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		return u.Host
	}
	return raw
}

// limited marks how many pages a rate-limited source had read.
func limited(err error, pages int) error {
	if l, ok := err.(errLimited); ok {
		l.pages = pages
		return l
	}
	return err
}

// Wayback Machine CDX API, paged: showNumPages first, then each page.
var waybackBase = "https://web.archive.org/cdx/search/cdx"

func wayback(ctx context.Context, g *getter, domain, _ string, add func([]string)) (int, error) {
	q := url.Values{"url": {"*." + domain + "/*"}, "output": {"json"}, "collapse": {"urlkey"}, "fl": {"original"}}
	n := 1
	if body, err := g.get(ctx, waybackBase+"?"+q.Encode()+"&showNumPages=true"); err == nil {
		if v, err := strconv.Atoi(strings.TrimSpace(string(body))); err == nil && v > 0 {
			n = v
		}
	} else {
		return 0, limited(err, 0)
	}
	for page := 0; page < n && page < g.maxPages; page++ {
		q.Set("page", strconv.Itoa(page))
		body, err := g.get(ctx, waybackBase+"?"+q.Encode())
		if err != nil {
			return page, limited(err, page)
		}
		var rows [][]string
		if len(strings.TrimSpace(string(body))) > 0 {
			if err := json.Unmarshal(body, &rows); err != nil {
				return page, fmt.Errorf("page %d: %w", page, err)
			}
		}
		var urls []string
		for i, r := range rows {
			if i == 0 && len(r) > 0 && r[0] == "original" {
				continue
			}
			if len(r) > 0 {
				urls = append(urls, r[0])
			}
		}
		add(urls)
	}
	return min(n, g.maxPages), nil
}

// Common Crawl: the newest index from collinfo.json, paged.
var commonCrawlInfo = "https://index.commoncrawl.org/collinfo.json"

func commonCrawl(ctx context.Context, g *getter, domain, _ string, add func([]string)) (int, error) {
	body, err := g.get(ctx, commonCrawlInfo)
	if err != nil {
		return 0, limited(err, 0)
	}
	var indexes []struct {
		CDXAPI string `json:"cdx-api"`
	}
	if err := json.Unmarshal(body, &indexes); err != nil || len(indexes) == 0 || indexes[0].CDXAPI == "" {
		return 0, fmt.Errorf("no Common Crawl index listed")
	}
	api := indexes[0].CDXAPI
	q := url.Values{"url": {"*." + domain}, "output": {"json"}, "fl": {"url"}}
	n := 1
	if body, err := g.get(ctx, api+"?"+q.Encode()+"&showNumPages=true"); err == nil {
		var p struct {
			Pages int `json:"pages"`
		}
		if json.Unmarshal(body, &p) == nil && p.Pages > 0 {
			n = p.Pages
		}
	} else {
		return 0, limited(err, 0)
	}
	for page := 0; page < n && page < g.maxPages; page++ {
		q.Set("page", strconv.Itoa(page))
		body, err := g.get(ctx, api+"?"+q.Encode())
		if err != nil {
			return page, limited(err, page)
		}
		var urls []string
		for _, line := range strings.Split(string(body), "\n") {
			var o struct {
				URL string `json:"url"`
			}
			if json.Unmarshal([]byte(line), &o) == nil && o.URL != "" {
				urls = append(urls, o.URL)
			}
		}
		add(urls)
	}
	return min(n, g.maxPages), nil
}

// AlienVault OTX URL list: 500 per page until has_next is false.
var otxBase = "https://otx.alienvault.com/api/v1/indicators"

func otx(ctx context.Context, g *getter, domain, _ string, add func([]string)) (int, error) {
	for page := 1; page <= g.maxPages; page++ {
		body, err := g.get(ctx, fmt.Sprintf("%s/domain/%s/url_list?limit=500&page=%d", otxBase, url.PathEscape(domain), page))
		if err != nil {
			return page - 1, limited(err, page-1)
		}
		var r struct {
			HasNext bool `json:"has_next"`
			URLList []struct {
				URL string `json:"url"`
			} `json:"url_list"`
		}
		if err := json.Unmarshal(body, &r); err != nil {
			return page - 1, fmt.Errorf("page %d: %w", page, err)
		}
		var urls []string
		for _, u := range r.URLList {
			urls = append(urls, u.URL)
		}
		add(urls)
		if !r.HasNext || len(r.URLList) == 0 {
			return page, nil
		}
	}
	return g.maxPages, nil
}

// urlscan.io search: page and task URLs of public scans, 100 per page
// without a key, paged with search_after.
var urlscanBase = "https://urlscan.io/api/v1/search/"

func urlscan(ctx context.Context, g *getter, domain, key string, add func([]string)) (int, error) {
	if key != "" {
		g.header = http.Header{"Api-Key": {key}}
	}
	after := ""
	for page := 1; page <= g.maxPages; page++ {
		q := url.Values{"q": {"domain:" + domain}, "size": {"100"}}
		if after != "" {
			q.Set("search_after", after)
		}
		body, err := g.get(ctx, urlscanBase+"?"+q.Encode())
		if err != nil {
			return page - 1, limited(err, page-1)
		}
		var r struct {
			Results []struct {
				Page struct {
					URL string `json:"url"`
				} `json:"page"`
				Task struct {
					URL string `json:"url"`
				} `json:"task"`
				Sort []json.RawMessage `json:"sort"`
			} `json:"results"`
			HasMore bool `json:"has_more"`
		}
		if err := json.Unmarshal(body, &r); err != nil {
			return page - 1, fmt.Errorf("page %d: %w", page, err)
		}
		var urls []string
		for _, x := range r.Results {
			urls = append(urls, x.Page.URL, x.Task.URL)
		}
		add(urls)
		if !r.HasMore || len(r.Results) == 0 {
			return page, nil
		}
		var parts []string
		for _, v := range r.Results[len(r.Results)-1].Sort {
			parts = append(parts, strings.Trim(string(v), `"`))
		}
		after = strings.Join(parts, ",")
	}
	return g.maxPages, nil
}

// arquivo.pt (Portuguese web archive, pywb): one request, one JSON object
// per line. It often holds what the Wayback Machine refuses to serve.
var arquivoBase = "https://arquivo.pt/wayback/cdx"

func arquivo(ctx context.Context, g *getter, domain, _ string, add func([]string)) (int, error) {
	q := url.Values{"url": {"*." + domain + "/*"}, "output": {"json"}, "collapse": {"urlkey"}, "limit": {"10000"}}
	body, err := g.get(ctx, arquivoBase+"?"+q.Encode())
	if err != nil {
		return 0, limited(err, 0)
	}
	var urls []string
	for _, line := range strings.Split(string(body), "\n") {
		var o struct {
			URL string `json:"url"`
		}
		if json.Unmarshal([]byte(line), &o) == nil && o.URL != "" {
			urls = append(urls, o.URL)
		}
	}
	add(urls)
	return 1, nil
}
