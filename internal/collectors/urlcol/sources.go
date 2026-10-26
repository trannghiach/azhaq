package urlcol

import (
	"context"
	"encoding/json"
	"errors"
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

// errStatus is an answer other than 200, 429 or 503.
type errStatus struct {
	host string
	code int
}

func (e errStatus) Error() string { return fmt.Sprintf("%s answered %d", e.host, e.code) }

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
	body, err := g.open(ctx, raw)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	return io.ReadAll(io.LimitReader(body, 64<<20))
}

// open sends the request, waiting and retrying as get does, and returns
// the body of a 200 answer for the caller to read and close.
func (g *getter) open(ctx context.Context, raw string) (io.ReadCloser, error) {
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
		req.Header.Set("User-Agent", fetch.ToolAgent)
		req.Header.Set("Accept", "application/json")
		for k, vs := range g.header {
			req.Header[k] = vs
		}
		resp, err := g.client.Do(req)
		if err != nil {
			// An archive that refuses or drops connections for a while
			// (after a large query) is asked again, as a 503 would be.
			if ctx.Err() != nil || attempt >= g.retries || attempt >= len(backoff) {
				return nil, err
			}
			if err := sleep(ctx, backoff[attempt]); err != nil {
				return nil, err
			}
			continue
		}
		if resp.StatusCode == http.StatusOK {
			return resp.Body, nil
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		switch {
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
			return nil, errStatus{host: hostOf(raw), code: resp.StatusCode}
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

// Wayback Machine CDX API, page by page as gau reads it: showNumPages
// answers [["original"],[null]] when output=json, so the pages are read
// until one comes back empty or the server says 400 (past the last page).
// A page of a large domain is tens of MB and takes minutes, so it is read
// row by row (one row a line): what arrived before the time ran out counts.
var waybackBase = "https://web.archive.org/cdx/search/cdx"

func wayback(ctx context.Context, g *getter, domain, _ string, add func([]string)) (int, error) {
	q := url.Values{"url": {"*." + domain + "/*"}, "output": {"json"}, "collapse": {"urlkey"}, "fl": {"original"}, "pageSize": {"100"}}
	for page := 0; page < g.maxPages; page++ {
		q.Set("page", strconv.Itoa(page))
		body, err := g.open(ctx, waybackBase+"?"+q.Encode())
		if err != nil {
			var st errStatus
			if page > 0 && errors.As(err, &st) && st.code == http.StatusBadRequest {
				return page, nil
			}
			return page, limited(err, page)
		}
		n, err := cdxRows(body, add)
		body.Close()
		if err != nil {
			return page, fmt.Errorf("page %d: %w", page, err)
		}
		if n == 0 {
			return page, nil
		}
	}
	return g.maxPages, nil
}

// cdxRows reads a CDX JSON answer ([["original"], ["http://…"], …]) as it
// arrives and adds the URLs in batches; it returns how many it read.
func cdxRows(body io.Reader, add func([]string)) (int, error) {
	dec := json.NewDecoder(body)
	if tok, err := dec.Token(); err == io.EOF {
		return 0, nil
	} else if err != nil {
		return 0, err
	} else if d, ok := tok.(json.Delim); !ok || d != '[' {
		return 0, fmt.Errorf("not a JSON array")
	}
	n := 0
	var batch []string
	defer func() {
		if len(batch) > 0 {
			add(batch)
		}
	}()
	for dec.More() {
		var row []string
		if err := dec.Decode(&row); err != nil {
			return n, err
		}
		if len(row) == 0 || row[0] == "" || row[0] == "original" {
			continue
		}
		batch = append(batch, row[0])
		n++
		if len(batch) == 1000 {
			add(batch)
			batch = nil
		}
	}
	return n, nil
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
			HasNext  bool `json:"has_next"`
			FullSize int  `json:"full_size"`
			URLList  []struct {
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
		// has_next is sometimes false while full_size says more remain.
		if len(r.URLList) == 0 || (!r.HasNext && r.FullSize <= page*500) {
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
