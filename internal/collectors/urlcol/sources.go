package urlcol

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/trannghiach/azhaq/internal/answer"
	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/internal/normalize"
)

// source lists the archived URLs of a domain and its subdomains, page by
// page. add receives each page as it comes, so a source that fails half
// way keeps what it got.
type source struct {
	name  string
	needs string // provider key name; "" when none is needed
	can   int    // the filters it applies (by*); the others are not applied to its URLs
	fetch func(ctx context.Context, g *getter, domain string, key string, add func([]string)) (pages int, err error)
}

func allSources() []source {
	return []source{
		{name: "wayback", can: byStatus | byMime | byDate, fetch: wayback},
		{name: "commoncrawl", can: byStatus | byMime | byDate, fetch: commonCrawl},
		{name: "otx", fetch: otx},
		{name: "urlscan", can: byDate, fetch: urlscan},
		{name: "arquivo", can: byStatus | byMime | byDate, fetch: arquivo},
	}
}

// getter sends the requests of one source: a pause between requests,
// backoff on 429 and 503, and a cap on pages.
type getter struct {
	client   *http.Client
	pause    time.Duration
	maxPages int
	retries  int // asked again after a refusal or a network error; -1: a 429 or 503 until the time is spent, a network error 3 times
	last     time.Time
	// What the requests cost, for the source's row.
	tries   int           // requests sent, retries included
	retried int           // sent again
	waited  time.Duration // spent waiting between tries
	header  http.Header
	apex    bool    // the domain's own host only, not its subdomains
	filters Filters // sent to the archive
	base    string  // replaces the source's address
	capped  bool    // the source stopped at its page cap with more to read
	raw     bool    // only what gau would print: urlscan's page URLs, not its task URLs
}

// at is the source's address: the override, or def.
func (g *getter) at(def string) string {
	if g.base != "" {
		return g.base
	}
	return def
}

// pattern is the CDX url parameter: the host alone, or with its subdomains.
func (g *getter) pattern(domain string) string {
	if g.apex {
		return domain + "/*"
	}
	return "*." + domain + "/*"
}

// errStatus is an answer other than 200, 429 or 503.
type errStatus struct {
	host string
	code int
}

func (e errStatus) Error() string { return fmt.Sprintf("%s answered %d", e.host, e.code) }

// errAnswer is a 200 whose body is an error (a quota page, a JSON error),
// not data: the archive has not answered.
type errAnswer struct {
	host, why string
}

func (e errAnswer) Error() string {
	return fmt.Sprintf("%s answered 200 with an error, not URLs: %s", e.host, e.why)
}

// errTried is a request that kept failing: what it was told, how many
// tries it took, and why it stopped.
type errTried struct {
	tries  int
	why    string        // "429 Too Many Requests", "connection refused"
	waited time.Duration // spent waiting between the tries
	short  string        // why it stopped before its tries were spent
	pages  int           // read before it
}

func (e errTried) Error() string {
	try := "tries"
	if e.tries == 1 {
		try = "try"
	}
	s := fmt.Sprintf("failed after %d %s, %s", e.tries, try, e.why)
	if e.waited >= time.Second/2 {
		s += fmt.Sprintf(" (waited %s)", e.waited.Round(time.Second))
	}
	if e.short != "" {
		s += "; " + e.short
	}
	if e.pages > 0 {
		s += fmt.Sprintf("; %d pages were read before", e.pages)
	}
	return s
}

// backoff is the wait before each retry when the server names none; past
// the table the last wait repeats.
var backoff = []time.Duration{2 * time.Second, 5 * time.Second, 10 * time.Second, 20 * time.Second, 30 * time.Second}

// netTries is how many times a network error is retried when -retries is
// not given.
const netTries = 3

// waitFor is the wait before retry number attempt.
func waitFor(attempt int) time.Duration { return backoff[min(attempt, len(backoff)-1)] }

func (g *getter) get(ctx context.Context, raw string) ([]byte, error) {
	body, err := g.open(ctx, raw)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	return io.ReadAll(io.LimitReader(body, 64<<20))
}

// open sends the request and returns the body of a 200 answer for the
// caller to read and close. A 429 or 503 is asked again after the
// Retry-After it names (seconds or a date, however long) or after 2, 5, 10,
// 20 and then 30 s, for as long as the time of the source and of the run
// allows (-retries N makes it N times); a network error is asked again 3
// times (or N). A wait that is longer than the time left ends the request
// at once, with the reason, and not at the deadline with none.
func (g *getter) open(ctx context.Context, raw string) (io.ReadCloser, error) {
	var waited time.Duration
	// retry says whether another try may follow the one numbered attempt,
	// and if so after what wait; short says why not, when time is the reason.
	retry := func(attempt int, limited bool, hinted time.Duration, why string) (wait time.Duration, err error) {
		allowed := g.retries
		if g.retries < 0 {
			allowed = netTries
			if limited {
				allowed = math.MaxInt
			}
		}
		if attempt >= allowed {
			return 0, errTried{tries: attempt + 1, why: why, waited: waited}
		}
		wait = waitFor(attempt)
		if hinted > 0 {
			wait = hinted
		}
		if dl, ok := ctx.Deadline(); ok && time.Until(dl) <= wait {
			return 0, errTried{tries: attempt + 1, why: why, waited: waited, short: fmt.Sprintf("the %s to wait is more than the %s left (-urls-timeout or -timeout)", wait.Round(time.Second), max(time.Until(dl), 0).Round(time.Second))}
		}
		return wait, nil
	}
	pause := func(d time.Duration, attempt int, why string) error {
		if err := sleep(ctx, d); err != nil {
			return errTried{tries: attempt + 1, why: why, waited: waited, short: "the time (-urls-timeout or -timeout) ran out while waiting"}
		}
		waited += d
		g.waited += d
		g.retried++
		return nil
	}
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
		g.tries++
		resp, err := g.client.Do(req)
		if err != nil {
			// An archive that refuses or drops connections for a while
			// (after a large query) is asked again, as a 503 would be.
			if ctx.Err() != nil {
				return nil, err
			}
			why := netReason(err)
			wait, stop := retry(attempt, false, 0, why)
			if stop != nil {
				return nil, stop
			}
			if err := pause(wait, attempt, why); err != nil {
				return nil, err
			}
			continue
		}
		if resp.StatusCode == http.StatusOK {
			body, why := answer.Screen(resp.Body)
			if why != "" {
				body.Close()
				return nil, errAnswer{host: hostOf(raw), why: why}
			}
			return body, nil
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		switch {
		case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable:
			why := statusReason(resp)
			hinted := retryAfter(resp.Header.Get("Retry-After"))
			if hinted > 0 {
				why += fmt.Sprintf(", Retry-After %s", hinted.Round(time.Second))
			}
			wait, stop := retry(attempt, true, hinted, why)
			if stop != nil {
				return nil, stop
			}
			if err := pause(wait, attempt, why); err != nil {
				return nil, err
			}
		default:
			return nil, errStatus{host: hostOf(raw), code: resp.StatusCode}
		}
	}
}

// statusReason is "429 Too Many Requests".
func statusReason(resp *http.Response) string {
	if resp.Status != "" {
		return resp.Status
	}
	return fmt.Sprintf("%d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
}

// netReason is a network error without the URL it names.
func netReason(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) && ue.Err != nil {
		err = ue.Err
	}
	return err.Error()
}

// retryAfter reads a Retry-After header: seconds, or an HTTP date; 0 when
// there is none.
func retryAfter(h string) time.Duration {
	h = strings.TrimSpace(h)
	if n, err := strconv.Atoi(h); err == nil && n > 0 {
		return time.Duration(n) * time.Second
	}
	if at, err := http.ParseTime(h); err == nil {
		return max(time.Until(at), 0)
	}
	return 0
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

// limited marks how many pages a source had read before a request failed.
func limited(err error, pages int) error {
	if l, ok := err.(errTried); ok {
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
	q := url.Values{"url": {g.pattern(domain)}, "output": {"json"}, "collapse": {"urlkey"}, "fl": {"original"}, "pageSize": {"100"}}
	g.filters.params(q, cdxWayback)
	for page := 0; page < g.maxPages; page++ {
		q.Set("page", strconv.Itoa(page))
		body, err := g.open(ctx, g.at(waybackBase)+"?"+q.Encode())
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
	g.capped = true
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
	body, err := g.get(ctx, g.at(commonCrawlInfo))
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
	q := url.Values{"url": {g.pattern(domain)}, "output": {"json"}, "fl": {"url"}}
	g.filters.params(q, cdxPywb)
	n := 1
	if body, err := g.get(ctx, api+"?"+q.Encode()+"&showNumPages=true"); err == nil {
		var p struct {
			Pages int `json:"pages"`
		}
		if json.Unmarshal(body, &p) == nil && p.Pages > 0 {
			n = p.Pages
		}
	} else if noCaptures(err) {
		return 0, nil
	} else {
		return 0, limited(err, 0)
	}
	for page := 0; page < n && page < g.maxPages; page++ {
		q.Set("page", strconv.Itoa(page))
		body, err := g.get(ctx, api+"?"+q.Encode())
		if noCaptures(err) {
			return page, nil
		}
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
	g.capped = n > g.maxPages
	return min(n, g.maxPages), nil
}

// noCaptures: Common Crawl answers 404 for a name its index holds nothing
// under, which is an empty answer, not a failure.
func noCaptures(err error) bool {
	var st errStatus
	return errors.As(err, &st) && st.code == http.StatusNotFound
}

// AlienVault OTX URL list: 500 per page until has_next is false. A name
// with a subdomain is asked as a hostname (that host alone), or, when its
// subdomains are wanted, as its registered domain, as gau does.
var otxBase = "https://otx.alienvault.com/api/v1/indicators"

func otxTarget(domain string, apex bool) (category, name string) {
	reg := normalize.RegistrableDomain(domain)
	switch {
	case reg == "" || reg == domain:
		return "domain", domain
	case apex:
		return "hostname", domain
	}
	return "domain", reg
}

func otx(ctx context.Context, g *getter, domain, _ string, add func([]string)) (int, error) {
	category, name := otxTarget(domain, g.apex)
	for page := 1; page <= g.maxPages; page++ {
		body, err := g.get(ctx, fmt.Sprintf("%s/%s/%s/url_list?limit=500&page=%d", g.at(otxBase), category, url.PathEscape(name), page))
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
	g.capped = true
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
		q := url.Values{"q": {urlscanQuery(domain, g.filters)}, "size": {"100"}}
		if after != "" {
			q.Set("search_after", after)
		}
		body, err := g.get(ctx, g.at(urlscanBase)+"?"+q.Encode())
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
			urls = append(urls, x.Page.URL)
			if !g.raw {
				urls = append(urls, x.Task.URL)
			}
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
	g.capped = true
	return g.maxPages, nil
}

// urlscanQuery is the search for a domain, within the dates when given.
func urlscanQuery(domain string, f Filters) string {
	q := "domain:" + domain
	if f.From != "" {
		q += " AND date:>=" + dateBound(f.From, false)
	}
	if f.To != "" {
		q += " AND date:<=" + dateBound(f.To, true)
	}
	return q
}

// dateBound is the first (or last) day a YYYY, YYYYMM, YYYYMMDD or
// YYYYMMDDhhmmss value stands for, as 2006-01-02.
func dateBound(d string, last bool) string {
	d = d[:min(len(d), 8)]
	for len(d) < 8 {
		switch len(d) {
		case 4:
			d += "01"
			if last {
				d = d[:4] + "12"
			}
		case 6:
			d += "01"
			if last {
				t, _ := time.Parse("200601", d[:6])
				d = t.AddDate(0, 1, -1).Format("20060102")
			}
		}
	}
	return d[:4] + "-" + d[4:6] + "-" + d[6:8]
}

// arquivo.pt (Portuguese web archive, pywb): one request, one JSON object
// per line. It often holds what the Wayback Machine refuses to serve.
var arquivoBase = "https://arquivo.pt/wayback/cdx"

func arquivo(ctx context.Context, g *getter, domain, _ string, add func([]string)) (int, error) {
	q := url.Values{"url": {g.pattern(domain)}, "output": {"json"}, "collapse": {"urlkey"}, "limit": {strconv.Itoa(arquivoLimit)}}
	g.filters.params(q, cdxPywb)
	body, err := g.get(ctx, g.at(arquivoBase)+"?"+q.Encode())
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
	g.capped = len(urls) >= arquivoLimit
	return 1, nil
}

// arquivoLimit is how many rows the one request asks for.
const arquivoLimit = 10000
