// Package searchcol asks internet scan engines (Shodan, FOFA, Netlas)
// which hosts and services they have seen for a domain: uncover's job.
// Each needs a key in the provider file; without one it is skipped and
// says so.
package searchcol

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/trannghiach/azhaq/catalog"
	"github.com/trannghiach/azhaq/internal/collectors/httpcol"
	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/internal/normalize"
	"github.com/trannghiach/azhaq/types"
)

const Name = "azhaq-search"

// result is one service an engine saw.
type result struct {
	IP   string
	Port int
	Host string
}

type engine struct {
	name  string
	query func(ctx context.Context, c *http.Client, key, domain string, pages int) ([]result, error)
}

// Bases point at the engines; tests replace them.
var Bases = map[string]string{
	"shodan": "https://api.shodan.io",
	"fofa":   "https://fofa.info",
	"netlas": "https://app.netlas.io",
}

func engines() []engine {
	return []engine{{"shodan", shodan}, {"fofa", fofa}, {"netlas", netlas}}
}

type Collector struct {
	Client *http.Client
	Keys   map[string][]string
	Pages  int // per engine; each page costs credits; default 1
}

func New(keys map[string][]string) *Collector {
	return &Collector{Client: &http.Client{Timeout: 60 * time.Second}, Keys: keys, Pages: 1}
}

func (c *Collector) Name() string { return Name }

// Info: asks third parties only.
func (c *Collector) Info() catalog.Info { return catalog.Info{Kind: catalog.Passive} }

func (c *Collector) Inputs() []types.SeedType { return []types.SeedType{types.TypeDomain} }

func (c *Collector) Outputs() []string { return []string{"services"} }

func (c *Collector) Run(ctx context.Context, seed types.Seed, emit func(types.Observation) error) (types.RunMeta, error) {
	domain := normalize.Hostname(seed.Key())
	if domain == "" || normalize.SpecialUse(domain) {
		return types.RunMeta{Status: types.StatusOK}, nil
	}
	status := map[string]any{}
	var mu sync.Mutex
	var all []result
	var wg sync.WaitGroup
	for _, e := range engines() {
		key := ""
		if ks := c.Keys[e.name]; len(ks) > 0 {
			key = ks[0]
		}
		if key == "" {
			mu.Lock()
			status[e.name] = map[string]any{"skipped": "needs a key"}
			mu.Unlock()
			continue
		}
		wg.Add(1)
		go func(e engine, key string) {
			defer wg.Done()
			t0 := time.Now()
			rs, err := e.query(ctx, c.Client, key, domain, max(c.Pages, 1))
			row := map[string]any{"count": len(rs), "seconds": float64(time.Since(t0).Milliseconds()/100) / 10}
			if err != nil {
				row["error"] = err.Error()
			}
			mu.Lock()
			status[e.name] = row
			all = append(all, rs...)
			mu.Unlock()
		}(e, key)
	}
	wg.Wait()

	hosts := map[string]bool{}
	services := map[string]bool{}
	for _, r := range all {
		h := normalize.Hostname(r.Host)
		if h != "" && (h == domain || strings.HasSuffix(h, "."+domain)) {
			hosts[h] = true
		}
		if net.ParseIP(r.IP) != nil && r.Port > 0 {
			services[net.JoinHostPort(r.IP, strconv.Itoa(r.Port))] = true
		}
	}
	payload := map[string]any{"domain": domain, "engines": status, "hosts": keys(hosts), "services": keys(services)}
	meta := types.RunMeta{Status: types.StatusOK, EmitCount: 1}
	failed := 0
	for _, v := range status {
		if m, ok := v.(map[string]any); ok && m["error"] != nil {
			failed++
		}
	}
	if failed > 0 {
		payload["degraded"] = true
		meta.Status = types.StatusDegraded
	}
	raw, _ := json.Marshal(payload)
	if err := emit(types.Observation{Collector: Name, Source: "engines", Kind: "services", Payload: raw, Confidence: 0.7, ObservedAt: time.Now().UTC()}); err != nil {
		return meta, err
	}
	for h := range hosts {
		meta.NextHints = append(meta.NextHints, types.Seed{Type: types.TypeHostname, Keys: map[string]string{"fqdn": h}})
	}
	for s := range services {
		host, port, _ := net.SplitHostPort(s)
		if port == "80" {
			meta.NextHints = append(meta.NextHints, types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": "http://" + host + "/"}})
			continue
		}
		meta.NextHints = append(meta.NextHints, types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": "https://" + s + "/", httpcol.FallbackKey: "http"}})
	}
	return meta, nil
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func getJSON(ctx context.Context, c *http.Client, raw string, header http.Header, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", fetch.ToolAgent)
	req.Header.Set("Accept", "application/json")
	for k, vs := range header {
		req.Header[k] = vs
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if resp.StatusCode != http.StatusOK {
		msg := strings.TrimSpace(string(body))
		if len(msg) > 160 {
			msg = msg[:160]
		}
		return fmt.Errorf("%d %s", resp.StatusCode, msg)
	}
	return json.Unmarshal(body, v)
}

// shodan searches hostname:domain, 100 matches a page.
func shodan(ctx context.Context, c *http.Client, key, domain string, pages int) ([]result, error) {
	var out []result
	for page := 1; page <= pages; page++ {
		q := url.Values{"key": {key}, "query": {"hostname:" + domain}, "page": {strconv.Itoa(page)}}
		var r struct {
			Matches []struct {
				IP        string   `json:"ip_str"`
				Port      int      `json:"port"`
				Hostnames []string `json:"hostnames"`
			} `json:"matches"`
			Total int `json:"total"`
		}
		if err := getJSON(ctx, c, Bases["shodan"]+"/shodan/host/search?"+q.Encode(), nil, &r); err != nil {
			return out, err
		}
		for _, m := range r.Matches {
			if len(m.Hostnames) == 0 {
				out = append(out, result{IP: m.IP, Port: m.Port})
			}
			for _, h := range m.Hostnames {
				out = append(out, result{IP: m.IP, Port: m.Port, Host: h})
			}
		}
		if page*100 >= r.Total {
			break
		}
	}
	return out, nil
}

// fofa searches domain="…"; the key is "email:key".
func fofa(ctx context.Context, c *http.Client, key, domain string, pages int) ([]result, error) {
	email, k, ok := strings.Cut(key, ":")
	if !ok {
		return nil, fmt.Errorf("fofa key must be email:key")
	}
	var out []result
	for page := 1; page <= pages; page++ {
		q := url.Values{"email": {email}, "key": {k}, "qbase64": {base64.StdEncoding.EncodeToString([]byte(`domain="` + domain + `"`))},
			"fields": {"ip,port,host"}, "size": {"100"}, "page": {strconv.Itoa(page)}}
		var r struct {
			Error   bool       `json:"error"`
			Errmsg  string     `json:"errmsg"`
			Results [][]string `json:"results"`
			Size    int        `json:"size"`
		}
		if err := getJSON(ctx, c, Bases["fofa"]+"/api/v1/search/all?"+q.Encode(), nil, &r); err != nil {
			return out, err
		}
		if r.Error {
			return out, fmt.Errorf("%s", r.Errmsg)
		}
		for _, row := range r.Results {
			if len(row) < 3 {
				continue
			}
			port, _ := strconv.Atoi(row[1])
			host := row[2]
			if u, err := url.Parse(host); err == nil && u.Hostname() != "" {
				host = u.Hostname()
			} else if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}
			out = append(out, result{IP: row[0], Port: port, Host: host})
		}
		if page*100 >= r.Size {
			break
		}
	}
	return out, nil
}

// netlas searches responses for host:*.domain.
func netlas(ctx context.Context, c *http.Client, key, domain string, pages int) ([]result, error) {
	var out []result
	for page := 0; page < pages; page++ {
		q := url.Values{"q": {"host:" + domain + " OR host:*." + domain}, "start": {strconv.Itoa(page * 20)}, "fields": {"ip,port,host"}}
		var r struct {
			Items []struct {
				Data struct {
					IP   string `json:"ip"`
					Port int    `json:"port"`
					Host string `json:"host"`
				} `json:"data"`
			} `json:"items"`
		}
		if err := getJSON(ctx, c, Bases["netlas"]+"/api/responses/?"+q.Encode(), http.Header{"X-Api-Key": {key}}, &r); err != nil {
			return out, err
		}
		for _, it := range r.Items {
			out = append(out, result{IP: it.Data.IP, Port: it.Data.Port, Host: it.Data.Host})
		}
		if len(r.Items) < 20 {
			break
		}
	}
	return out, nil
}
