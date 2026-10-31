package rdapcol

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/trannghiach/azhaq/catalog"
	"github.com/trannghiach/azhaq/internal/egress"
	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/internal/normalize"
	"github.com/trannghiach/azhaq/internal/timing"
	"github.com/trannghiach/azhaq/types"
)

const Name = "azhaq-rdap"

const tryTimeout = 6 * time.Second

type Collector struct {
	Client  *http.Client
	BaseURL string // tests; live default is rdap.org
}

func New(client *http.Client) *Collector {
	return &Collector{Client: registryClient(client)}
}

// registryClient is a client for the registries: a third-party source,
// not the target, so the target scope does not hold it and the ledger lists
// it as a source's.
func registryClient(client *http.Client) *http.Client {
	if client == nil {
		return egress.SourceClient(egress.SourceOptions{Timeout: tryTimeout})
	}
	c := *egress.SourceFrom(client)
	c.Timeout = tryTimeout
	return &c
}

func Register(cat *catalog.Catalog, client *http.Client) {
	cat.MustRegister(New(client))
}

func (c *Collector) Name() string { return Name }

// Info: this collector only asks third parties or DNS resolvers.
func (c *Collector) Info() catalog.Info { return catalog.Info{Kind: catalog.Passive} }

func (c *Collector) Inputs() []types.SeedType {
	return []types.SeedType{types.TypeDomain, types.TypeOrganization}
}

func (c *Collector) Outputs() []string { return []string{"rdap", "organization", "domain"} }

// Asks: rdap.org once for a domain (it redirects to the registry's
// server). An organization asks nobody: there is no public search by name.
func (c *Collector) Asks(seed types.Seed) []string {
	domain := normalize.Hostname(seed.Keys["domain"])
	if seed.Type != types.TypeDomain || domain == "" || (normalize.SpecialUse(domain) && c.BaseURL == "") {
		return nil
	}
	return []string{hostOf(c.domainURL(domain))}
}

func (c *Collector) Run(ctx context.Context, seed types.Seed, emit func(types.Observation) error) (types.RunMeta, error) {
	switch seed.Type {
	case types.TypeDomain:
		return c.runDomain(ctx, seed, emit)
	case types.TypeOrganization:
		return c.runOrg(ctx, seed, emit)
	default:
		return types.RunMeta{Status: types.StatusOK}, nil
	}
}

func (c *Collector) runDomain(ctx context.Context, seed types.Seed, emit func(types.Observation) error) (types.RunMeta, error) {
	domain := normalize.Hostname(seed.Keys["domain"])
	if domain == "" {
		return types.RunMeta{Status: types.StatusError, Error: "empty domain"}, nil
	}
	if normalize.SpecialUse(domain) && c.BaseURL == "" {
		payload, _ := json.Marshal(map[string]any{"domain": domain, "status": 0, "skipped": "reserved"})
		_ = emit(types.Observation{
			Collector: Name, Source: "rdap", Kind: "rdap",
			Payload: payload, Confidence: 0, ObservedAt: time.Now().UTC(),
		})
		return types.RunMeta{Status: types.StatusOK, EmitCount: 1}, nil
	}
	rawURL := c.domainURL(domain)
	doc, src, status, err := c.pull(ctx, rawURL, "rdap.domain")
	if err != nil {
		return types.RunMeta{Status: types.StatusError, Error: err.Error()}, err
	}
	info := parseRDAP(doc)
	if info.Domain == "" {
		info.Domain = domain
	}
	payload, _ := json.Marshal(map[string]any{
		"domain":      info.Domain,
		"registrar":   info.Registrar,
		"registrant":  info.Registrant,
		"status":      status,
		"nameservers": info.Nameservers,
		"expires":     info.Expires,
	})
	if err := emit(types.Observation{
		Collector:  Name,
		Source:     src,
		Kind:       "rdap",
		Payload:    payload,
		Confidence: 0.85,
		ObservedAt: time.Now().UTC(),
	}); err != nil {
		return types.RunMeta{}, err
	}
	meta := types.RunMeta{Status: types.StatusOK, EmitCount: 1}
	if status == http.StatusTooManyRequests || status == http.StatusServiceUnavailable {
		meta.Status = types.StatusDegraded
	}
	// The registrant owns the domain; the registrar only sold it
	// (MarkMonitor, Amazon Registrar) and privacy services stand in for
	// whoever hides behind them.
	if org := info.Registrant; org != "" && !privacyService.MatchString(org) {
		meta.NextHints = append(meta.NextHints, types.Seed{
			Type: types.TypeOrganization,
			Keys: map[string]string{"name": org},
		})
	}
	return meta, nil
}

var privacyService = regexp.MustCompile(`(?i)redacted|privacy|proxy|withheld|not disclosed|data protected|whoisguard|contact privacy|perfect privacy|statutory masking`)

func (c *Collector) runOrg(ctx context.Context, seed types.Seed, emit func(types.Observation) error) (types.RunMeta, error) {
	name := strings.TrimSpace(seed.Keys["name"])
	if name == "" {
		name = strings.TrimSpace(seed.Keys["handle"])
	}
	if name == "" {
		return types.RunMeta{Status: types.StatusError, Error: "empty organization"}, nil
	}
	// Live RDAP has no universal org→domain search. Tests may expose /entities?fn=.
	if c.BaseURL == "" {
		payload, _ := json.Marshal(map[string]any{
			"name":      name,
			"extracted": 0,
			"note":      "no public org→domain search; seed domains with -url/-in or a connector",
		})
		if err := emit(types.Observation{
			Collector: Name, Source: "rdap", Kind: "organization",
			Payload: payload, Confidence: 0.7, ObservedAt: time.Now().UTC(),
		}); err != nil {
			return types.RunMeta{}, err
		}
		return types.RunMeta{Status: types.StatusOK, EmitCount: 1}, nil
	}
	payload, _ := json.Marshal(map[string]any{"name": name})
	if err := emit(types.Observation{
		Collector:  Name,
		Source:     "rdap",
		Kind:       "organization",
		Payload:    payload,
		Confidence: 0.7,
		ObservedAt: time.Now().UTC(),
	}); err != nil {
		return types.RunMeta{}, err
	}
	meta := types.RunMeta{Status: types.StatusOK, EmitCount: 1}
	rawURL := strings.TrimRight(c.BaseURL, "/") + "/entities?fn=" + url.QueryEscape(name)
	doc, src, _, err := c.pull(ctx, rawURL, "rdap.entity")
	if err != nil || len(doc) == 0 {
		return meta, nil
	}
	info := parseRDAP(doc)
	for _, d := range info.Domains {
		d = normalize.Hostname(d)
		if d == "" {
			continue
		}
		up, _ := json.Marshal(map[string]any{"domain": d, "via": "rdap", "name": name})
		if err := emit(types.Observation{
			Collector:  Name,
			Source:     src,
			Kind:       "domain",
			Payload:    up,
			Confidence: 0.6,
			ObservedAt: time.Now().UTC(),
		}); err != nil {
			return meta, err
		}
		meta.EmitCount++
		meta.NextHints = append(meta.NextHints, types.Seed{
			Type: types.TypeDomain,
			Keys: map[string]string{"domain": d},
		})
	}
	return meta, nil
}

func (c *Collector) domainURL(domain string) string {
	if c.BaseURL != "" {
		return strings.TrimRight(c.BaseURL, "/") + "/domain/" + url.PathEscape(domain)
	}
	return "https://rdap.org/domain/" + url.PathEscape(domain)
}

func (c *Collector) pull(ctx context.Context, rawURL, span string) (json.RawMessage, string, int, error) {
	done := timing.Start(ctx, span)
	defer done()
	ctx, cancel := context.WithTimeout(ctx, tryTimeout)
	defer cancel()
	cli := c.Client
	if cli == nil {
		cli = registryClient(nil)
	}
	cli = noFollow(cli)

	current := rawURL
	for hop := 0; hop < 6; hop++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, current, nil)
		if err != nil {
			return nil, current, 0, err
		}
		req.Header.Set("User-Agent", fetch.ToolAgent)
		req.Header.Set("Accept", "application/rdap+json, application/json")
		resp, err := cli.Do(req)
		if err != nil {
			return nil, current, 0, err
		}
		if isRedirect(resp.StatusCode) {
			loc := strings.TrimSpace(resp.Header.Get("Location"))
			resp.Body.Close()
			if loc == "" {
				return nil, current, resp.StatusCode, fmt.Errorf("%s %d", hostOf(current), resp.StatusCode)
			}
			next, err := resp.Request.URL.Parse(loc)
			if err != nil {
				return nil, current, resp.StatusCode, err
			}
			if next.Scheme != "http" && next.Scheme != "https" {
				return nil, current, resp.StatusCode, fmt.Errorf("%s %d", hostOf(current), resp.StatusCode)
			}
			current = next.String()
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
		resp.Body.Close()
		if err != nil {
			return nil, current, resp.StatusCode, err
		}
		switch resp.StatusCode {
		case http.StatusOK:
			if len(body) == 0 {
				return json.RawMessage(`{}`), current, resp.StatusCode, nil
			}
			return json.RawMessage(body), current, resp.StatusCode, nil
		case http.StatusNotFound, http.StatusTooManyRequests, http.StatusServiceUnavailable, http.StatusNotImplemented:
			return json.RawMessage(`{}`), current, resp.StatusCode, nil
		default:
			return nil, current, resp.StatusCode, fmt.Errorf("%s %d", hostOf(current), resp.StatusCode)
		}
	}
	return nil, current, 0, fmt.Errorf("%s redirect loop", hostOf(current))
}

// noFollow is c without redirects.
func noFollow(c *http.Client) *http.Client {
	cp := *c
	cp.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &cp
}

func isRedirect(status int) bool {
	switch status {
	case 301, 302, 303, 307, 308:
		return true
	default:
		return false
	}
}

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "rdap"
	}
	return u.Host
}

type rdapInfo struct {
	Domain      string
	Registrar   string
	Registrant  string
	Nameservers []string
	Expires     string
	Domains     []string
}

func parseRDAP(raw json.RawMessage) rdapInfo {
	var doc struct {
		LDHName     string `json:"ldhName"`
		Nameservers []struct {
			LDHName string `json:"ldhName"`
		} `json:"nameservers"`
		Entities []struct {
			Roles      []string `json:"roles"`
			VCardArray []any    `json:"vcardArray"`
			Domains    []string `json:"domains"`
		} `json:"entities"`
		Events []struct {
			Action string `json:"eventAction"`
			Date   string `json:"eventDate"`
		} `json:"events"`
		Domains []string `json:"domains"`
	}
	_ = json.Unmarshal(raw, &doc)
	info := rdapInfo{Domain: normalize.Hostname(doc.LDHName), Domains: append([]string{}, doc.Domains...)}
	for _, ns := range doc.Nameservers {
		if n := normalize.Hostname(ns.LDHName); n != "" {
			info.Nameservers = append(info.Nameservers, n)
		}
	}
	for _, ev := range doc.Events {
		if strings.EqualFold(ev.Action, "expiration") {
			info.Expires = ev.Date
		}
	}
	for _, ent := range doc.Entities {
		fn := vcardFN(ent.VCardArray)
		info.Domains = append(info.Domains, ent.Domains...)
		for _, role := range ent.Roles {
			switch strings.ToLower(role) {
			case "registrar":
				if info.Registrar == "" {
					info.Registrar = fn
				}
			case "registrant":
				if info.Registrant == "" {
					info.Registrant = fn
				}
			}
		}
		if info.Registrar == "" && fn != "" {
			info.Registrar = fn
		}
	}
	return info
}

func vcardFN(arr []any) string {
	if len(arr) < 2 {
		return ""
	}
	props, ok := arr[1].([]any)
	if !ok {
		return ""
	}
	for _, p := range props {
		row, ok := p.([]any)
		if !ok || len(row) < 4 {
			continue
		}
		name, _ := row[0].(string)
		if !strings.EqualFold(name, "fn") {
			continue
		}
		if s, ok := row[len(row)-1].(string); ok {
			return strings.TrimSpace(s)
		}
	}
	return ""
}
