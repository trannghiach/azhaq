// Package brutecol finds subdomains by resolving guesses: a wordlist under
// a domain (azhaq-dns-brute) and variations of names already found
// (azhaq-permute). Both are active techniques: they run only with their
// flag and an -allow scope, at the resolver pool's rate.
package brutecol

import (
	"context"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/trannghiach/azhaq/catalog"
	"github.com/trannghiach/azhaq/internal/dnsr"
	"github.com/trannghiach/azhaq/internal/normalize"
	"github.com/trannghiach/azhaq/types"
)

const (
	BruteName   = "azhaq-dns-brute"
	PermuteName = "azhaq-permute"
)

// An underscore is a legal label of a service or policy name (_dmarc,
// _domainkey, _acme-challenge).
var label = regexp.MustCompile(`^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$`)

// Brute resolves word.domain for every word in Words.
type Brute struct {
	Pool    *dnsr.Pool
	Wild    *dnsr.Wildcards
	Words   []string
	Workers int
}

func (b *Brute) Name() string { return BruteName }

func (b *Brute) Info() catalog.Info { return catalog.Info{Kind: catalog.Active, Flag: "dns-brute"} }

func (b *Brute) Inputs() []types.SeedType { return []types.SeedType{types.TypeDomain} }

func (b *Brute) Outputs() []string { return []string{"subdomains"} }

func (b *Brute) Run(ctx context.Context, seed types.Seed, emit func(types.Observation) error) (types.RunMeta, error) {
	domain := normalize.Hostname(seed.Keys["domain"])
	seen := map[string]bool{}
	var names []string
	for _, w := range b.Words {
		w = strings.ToLower(strings.Trim(strings.TrimSpace(w), "."))
		if w == "" || strings.HasPrefix(w, "#") {
			continue
		}
		ok := true
		for _, part := range strings.Split(w, ".") {
			ok = ok && label.MatchString(part)
		}
		if n := w + "." + domain; ok && !seen[n] {
			seen[n] = true
			names = append(names, n)
		}
	}
	answers := resolveFound(ctx, b.Pool, b.Wild, domain, names, b.Workers)
	found := nameList(answers)
	wild := b.Wild.Zone(ctx, domain)
	return report(ctx, emit, BruteName, domain, map[string]any{
		"domain": domain, "names": found, "answers": answerList(answers), "count": len(found), "tried": len(names), "wildcard_zone": wild,
	}, found)
}

// Permute resolves variations of each live hostname it is given: numbers
// and regions, and common words joined to the first label, put after it,
// before the name and in its place (api-dev, api.dev, dev.api, dev). Each
// name is tried once per run; the user limits what is asked, not this.
type Permute struct {
	Pool    *dnsr.Pool
	Wild    *dnsr.Wildcards
	Words   []string // default: PermuteWords
	PerHost int      // candidates per hostname; 0: every one
	Workers int

	mu    sync.Mutex
	tried map[string]bool // candidates, including the names found
}

// PermuteWords are joined to, put after and substituted for the first label:
// the words alterx's default patterns use, and others of the same kind.
var PermuteWords = dedupe([]string{
	"dev", "development", "stage", "staging", "stg", "test", "testing", "qa", "uat", "prod", "production",
	"preprod", "pre", "sandbox", "demo", "beta", "alpha", "internal", "int", "admin", "api", "app",
	"old", "new", "legacy", "v1", "v2", "v3", "backup", "bak", "tmp", "local", "corp", "eu", "us", "ap",
	"k8s", "origin", "raw", "web", "service", "grafana", "wordpress", "wp", "mta-sts", "tech", "private",
	"public", "login", "role", "backend", "cloud", "mail", "oauth", "oauth2", "vpn", "lab", "live", "data",
	"mobile", "search", "stats", "final", "ldap", "media", "docs", "eng", "engineering", "market", "compute",
	"cdn", "acc", "access", "blogs", "blog", "careers", "client", "cms", "cms1", "conf", "dmz", "drupal",
	"faq", "ir", "log", "logs", "dashboard", "monitor", "mysql", "mssql", "db", "partner", "payment", "pay",
	"office", "plugins", "shop", "prometheus", "stripe", "forum", "manager", "server", "core", "content",
	"ads", "shopify", "o1", "s1", "s3", "promotion", "temp", "my", "proxy", "asset", "assets", "atlas",
	"build", "builds", "code", "info", "image", "review", "developers", "developer", "administrator", "www",
	"www1", "www2", "netlify", "storage",
})

// PermuteNumbers follow the first label (api → api1, api2024), and
// PermuteRegions stand before the name (us-east-1.api.example.com).
var (
	PermuteNumbers = []string{"1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "18", "20", "21", "22", "23", "24",
		"2017", "2018", "2019", "2020", "2021", "2022", "2023", "2024"}
	PermuteRegions = []string{"us-east-1", "us-east-2", "us-west-1", "us-west-2", "eu-east-1", "eu-central-1"}
)

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func (p *Permute) Name() string { return PermuteName }

// Info: active, and only for names DNS found alive.
func (p *Permute) Info() catalog.Info {
	return catalog.Info{Kind: catalog.Active, Flag: "permute", After: "azhaq-dns"}
}

func (p *Permute) Inputs() []types.SeedType { return []types.SeedType{types.TypeHostname} }

func (p *Permute) Outputs() []string { return []string{"subdomains"} }

func (p *Permute) Run(ctx context.Context, seed types.Seed, emit func(types.Observation) error) (types.RunMeta, error) {
	host := normalize.Hostname(seed.Keys["fqdn"])
	domain := normalize.RegistrableDomain(host)
	p.mu.Lock()
	p.mu.Unlock()
	if domain == "" || host == domain || seed.Keys[types.ViaKey] == types.ViaPermute {
		// A name a variation found is not varied again: that would compound
		// guesses on guesses. A name a source gave stays, even when some
		// variation asked for it too.
		return types.RunMeta{Status: types.StatusOK}, nil
	}
	words := p.Words
	if len(words) == 0 {
		words = PermuteWords
	}
	limit := p.PerHost
	var names []string
	p.mu.Lock()
	if p.tried == nil {
		p.tried = map[string]bool{}
	}
	for _, n := range variants(host, words) {
		if limit > 0 && len(names) >= limit {
			break
		}
		if n != host && !p.tried[n] {
			p.tried[n] = true
			names = append(names, n)
		}
	}
	p.mu.Unlock()
	if len(names) == 0 {
		return types.RunMeta{Status: types.StatusOK}, nil
	}
	answers := resolveFound(ctx, p.Pool, p.Wild, domain, names, p.Workers)
	found := nameList(answers)
	meta, err := report(ctx, emit, PermuteName, host, map[string]any{
		"fqdn": host, "names": found, "answers": answerList(answers), "count": len(found), "tried": len(names),
	}, found)
	for _, h := range meta.NextHints {
		h.Keys[types.ViaKey] = types.ViaPermute
	}
	return meta, err
}

// variants of host: first label a.b.example.com is "a", rest "b.example.com".
// Every kind of candidate comes early (numbers and regions first, then each
// word in all its places), so that a limit on the names asked still takes
// all of them.
func variants(host string, words []string) []string {
	i := strings.IndexByte(host, '.')
	if i <= 0 {
		return nil
	}
	first, rest := host[:i], host[i:]
	seen := map[string]bool{host: true}
	var out []string
	put := func(n string) {
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	add := func(l string) {
		if label.MatchString(l) {
			put(l + rest)
		}
	}
	// numbers: api2 → api1, api3; web-01 → web-02; and alterx's, api → api1, api2024
	if m := trailingNumber.FindStringSubmatch(first); m != nil {
		n, _ := strconv.Atoi(m[2])
		for _, d := range []int{-2, -1, 1, 2, 3} {
			if v := n + d; v >= 0 {
				add(m[1] + pad(v, len(m[2])))
			}
		}
	} else {
		for _, d := range []string{"1", "2", "-1", "-2", "01", "02"} {
			add(first + d)
		}
	}
	for _, n := range PermuteNumbers {
		add(first + n)
	}
	for _, r := range PermuteRegions {
		if label.MatchString(r) {
			put(r + "." + host)
		}
	}
	for _, w := range words {
		if !label.MatchString(w) {
			continue
		}
		add(w)                      // the word in place of the first label
		add(first + "-" + w)        // api-dev
		add(w + "-" + first)        // dev-api
		put(w + "." + host)         // one level below: dev.api.example.com
		put(first + "." + w + rest) // the word after the first label: api.dev.example.com
		add(first + w)              // apidev
	}
	return out
}

var trailingNumber = regexp.MustCompile(`^(.*?)(\d+)$`)

// PermuteSample is two of the names Permute would ask for host: a number
// next to its first label and an environment word joined to it.
func PermuteSample(host string) []string {
	v := variants(host, PermuteWords[:1])
	var out []string
	for _, n := range v {
		if len(out) == 0 || strings.HasSuffix(strings.SplitN(n, ".", 2)[0], "-"+PermuteWords[0]) && len(out) == 1 {
			out = append(out, n)
		}
	}
	return out
}

func pad(n, width int) string {
	s := strconv.Itoa(n)
	for len(s) < width {
		s = "0" + s
	}
	return s
}

// resolveFound resolves names and keeps those with an address that is not
// a wildcard answer.
func resolveFound(ctx context.Context, pool *dnsr.Pool, wild *dnsr.Wildcards, apex string, names []string, workers int) []dnsr.Answer {
	if workers <= 0 {
		workers = 128
	}
	var found []dnsr.Answer
	for _, a := range pool.ResolveMany(dnsr.Bulk(ctx), names, workers) {
		// A CNAME whose target is gone is a name that exists: the kind a
		// takeover check wants most.
		if (a.Live() || len(a.CNAME) > 0) && !wild.Match(ctx, a.Name, apex, a) {
			found = append(found, a)
		}
	}
	return found
}

func nameList(as []dnsr.Answer) []string {
	out := make([]string, len(as))
	for i, a := range as {
		out[i] = a.Name
	}
	return out
}

// answerList is what DNS said of each name found, kept with the name: a run
// that does not resolve the names it finds (-depth 0) still has their addresses.
func answerList(as []dnsr.Answer) []map[string]any {
	out := make([]map[string]any, len(as))
	for i, a := range as {
		out[i] = map[string]any{"name": a.Name}
		if ips := a.IPs(); len(ips) > 0 {
			out[i]["ips"] = ips
		}
		if len(a.CNAME) > 0 {
			out[i]["cname"] = a.CNAME[0]
		}
	}
	return out
}

func report(ctx context.Context, emit func(types.Observation) error, name, source string, payload map[string]any, found []string) (types.RunMeta, error) {
	if ctx.Err() != nil {
		return types.RunMeta{Status: types.StatusCancelled}, ctx.Err()
	}
	raw, _ := json.Marshal(payload)
	if err := emit(types.Observation{
		Collector: name, Source: source, Kind: "subdomains",
		Payload: raw, Confidence: 0.9, ObservedAt: time.Now().UTC(),
	}); err != nil {
		return types.RunMeta{}, err
	}
	meta := types.RunMeta{Status: types.StatusOK, EmitCount: 1}
	for _, n := range found {
		meta.NextHints = append(meta.NextHints, types.Seed{Type: types.TypeHostname, Keys: map[string]string{"fqdn": n}})
	}
	return meta, nil
}
