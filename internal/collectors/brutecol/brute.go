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

var label = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

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
	found := resolveFound(ctx, b.Pool, b.Wild, domain, names, b.Workers)
	wild := b.Wild.Zone(ctx, domain)
	return report(ctx, emit, BruteName, domain, map[string]any{
		"domain": domain, "names": found, "count": len(found), "tried": len(names), "wildcard_zone": wild,
	}, found)
}

// Permute resolves variations of each live hostname it is given: numbers
// next to the ones in the first label, common environment words joined to
// it, and those words in its place. Each name is tried once per run.
type Permute struct {
	Pool    *dnsr.Pool
	Wild    *dnsr.Wildcards
	Words   []string // default: PermuteWords
	PerHost int      // candidates per hostname; default 120
	Workers int

	mu    sync.Mutex
	tried map[string]bool // candidates, including the names found
}

// PermuteWords are joined to and substituted for the first label.
var PermuteWords = []string{
	"dev", "development", "stage", "staging", "stg", "test", "testing", "qa", "uat", "prod", "production",
	"preprod", "pre", "sandbox", "demo", "beta", "alpha", "internal", "int", "admin", "api", "app",
	"old", "new", "legacy", "v1", "v2", "v3", "backup", "bak", "tmp", "local", "corp", "eu", "us", "ap",
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
	ownFind := p.tried[host]
	p.mu.Unlock()
	if domain == "" || host == domain || ownFind {
		// A name this collector guessed is not permuted again: that would
		// compound guesses on guesses.
		return types.RunMeta{Status: types.StatusOK}, nil
	}
	words := p.Words
	if len(words) == 0 {
		words = PermuteWords
	}
	limit := p.PerHost
	if limit <= 0 {
		limit = 120
	}
	var names []string
	p.mu.Lock()
	if p.tried == nil {
		p.tried = map[string]bool{}
	}
	for _, n := range variants(host, words) {
		if len(names) >= limit {
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
	found := resolveFound(ctx, p.Pool, p.Wild, domain, names, p.Workers)
	return report(ctx, emit, PermuteName, host, map[string]any{
		"fqdn": host, "names": found, "count": len(found), "tried": len(names),
	}, found)
}

// variants of host: first label a.b.example.com is "a", rest "b.example.com".
func variants(host string, words []string) []string {
	i := strings.IndexByte(host, '.')
	if i <= 0 {
		return nil
	}
	first, rest := host[:i], host[i:]
	var out []string
	add := func(l string) {
		if label.MatchString(l) {
			out = append(out, l+rest)
		}
	}
	// numbers: api2 → api1, api3; web-01 → web-02
	if m := regexp.MustCompile(`^(.*?)(\d+)$`).FindStringSubmatch(first); m != nil {
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
	for _, w := range words {
		add(w + "-" + first)
		add(first + "-" + w)
		add(first + w)
	}
	for _, w := range words {
		add(w) // the word in place of the first label
	}
	for _, w := range words {
		if label.MatchString(w) {
			out = append(out, w+"."+host) // one level below
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
func resolveFound(ctx context.Context, pool *dnsr.Pool, wild *dnsr.Wildcards, apex string, names []string, workers int) []string {
	if workers <= 0 {
		workers = 128
	}
	var found []string
	for _, a := range pool.ResolveMany(ctx, names, workers) {
		if a.Live() && !wild.Match(ctx, a.Name, apex, a) {
			found = append(found, a.Name)
		}
	}
	return found
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
