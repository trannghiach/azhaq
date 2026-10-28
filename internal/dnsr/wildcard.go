package dnsr

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"sync"

	"github.com/trannghiach/azhaq/internal/normalize"
)

// Wildcards finds names that only resolve because their zone answers for
// every label (*.example.com). Each parent zone is probed once with random
// labels; a name is a wildcard answer when all its addresses, or its CNAME
// target, are what the random labels got.
type Wildcards struct {
	pool  *Pool
	mu    sync.Mutex
	zones map[string]*zone
}

type zone struct {
	once   sync.Once
	on     bool
	ips    map[string]bool
	cnames map[string]bool
}

// NewWildcards returns a detector that probes through pool.
func NewWildcards(pool *Pool) *Wildcards {
	return &Wildcards{pool: pool, zones: map[string]*zone{}}
}

// Match reports whether a, the answer for name, is what a wildcard in one
// of name's parent zones (up to and including apex) returns.
func (w *Wildcards) Match(ctx context.Context, name, apex string, a Answer) bool {
	if !a.Live() && len(a.CNAME) == 0 {
		return false
	}
	name, apex = normalize.Hostname(name), normalize.Hostname(apex)
	for p := parent(name); p != "" && (p == apex || strings.HasSuffix(p, "."+apex)); p = parent(p) {
		z := w.zone(ctx, p)
		if z.on && z.covers(a) {
			return true
		}
	}
	return false
}

// Zone reports whether zone answers for random labels.
func (w *Wildcards) Zone(ctx context.Context, name string) bool {
	return w.zone(ctx, normalize.Hostname(name)).on
}

func (w *Wildcards) zone(ctx context.Context, name string) *zone {
	w.mu.Lock()
	z, ok := w.zones[name]
	if !ok {
		z = &zone{ips: map[string]bool{}, cnames: map[string]bool{}}
		w.zones[name] = z
	}
	w.mu.Unlock()
	z.once.Do(func() {
		for i := 0; i < 2; i++ {
			a := w.pool.Resolve(ctx, randomLabel()+"."+name)
			if !a.Live() && len(a.CNAME) == 0 {
				continue
			}
			z.on = true
			w.pool.wildcard(name)
			for _, ip := range a.IPs() {
				z.ips[ip] = true
			}
			for _, c := range a.CNAME {
				z.cnames[c] = true
			}
		}
	})
	return z
}

func (z *zone) covers(a Answer) bool {
	for _, c := range a.CNAME {
		if z.cnames[c] {
			return true
		}
	}
	ips := a.IPs()
	if len(ips) == 0 {
		return false
	}
	for _, ip := range ips {
		if !z.ips[ip] {
			return false
		}
	}
	return true
}

func parent(name string) string {
	i := strings.IndexByte(name, '.')
	if i < 0 {
		return ""
	}
	return name[i+1:]
}

// probePrefix starts every random label: the pool knows a probe by it.
const probePrefix = "azhaq-"

func randomLabel() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return probePrefix + hex.EncodeToString(b[:])
}
