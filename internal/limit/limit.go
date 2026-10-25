// Package limit paces requests per key: a target host, a third-party
// source, a DNS resolver. One Limiter is shared by everything that talks
// to the same kind of endpoint in a run.
package limit

import (
	"context"
	"sync"

	"golang.org/x/time/rate"
)

// Limiter is a set of token buckets, one per key, created on first use.
// A zero or negative rate means no limit.
type Limiter struct {
	mu        sync.Mutex
	perSecond float64
	burst     int
	overrides map[string]float64
	buckets   map[string]*rate.Limiter
}

// New returns a Limiter allowing perSecond requests per key with the given
// burst.
func New(perSecond float64, burst int) *Limiter {
	if burst < 1 {
		burst = 1
	}
	return &Limiter{
		perSecond: perSecond,
		burst:     burst,
		overrides: map[string]float64{},
		buckets:   map[string]*rate.Limiter{},
	}
}

// Set gives one key its own rate. It applies to buckets created after the
// call and to an existing bucket for that key.
func (l *Limiter) Set(key string, perSecond float64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.overrides[key] = perSecond
	if b, ok := l.buckets[key]; ok {
		b.SetLimit(toLimit(perSecond))
	}
}

// Wait blocks until key may send one request or ctx ends.
func (l *Limiter) Wait(ctx context.Context, key string) error {
	if l == nil {
		return ctx.Err()
	}
	return l.bucket(key).Wait(ctx)
}

func (l *Limiter) bucket(key string) *rate.Limiter {
	l.mu.Lock()
	defer l.mu.Unlock()
	if b, ok := l.buckets[key]; ok {
		return b
	}
	r := l.perSecond
	if o, ok := l.overrides[key]; ok {
		r = o
	}
	b := rate.NewLimiter(toLimit(r), l.burst)
	l.buckets[key] = b
	return b
}

func toLimit(perSecond float64) rate.Limit {
	if perSecond <= 0 {
		return rate.Inf
	}
	return rate.Limit(perSecond)
}
