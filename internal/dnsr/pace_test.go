package dnsr

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// slowLive answers every A question after d with an address.
func slowLive(d time.Duration, asked *atomic.Int32) func(context.Context, *dns.Msg, string) (*dns.Msg, error) {
	return func(ctx context.Context, q *dns.Msg, _ string) (*dns.Msg, error) {
		asked.Add(1)
		select {
		case <-time.After(d):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		m := new(dns.Msg)
		m.SetReply(q)
		if q.Question[0].Qtype == dns.TypeA {
			rr, _ := dns.NewRR(q.Question[0].Name + " 60 IN A 192.0.2.1")
			m.Answer = append(m.Answer, rr)
		}
		return m, nil
	}
}

func names(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("h%d.example.org", i)
	}
	return out
}

// 700 names with no pace take what dnsx -t 100 takes: names / threads
// round trips, not more. Resolvers answering in 20 ms, 128 queries in
// flight: 6 rounds of 20 ms, so under a second with room for a slow CI.
func TestResolveManyAsFastAsDnsxAtItsDefaults(t *testing.T) {
	p := New(Options{})
	var asked atomic.Int32
	p.Exchange = slowLive(20*time.Millisecond, &asked)
	t0 := time.Now()
	out := p.ResolveMany(context.Background(), names(700), 128)
	took := time.Since(t0)
	for _, a := range out {
		if a.Status != StatusOK {
			t.Fatalf("%s: %s %s", a.Name, a.Status, a.Err)
		}
	}
	if took > time.Second {
		t.Errorf("700 names took %s with 128 in flight and 20 ms a query", took)
	}
	if n := asked.Load(); n != 700 {
		t.Errorf("%d queries for 700 live names: one each is enough", n)
	}
}

// -dns-rate is per resolver and the default pool has six, so 700 names at
// -dns-rate 100 go out at 600 queries a second, a second and a bit: the
// pace is spread over the resolvers, not spent on one.
func TestResolveManyPaceIsPerResolver(t *testing.T) {
	p := New(Options{PerSecond: 100})
	var asked atomic.Int32
	p.Exchange = slowLive(time.Millisecond, &asked)
	t0 := time.Now()
	p.ResolveMany(context.Background(), names(700), 128)
	took := time.Since(t0)
	if took < 700*time.Millisecond || took > 3*time.Second {
		t.Errorf("700 queries at 100 a second on 6 resolvers took %s, want about 1.2 s", took)
	}
}

// One resolver that refuses this machine does not hold the run back: the
// names are answered by the others.
func TestResolveManyPastARefusingResolver(t *testing.T) {
	p := New(Options{})
	var asked atomic.Int32
	live := slowLive(time.Millisecond, &asked)
	p.Exchange = func(ctx context.Context, q *dns.Msg, server string) (*dns.Msg, error) {
		if strings.HasPrefix(server, "8.8.8.8") {
			m := new(dns.Msg)
			m.SetRcode(q, dns.RcodeRefused)
			return m, nil
		}
		return live(ctx, q, server)
	}
	out := p.ResolveMany(context.Background(), names(300), 128)
	for _, a := range out {
		if a.Status != StatusOK {
			t.Fatalf("%s: %s %s", a.Name, a.Status, a.Err)
		}
	}
}

// A name no resolver answered says which resolver failed last and why.
func TestFailedAnswerNamesTheResolver(t *testing.T) {
	p := New(Options{Resolvers: []string{"192.0.2.53"}})
	p.Exchange = func(_ context.Context, q *dns.Msg, _ string) (*dns.Msg, error) {
		m := new(dns.Msg)
		m.SetRcode(q, dns.RcodeRefused)
		return m, nil
	}
	a := p.Resolve(context.Background(), "x.example.org")
	if a.Status != StatusFailed || a.Resolver != "192.0.2.53:53" || !strings.Contains(a.Err, "REFUSED") {
		t.Errorf("%+v", a)
	}
}

// Resolvers that answer nothing are found out in one pass: asking every
// name again at a quarter of the speed would take minutes more for the same
// failures. The names say they got no answer.
func TestResolveManyDoesNotRepeatAPassThatMostlyFailed(t *testing.T) {
	p := New(Options{Timeout: 30 * time.Millisecond})
	var asked atomic.Int32
	p.Exchange = func(ctx context.Context, q *dns.Msg, _ string) (*dns.Msg, error) {
		asked.Add(1)
		select {
		case <-time.After(30 * time.Millisecond):
		case <-ctx.Done():
		}
		return nil, errors.New("read udp: i/o timeout")
	}
	t0 := time.Now()
	out := p.ResolveMany(context.Background(), names(200), 128)
	took := time.Since(t0)
	for _, a := range out {
		if a.Status != StatusFailed || a.Resolver == "" {
			t.Fatalf("%+v", a)
		}
	}
	if n := asked.Load(); n > 200*3 {
		t.Errorf("%d queries for 200 names at 3 attempts each: a second pass was made", n)
	}
	if took > 2*time.Second {
		t.Errorf("took %s", took)
	}
}
