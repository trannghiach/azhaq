package dnsr

import (
	"context"
	"math/rand/v2"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// RootServers are asked first by Trace.
var RootServers = []string{
	"198.41.0.4:53", "170.247.170.2:53", "192.33.4.12:53", "199.7.91.13:53", "192.203.230.10:53",
	"192.5.5.241:53", "192.112.36.4:53", "198.97.190.53:53", "192.36.148.17:53", "192.58.128.30:53",
	"193.0.14.129:53", "199.7.83.42:53", "202.12.27.33:53",
}

// Trace follows the delegations for host from the root servers to the
// answer: each step is one server's reply, with the name servers it
// delegates to (ns) when it refers the question onward. It stops at an
// answer, at an error, or after max steps. Servers are asked over UDP,
// with TCP on truncation, at the pool's timeout.
func (p *Pool) Trace(ctx context.Context, host string, qtype uint16, max int) *Chain {
	chain := &Chain{Host: host}
	servers := append([]string(nil), RootServers...)
	if p.TraceRoots != nil {
		servers = append([]string(nil), p.TraceRoots...)
	}
	rand.Shuffle(len(servers), func(i, j int) { servers[i], servers[j] = servers[j], servers[i] })
	port := "53"
	if p.TracePort != "" {
		port = p.TracePort
	}
	name := dns.Fqdn(host)
	asked := map[string]bool{}
	for step := 0; step < max && ctx.Err() == nil; step++ {
		var m *dns.Msg
		var from string
		for _, s := range servers {
			if asked[s+"|"+name] {
				continue
			}
			asked[s+"|"+name] = true
			q := new(dns.Msg)
			q.SetQuestion(name, qtype)
			q.SetEdns0(4096, false)
			in, err := p.exchangeAt(ctx, q, s)
			if err == nil && in != nil {
				m, from = in, s
				break
			}
		}
		if m == nil {
			return chain
		}
		d := &Data{Host: host, rcodes: map[uint16]int{}, answered: true, Resolver: []string{from}, Timestamp: time.Now()}
		d.add(m, "", qtype, false)
		d.Resolver = []string{from}
		var next []string
		var glue = map[string][]string{}
		for _, rr := range m.Extra {
			if a, ok := rr.(*dns.A); ok {
				glue[strings.ToLower(a.Hdr.Name)] = append(glue[strings.ToLower(a.Hdr.Name)], net.JoinHostPort(a.A.String(), port))
			}
		}
		for _, rr := range m.Ns {
			if ns, ok := rr.(*dns.NS); ok {
				d.NS = append(d.NS, trimDot(ns.Ns))
				d.AllRecords = append(d.AllRecords, rr.String())
				next = append(next, glue[strings.ToLower(ns.Ns)]...)
				if len(glue[strings.ToLower(ns.Ns)]) == 0 {
					if a := p.Resolve(ctx, ns.Ns); len(a.A) > 0 {
						next = append(next, net.JoinHostPort(a.A[0], port))
					}
				}
			}
		}
		d.dedupe()
		chain.Data = append(chain.Data, d)
		if len(m.Answer) > 0 {
			if c := cnameTarget(m); c != "" && !hasAnswer(m, qtype) {
				name = c // follow a CNAME that ended the answer
				servers = append([]string(nil), RootServers...)
				if p.TraceRoots != nil {
					servers = append([]string(nil), p.TraceRoots...)
				}
				continue
			}
			return chain
		}
		if len(next) == 0 {
			return chain
		}
		servers = dedupe(next)
	}
	return chain
}

func cnameTarget(m *dns.Msg) string {
	for _, rr := range m.Answer {
		if c, ok := rr.(*dns.CNAME); ok {
			return c.Target
		}
	}
	return ""
}

// exchangeAt asks one server directly (not through the pool's resolvers).
func (p *Pool) exchangeAt(ctx context.Context, q *dns.Msg, server string) (*dns.Msg, error) {
	q.RecursionDesired = false
	return p.x.ExchangeAt(ctx, q, server)
}
