package ledger

import (
	"context"
	"net"
)

// UDP records a datagram about to be sent to addr (ip:port), as TCP does
// a connect.
func UDP(ctx context.Context, host, addr string) {
	l := Active()
	if l == nil {
		return
	}
	ip, _, err := net.SplitHostPort(addr)
	if err != nil {
		ip = addr
	}
	name := host
	if name == "" {
		name = ip
	}
	rule := l.rule(name)
	if rule == "" && name != ip {
		rule = l.rule(ip)
	}
	l.Record(Entry{Kind: "udp", Target: addr, Host: host, Rule: rule, Collector: collectorOf(ctx)})
}
