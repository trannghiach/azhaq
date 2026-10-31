// Package egress is the only code that opens an outbound connection. A run
// has one Policy, built from its flags, and everything that leaves the
// machine goes through what the Policy hands out: HTTP clients for targets
// and for third-party sources, dialers, DNS exchanges, Chrome. Each one
// applies the run's controls (scope, -deny-path, the request budget, the
// pace, the proxies, the kill file) and enters what it sends in the ledger
// under its class: target, source or dns.
//
// A request that skips a control is a bug in the Policy, not in a call
// site, so no other package builds an http.Client, a dialer or a DNS client:
// the lint rules in .golangci.yml and the test in rules_test.go say so.
package egress
