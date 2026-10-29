// Command labdns is a resolver for the local DNS lab: it answers the zone
// azqlab.lan itself and forwards every other name upstream, so wildcard and
// takeover behaviour can be checked without a public zone.
//
//	go run ./bench/labdns -addr 127.0.0.1:5354
//
// azqlab.lan holds real names, a wildcard subzone and dangling CNAMEs; the
// list is in bench/truth/labdns.md.
package main

import (
	"flag"
	"log"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// zone is azqlab.lan: name → records, in zone-file syntax without the name.
var zone = map[string][]string{
	"azqlab.lan.":           {"A 127.0.0.1"},
	"www.azqlab.lan.":       {"A 127.0.0.1"},
	"app.azqlab.lan.":       {"A 127.0.0.1"},
	"api.azqlab.lan.":       {"CNAME app.azqlab.lan."},
	"mail.azqlab.lan.":      {"A 127.0.0.1"},
	"dev.azqlab.lan.":       {"A 127.0.0.1"},
	"vpn.azqlab.lan.":       {"A 127.0.0.1"},
	"staging.azqlab.lan.":   {"CNAME app.azqlab.lan."},
	"old-shop.azqlab.lan.":  {"CNAME azq-lab-gone-7c1e.azurewebsites.net."},
	"assets.azqlab.lan.":    {"CNAME azq-lab-gone-7c1e.azureedge.net."},
	"docs.azqlab.lan.":      {"CNAME azq-lab-gone-7c1e.us-east-1.elasticbeanstalk.com."},
	"real.wild.azqlab.lan.": {"A 127.0.0.3"},
}

// wildcard answers any name under it that zone does not hold.
const wildcard, wildcardA = ".wild.azqlab.lan.", "127.0.0.2"

func main() {
	addr := flag.String("addr", "127.0.0.1:5354", "listen address (UDP and TCP)")
	upstream := flag.String("upstream", "1.1.1.1:53", "resolver for names outside azqlab.lan")
	flag.Parse()
	client := &dns.Client{Timeout: 3 * time.Second}
	dns.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		q := r.Question[0]
		name := strings.ToLower(q.Name)
		if name != "azqlab.lan." && !strings.HasSuffix(name, ".azqlab.lan.") {
			if in, _, err := client.Exchange(r, *upstream); err == nil {
				_ = w.WriteMsg(in)
				return
			}
			m := new(dns.Msg)
			m.SetRcode(r, dns.RcodeServerFailure)
			_ = w.WriteMsg(m)
			return
		}
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		recs, ok := zone[name]
		if !ok && strings.HasSuffix(name, wildcard) {
			recs, ok = []string{"A " + wildcardA}, true
		}
		if !ok {
			m.Rcode = dns.RcodeNameError
			_ = w.WriteMsg(m)
			return
		}
		for _, rec := range recs {
			rr, err := dns.NewRR(name + " 60 IN " + rec)
			if err != nil {
				continue
			}
			if rr.Header().Rrtype == q.Qtype || rr.Header().Rrtype == dns.TypeCNAME {
				m.Answer = append(m.Answer, rr)
			}
			// Follow a CNAME as a recursive resolver does: in the zone, or
			// upstream, whose NXDOMAIN for the target is the answer's code.
			if c, ok := rr.(*dns.CNAME); ok && q.Qtype != dns.TypeCNAME {
				sub := new(dns.Msg)
				sub.SetQuestion(c.Target, q.Qtype)
				if t, ok := zone[c.Target]; ok {
					for _, rec := range t {
						if rr, err := dns.NewRR(c.Target + " 60 IN " + rec); err == nil && rr.Header().Rrtype == q.Qtype {
							m.Answer = append(m.Answer, rr)
						}
					}
				} else if in, _, err := client.Exchange(sub, *upstream); err == nil {
					m.Answer = append(m.Answer, in.Answer...)
					m.Rcode = in.Rcode
				}
			}
		}
		_ = w.WriteMsg(m)
	})
	for _, n := range []string{"udp", "tcp"} {
		srv := &dns.Server{Addr: *addr, Net: n}
		go func() { log.Fatal(srv.ListenAndServe()) }()
	}
	log.Printf("labdns on %s, azqlab.lan answered here, the rest forwarded to %s", *addr, *upstream)
	select {}
}
