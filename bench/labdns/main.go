// Command labdns is a resolver for the local DNS lab: it answers the zone
// azqlab.lan itself and forwards every other name upstream, so wildcard and
// takeover behaviour can be checked without a public zone.
//
//	go run ./bench/labdns -addr 127.0.0.1:5354
//
// azqlab.lan holds real names, a wildcard subzone, dangling CNAMEs, records
// of every common type, a reverse zone for 127.0.0.0/24 and a zone
// transfer (TCP); the list is in bench/truth/labdns.md. With -stats ADDR
// it serves what it was asked (by type, transport, name) as JSON on
// ADDR/stats and clears it on ADDR/reset: evidence a test reads from the
// resolver's side.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// zone is azqlab.lan: name → records, in zone-file syntax without the name.
var zone = map[string][]string{
	"azqlab.lan.": {
		"A 127.0.0.1",
		"SOA ns1.azqlab.lan. hostmaster.azqlab.lan. 2026103001 3600 600 86400 60",
		"NS ns1.azqlab.lan.",
		"NS ns2.azqlab.lan.",
		"MX 10 mail.azqlab.lan.",
		"MX 20 app.azqlab.lan.",
		`TXT "v=spf1 mx -all"`,
		`TXT "azqlab-verification=7c1e"`,
		`CAA 0 issue "letsencrypt.org"`,
		`CAA 0 iodef "mailto:security@azqlab.lan"`,
	},
	"ns1.azqlab.lan.":       {"A 127.0.0.1"},
	"ns2.azqlab.lan.":       {"A 127.0.0.1"},
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

	// Record types beyond A and CNAME.
	"v6.azqlab.lan.":            {"AAAA ::1"},                            // an AAAA-only name
	"dual.azqlab.lan.":          {"A 127.0.0.1", "AAAA ::1", "AAAA ::2"}, // dual stack, two AAAA
	"_sip._tcp.azqlab.lan.":     {"SRV 10 5 5060 app.azqlab.lan.", "SRV 20 5 5061 www.azqlab.lan."},
	"_dmarc.azqlab.lan.":        {`TXT "v=DMARC1; p=none; rua=mailto:dmarc@azqlab.lan"`},
	"txt.azqlab.lan.":           {`TXT "one"`, `TXT "two" "parts"`},
	"big.azqlab.lan.":           {"TXT " + bigTXT()}, // 1,200 bytes: over 512, under 4,096
	"nodata.azqlab.lan.":        {`TXT "only text here"`},
	"mx.azqlab.lan.":            {"MX 5 mail.azqlab.lan."},
	"hosts.azqlab.lan.":         {"A 127.0.0.5", "A 127.0.0.6", "A 127.0.0.7"},
	"servfail.azqlab.lan.":      nil, // answered SERVFAIL (rcodes)
	"refused.azqlab.lan.":       nil, // answered REFUSED (rcodes)
	"deep.sub.azqlab.lan.":      {"A 127.0.0.8"},
	"empty.nonterm.azqlab.lan.": {"A 127.0.0.9"}, // nonterm.azqlab.lan exists without records
}

// rcodes are names answered with a code and no data.
var rcodes = map[string]int{
	"servfail.azqlab.lan.": dns.RcodeServerFailure,
	"refused.azqlab.lan.":  dns.RcodeRefused,
}

// ptr is the reverse zone 0.0.127.in-addr.arpa: last octet → names.
var ptr = map[string][]string{
	"1":   {"www.azqlab.lan.", "localhost."},
	"2":   {"wild.azqlab.lan."},
	"3":   {"real.wild.azqlab.lan."},
	"4":   {"dev.azqlab.lan."},
	"5":   {"mail.azqlab.lan."},
	"6":   {"vpn.azqlab.lan."},
	"7":   {"app.azqlab.lan."},
	"100": {"h100.azqlab.lan."},
	"101": {"h101.azqlab.lan."},
	"102": {"h102.azqlab.lan."},
	"103": {"h103.azqlab.lan."},
	"104": {"h104.azqlab.lan."},
}

const ptrZone = "0.0.127.in-addr.arpa."

// wildcard answers any name under it that zone does not hold.
const wildcard, wildcardA = ".wild.azqlab.lan.", "127.0.0.2"

// bigTXT is a TXT value of five 240-byte strings.
func bigTXT() string {
	var parts []string
	for i := 0; i < 5; i++ {
		parts = append(parts, strconv.Quote(strings.Repeat(string(rune('a'+i)), 240)))
	}
	return strings.Join(parts, " ")
}

// nonterminals: names that exist only because a name below them does.
func exists(name string) bool {
	if _, ok := zone[name]; ok {
		return true
	}
	for n := range zone {
		if strings.HasSuffix(n, "."+name) {
			return true
		}
	}
	return false
}

// counters is what the lab was asked.
type counters struct {
	mu        sync.Mutex
	since     time.Time
	total     int64
	byNet     map[string]int64
	byType    map[string]int64
	truncated int64
	names     map[string]int64
	inflight  int64
	peak      int64
	second    int64 // the second (unix) being counted
	inSecond  int64
	peakQPS   int64
}

func newCounters() *counters {
	return &counters{since: time.Now(), byNet: map[string]int64{}, byType: map[string]int64{}, names: map[string]int64{}}
}

func (c *counters) ask(network string, q dns.Question) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.total++
	c.byNet[network]++
	c.byType[dns.TypeToString[q.Qtype]]++
	c.names[strings.ToLower(q.Name)]++
	if now := time.Now().Unix(); now != c.second {
		c.second, c.inSecond = now, 0
	}
	if c.inSecond++; c.inSecond > c.peakQPS {
		c.peakQPS = c.inSecond
	}
}

func (c *counters) snapshot(withNames bool) map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := map[string]any{
		"since": c.since.Format(time.RFC3339), "total": c.total, "by_net": c.byNet, "by_type": c.byType,
		"truncated": c.truncated, "unique_names": len(c.names), "peak_in_flight": atomic.LoadInt64(&c.peak), "peak_per_second": c.peakQPS,
	}
	if withNames {
		names := make([]string, 0, len(c.names))
		for n := range c.names {
			names = append(names, n)
		}
		sort.Strings(names)
		out["names"] = names
	}
	return out
}

func (c *counters) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.since, c.total, c.truncated, c.inSecond, c.peakQPS = time.Now(), 0, 0, 0, 0
	c.byNet, c.byType, c.names = map[string]int64{}, map[string]int64{}, map[string]int64{}
	atomic.StoreInt64(&c.peak, atomic.LoadInt64(&c.inflight))
}

func rr(name, rec string) dns.RR {
	r, err := dns.NewRR(name + " 60 IN " + rec)
	if err != nil {
		log.Printf("bad record %s %s: %v", name, rec, err)
		return nil
	}
	return r
}

// maxUDP is the size a reply may have: the EDNS0 size the question
// advertised, or 512.
func maxUDP(r *dns.Msg) int {
	if o := r.IsEdns0(); o != nil {
		return int(o.UDPSize())
	}
	return dns.MinMsgSize
}

func main() {
	addr := flag.String("addr", "127.0.0.1:5354", "listen address (UDP and TCP)")
	upstream := flag.String("upstream", "1.1.1.1:53", "resolver for names outside azqlab.lan")
	statsAddr := flag.String("stats", "", "serve what was asked as JSON on this address: /stats, /stats?names=1, /reset")
	delay := flag.Duration("delay", 0, "wait this long before each answer (makes queries in flight measurable)")
	axfr := flag.Bool("axfr", true, "allow zone transfers of azqlab.lan over TCP")
	flag.Parse()
	client := &dns.Client{Timeout: 3 * time.Second}
	stats := newCounters()
	if *statsAddr != "" {
		mux := http.NewServeMux()
		mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(stats.snapshot(r.URL.Query().Get("names") != ""))
		})
		mux.HandleFunc("/reset", func(w http.ResponseWriter, _ *http.Request) {
			stats.reset()
			fmt.Fprintln(w, "ok")
		})
		go func() { log.Fatal(http.ListenAndServe(*statsAddr, mux)) }()
	}
	dns.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		if len(r.Question) == 0 {
			m := new(dns.Msg)
			m.SetRcode(r, dns.RcodeFormatError)
			_ = w.WriteMsg(m)
			return
		}
		q := r.Question[0]
		network := w.RemoteAddr().Network()
		stats.ask(network, q)
		n := atomic.AddInt64(&stats.inflight, 1)
		defer atomic.AddInt64(&stats.inflight, -1)
		for {
			p := atomic.LoadInt64(&stats.peak)
			if n <= p || atomic.CompareAndSwapInt64(&stats.peak, p, n) {
				break
			}
		}
		if *delay > 0 {
			time.Sleep(*delay)
		}
		name := strings.ToLower(q.Name)
		reply := func(m *dns.Msg) {
			if o := r.IsEdns0(); o != nil {
				m.SetEdns0(4096, false)
			}
			if network == "udp" {
				m.Truncate(maxUDP(r))
				if m.Truncated {
					stats.mu.Lock()
					stats.truncated++
					stats.mu.Unlock()
				}
			}
			_ = w.WriteMsg(m)
		}
		inLab := name == "azqlab.lan." || strings.HasSuffix(name, ".azqlab.lan.")
		inPTR := name == ptrZone || strings.HasSuffix(name, "."+ptrZone)
		if q.Qtype == dns.TypeAXFR || q.Qtype == dns.TypeIXFR {
			transfer(w, r, name, network, *axfr)
			return
		}
		if !inLab && !inPTR {
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
		if inPTR {
			answerPTR(m, q, name)
			reply(m)
			return
		}
		if code, ok := rcodes[name]; ok {
			m.Authoritative = false
			m.Rcode = code
			reply(m)
			return
		}
		recs, ok := zone[name]
		if !ok && strings.HasSuffix(name, wildcard) {
			recs, ok = []string{"A " + wildcardA}, true
		}
		if !ok && exists(name) {
			ok = true // an empty non-terminal: NODATA
		}
		if !ok {
			m.Rcode = dns.RcodeNameError
			reply(m)
			return
		}
		for _, rec := range recs {
			x := rr(name, rec)
			if x == nil {
				continue
			}
			if x.Header().Rrtype == q.Qtype || q.Qtype == dns.TypeANY || x.Header().Rrtype == dns.TypeCNAME {
				m.Answer = append(m.Answer, x)
			}
			// Follow a CNAME as a recursive resolver does: in the zone, or
			// upstream, whose NXDOMAIN for the target is the answer's code.
			if c, ok := x.(*dns.CNAME); ok && q.Qtype != dns.TypeCNAME && q.Qtype != dns.TypeANY {
				sub := new(dns.Msg)
				sub.SetQuestion(c.Target, q.Qtype)
				if t, ok := zone[c.Target]; ok {
					for _, rec := range t {
						if rr := rr(c.Target, rec); rr != nil && rr.Header().Rrtype == q.Qtype {
							m.Answer = append(m.Answer, rr)
						}
					}
				} else if in, _, err := client.Exchange(sub, *upstream); err == nil {
					m.Answer = append(m.Answer, in.Answer...)
					m.Rcode = in.Rcode
				}
			}
		}
		reply(m)
	})
	for _, n := range []string{"udp", "tcp"} {
		srv := &dns.Server{Addr: *addr, Net: n}
		go func() { log.Fatal(srv.ListenAndServe()) }()
	}
	log.Printf("labdns on %s, azqlab.lan answered here, the rest forwarded to %s", *addr, *upstream)
	select {}
}

// answerPTR answers the reverse zone of 127.0.0.0/24.
func answerPTR(m *dns.Msg, q dns.Question, name string) {
	if name == ptrZone {
		for _, rec := range []string{"SOA ns1.azqlab.lan. hostmaster.azqlab.lan. 2026103001 3600 600 86400 60", "NS ns1.azqlab.lan."} {
			if r := rr(name, rec); r != nil && (r.Header().Rrtype == q.Qtype || q.Qtype == dns.TypeANY) {
				m.Answer = append(m.Answer, r)
			}
		}
		return
	}
	last := strings.TrimSuffix(name, "."+ptrZone)
	names, ok := ptr[last]
	if !ok {
		m.Rcode = dns.RcodeNameError
		return
	}
	if q.Qtype != dns.TypePTR && q.Qtype != dns.TypeANY {
		return
	}
	for _, n := range names {
		if r := rr(name, "PTR "+n); r != nil {
			m.Answer = append(m.Answer, r)
		}
	}
}

// transfer sends azqlab.lan over TCP, SOA first and last as a transfer
// has it; the reverse zone and everything else is refused.
func transfer(w dns.ResponseWriter, r *dns.Msg, name, network string, allowed bool) {
	if network != "tcp" || name != "azqlab.lan." || !allowed {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeRefused)
		_ = w.WriteMsg(m)
		return
	}
	var soa dns.RR
	var rrs []dns.RR
	names := make([]string, 0, len(zone))
	for n := range zone {
		names = append(names, n)
	}
	names = append(names, "*"+wildcard)
	sort.Strings(names)
	for _, n := range names {
		recs := zone[n]
		if n == "*"+wildcard {
			recs = []string{"A " + wildcardA}
		}
		for _, rec := range recs {
			x := rr(n, rec)
			if x == nil {
				continue
			}
			if x.Header().Rrtype == dns.TypeSOA {
				soa = x
				continue
			}
			rrs = append(rrs, x)
		}
	}
	all := append([]dns.RR{soa}, rrs...)
	all = append(all, soa)
	ch := make(chan *dns.Envelope)
	tr := new(dns.Transfer)
	go func() {
		// 100 records an envelope keeps each message small.
		for i := 0; i < len(all); i += 100 {
			ch <- &dns.Envelope{RR: all[i:min(i+100, len(all))]}
		}
		close(ch)
	}()
	if err := tr.Out(w, r, ch); err != nil {
		log.Printf("axfr: %v", err)
	}
	w.Hijack()
}
