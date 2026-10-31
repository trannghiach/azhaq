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
//
// With -zone FILE it answers the zones in that JSON file instead of
// azqlab.lan (the file format is on zoneFile); every other name is still
// forwarded. The workflow trial estates are served this way, one resolver
// each.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// labData is what a resolver answers itself: zones, reverse zones and the
// names that get an rcode instead of data.
type labData struct {
	origins  []string            // zones answered here, FQDNs
	zone     map[string][]string // name → records, in zone-file syntax without the name
	wild     map[string][]string // ".suffix." → records for any name under it that zone does not hold
	rcodes   map[string]int      // names answered with a code and no data
	ptrZones []string            // reverse zones answered here
	ptr      map[string][]string // reverse name → target names
	ptrApex  map[string][]string // reverse zone → its SOA and NS
	axfr     bool                // the file allows zone transfers (-axfr covers azqlab.lan)
}

// defaultLab is azqlab.lan.
func defaultLab() *labData {
	d := &labData{
		origins:  []string{"azqlab.lan."},
		zone:     zone,
		wild:     map[string][]string{wildcard: {"A " + wildcardA}},
		rcodes:   rcodes,
		ptrZones: []string{ptrZone},
		ptr:      map[string][]string{},
		ptrApex:  map[string][]string{ptrZone: {"SOA ns1.azqlab.lan. hostmaster.azqlab.lan. 2026103001 3600 600 86400 60", "NS ns1.azqlab.lan."}},
	}
	for last, names := range ptr {
		d.ptr[last+"."+ptrZone] = names
	}
	return d
}

// zoneFile is the -zone file:
//
//	{"axfr": false,
//	 "zones": {"corp.test.": {"corp.test.": ["SOA …", "NS …"], "ci.corp.test.": ["A 127.31.0.5"], "*.dev.corp.test.": ["A 127.31.0.9"]}},
//	 "ptr":   {"0.31.127.in-addr.arpa.": {"@": ["SOA …", "NS …"], "5": ["ci.corp.test."]}}}
//
// Names are fully qualified. A name that starts with "*." answers every name
// under it that the zone does not hold. In a reverse zone "@" holds the
// apex records and every other key is the last octet.
type zoneFile struct {
	AXFR  bool                           `json:"axfr"`
	Zones map[string]map[string][]string `json:"zones"`
	PTR   map[string]map[string][]string `json:"ptr"`
}

func fqdn(n string) string {
	n = strings.ToLower(strings.TrimSpace(n))
	if !strings.HasSuffix(n, ".") {
		n += "."
	}
	return n
}

// loadZones reads a -zone file.
func loadZones(raw []byte) (*labData, error) {
	var zf zoneFile
	if err := json.Unmarshal(raw, &zf); err != nil {
		return nil, fmt.Errorf("zone file: %w", err)
	}
	if len(zf.Zones) == 0 {
		return nil, fmt.Errorf("zone file: no zones")
	}
	d := &labData{zone: map[string][]string{}, wild: map[string][]string{}, rcodes: map[string]int{}, ptr: map[string][]string{}, ptrApex: map[string][]string{}, axfr: zf.AXFR}
	for origin, names := range zf.Zones {
		origin = fqdn(origin)
		d.origins = append(d.origins, origin)
		if !hasSOA(names, origin) {
			return nil, fmt.Errorf("zone file: %s has no SOA record", origin)
		}
		for n, recs := range names {
			n = fqdn(n)
			if n != origin && !strings.HasSuffix(n, "."+origin) {
				return nil, fmt.Errorf("zone file: %s is not under %s", n, origin)
			}
			for _, r := range recs {
				if _, err := dns.NewRR(n + " 60 IN " + r); err != nil {
					return nil, fmt.Errorf("zone file: %s %q: %w", n, r, err)
				}
			}
			if strings.HasPrefix(n, "*.") {
				d.wild[n[1:]] = recs
			} else {
				d.zone[n] = recs
			}
		}
	}
	for origin, names := range zf.PTR {
		origin = fqdn(origin)
		d.ptrZones = append(d.ptrZones, origin)
		for k, v := range names {
			if k == "@" {
				d.ptrApex[origin] = v
				continue
			}
			d.ptr[k+"."+origin] = v
		}
	}
	sort.Strings(d.origins)
	sort.Strings(d.ptrZones)
	return d, nil
}

// hasSOA: the zone's apex holds an SOA (a zone transfer starts and ends with it).
func hasSOA(names map[string][]string, origin string) bool {
	for n, recs := range names {
		if fqdn(n) != origin {
			continue
		}
		for _, r := range recs {
			if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(r)), "SOA ") {
				return true
			}
		}
	}
	return false
}

// zoneOf returns the origin name is at or under.
func (d *labData) zoneOf(name string) (string, bool) {
	for _, o := range d.origins {
		if name == o || strings.HasSuffix(name, "."+o) {
			return o, true
		}
	}
	return "", false
}

func (d *labData) ptrZoneOf(name string) (string, bool) {
	for _, o := range d.ptrZones {
		if name == o || strings.HasSuffix(name, "."+o) {
			return o, true
		}
	}
	return "", false
}

// exists: a name that holds records or has a name below it that does.
func (d *labData) exists(name string) bool {
	if _, ok := d.zone[name]; ok {
		return true
	}
	for n := range d.zone {
		if strings.HasSuffix(n, "."+name) {
			return true
		}
	}
	return false
}

// wildcardFor returns the records of the longest wildcard suffix name is under.
func (d *labData) wildcardFor(name string) ([]string, bool) {
	best := ""
	for suffix := range d.wild {
		if strings.HasSuffix(name, suffix) && len(suffix) > len(best) {
			best = suffix
		}
	}
	if best == "" {
		return nil, false
	}
	return d.wild[best], true
}

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

// handler answers questions from lab, counts them in stats and forwards the
// names outside the zones to upstream.
func handler(lab *labData, stats *counters, upstream string, delay time.Duration, cymru bool) dns.HandlerFunc {
	client := &dns.Client{Timeout: 3 * time.Second}
	return func(w dns.ResponseWriter, r *dns.Msg) {
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
		if delay > 0 {
			time.Sleep(delay)
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
		_, inLab := lab.zoneOf(name)
		_, inPTR := lab.ptrZoneOf(name)
		if cymru && q.Qtype == dns.TypeTXT && (strings.HasSuffix(name, ".0.0.127.origin.asn.cymru.com.") || name == "as64500.asn.cymru.com.") {
			m := new(dns.Msg)
			m.SetReply(r)
			txt := "64500 | 127.0.0.0/24 | ZZ | lab | 2026-01-01"
			if name == "as64500.asn.cymru.com." {
				txt = "64500 | ZZ | lab | 2026-01-01 | AZQ-LAB Lab network, ZZ"
			}
			m.Answer = append(m.Answer, rr(name, `TXT "`+txt+`"`))
			reply(m)
			return
		}
		if q.Qtype == dns.TypeAXFR || q.Qtype == dns.TypeIXFR {
			transfer(w, r, lab, name, network)
			return
		}
		if !inLab && !inPTR {
			if in, _, err := client.Exchange(r, upstream); err == nil {
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
			answerPTR(m, q, lab, name)
			reply(m)
			return
		}
		if code, ok := lab.rcodes[name]; ok {
			m.Authoritative = false
			m.Rcode = code
			reply(m)
			return
		}
		recs, ok := lab.zone[name]
		if !ok {
			recs, ok = lab.wildcardFor(name)
		}
		if !ok && lab.exists(name) {
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
				if t, ok := lab.zone[c.Target]; ok {
					for _, rec := range t {
						if rr := rr(c.Target, rec); rr != nil && rr.Header().Rrtype == q.Qtype {
							m.Answer = append(m.Answer, rr)
						}
					}
				} else if in, _, err := client.Exchange(sub, upstream); err == nil {
					m.Answer = append(m.Answer, in.Answer...)
					m.Rcode = in.Rcode
				}
			}
		}
		reply(m)
	}
}

func main() {
	addr := flag.String("addr", "127.0.0.1:5354", "listen address (UDP and TCP)")
	upstream := flag.String("upstream", "1.1.1.1:53", "resolver for names outside azqlab.lan")
	statsAddr := flag.String("stats", "", "serve what was asked as JSON on this address: /stats, /stats?names=1, /reset")
	delay := flag.Duration("delay", 0, "wait this long before each answer (makes queries in flight measurable)")
	axfr := flag.Bool("axfr", true, "allow zone transfers of azqlab.lan over TCP")
	cymru := flag.Bool("cymru", false, "answer Team Cymru's address-to-AS lookups for 127.0.0.0/24 (AS64500) instead of forwarding them")
	zonePath := flag.String("zone", "", "answer the zones in this JSON file (- reads it from stdin) instead of azqlab.lan (format: zoneFile in main.go)")
	flag.Parse()
	lab := defaultLab()
	lab.axfr = *axfr
	if *zonePath != "" {
		var raw []byte
		var err error
		if *zonePath == "-" {
			raw, err = io.ReadAll(os.Stdin) // no file another user could read
		} else {
			raw, err = os.ReadFile(*zonePath)
		}
		if err != nil {
			log.Fatal(err)
		}
		if lab, err = loadZones(raw); err != nil {
			log.Fatal(err)
		}
	}
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
	dns.HandleFunc(".", handler(lab, stats, *upstream, *delay, *cymru))
	for _, n := range []string{"udp", "tcp"} {
		srv := &dns.Server{Addr: *addr, Net: n}
		go func() { log.Fatal(srv.ListenAndServe()) }()
	}
	log.Printf("labdns on %s, azqlab.lan answered here, the rest forwarded to %s", *addr, *upstream)
	select {}
}

// answerPTR answers the reverse zones.
func answerPTR(m *dns.Msg, q dns.Question, lab *labData, name string) {
	origin, _ := lab.ptrZoneOf(name)
	if name == origin {
		for _, rec := range lab.ptrApex[origin] {
			if r := rr(name, rec); r != nil && (r.Header().Rrtype == q.Qtype || q.Qtype == dns.TypeANY) {
				m.Answer = append(m.Answer, r)
			}
		}
		return
	}
	names, ok := lab.ptr[name]
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

// transfer sends a zone over TCP, SOA first and last as a transfer has it;
// the reverse zones and everything else is refused.
func transfer(w dns.ResponseWriter, r *dns.Msg, lab *labData, name, network string) {
	origin, isZone := lab.zoneOf(name)
	if network != "tcp" || !isZone || name != origin || !lab.axfr {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeRefused)
		_ = w.WriteMsg(m)
		return
	}
	under := func(n string) bool { return n == origin || strings.HasSuffix(n, "."+origin) }
	var soa dns.RR
	var rrs []dns.RR
	recsOf := map[string][]string{}
	names := make([]string, 0, len(lab.zone))
	for n, recs := range lab.zone {
		if under(n) {
			names = append(names, n)
			recsOf[n] = recs
		}
	}
	for suffix, recs := range lab.wild {
		if under(suffix[1:]) || suffix[1:] == origin {
			names = append(names, "*"+suffix)
			recsOf["*"+suffix] = recs
		}
	}
	sort.Strings(names)
	for _, n := range names {
		for _, rec := range recsOf[n] {
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
