package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// dnsRow compares `azhaq dns` record types and reverse lookups with dnsx against a zone the bench serves itself (bench.lan:
// A, AAAA, CNAME, MX, NS, TXT, SRV, CAA, SOA and PTR), so the
// answers are known and every query the tools send is counted at the server.
type dnsRow struct {
	Profile    string   `json:"profile,omitempty"`
	Names      int      `json:"names"`
	AzhaqOK    int      `json:"azhaq_confirmed"`
	DnsxOK     int      `json:"dnsx_confirmed"`
	AzhaqSecs  float64  `json:"azhaq_seconds"`
	DnsxSecs   float64  `json:"dnsx_seconds"`
	AzhaqQ     int      `json:"azhaq_queries"`
	DnsxQ      int      `json:"dnsx_queries"`
	AzhaqPeak  int      `json:"azhaq_peak_per_second"`
	DnsxPeak   int      `json:"dnsx_peak_per_second"`
	FieldDiffs []string `json:"field_diffs,omitempty"`
}

const recZone = "bench.lan."

// recServer answers recZone and counts every query with its time.
type recServer struct {
	mu   sync.Mutex
	log  []time.Time
	addr string
	srv  []*dns.Server
	// truth: "host|type" present in the zone.
	truth map[string]bool
	rrs   map[string][]dns.RR // lowercase name → records
}

func newRecServer() *recServer {
	z := &recServer{truth: map[string]bool{}, rrs: map[string][]dns.RR{}}
	add := func(s string) {
		rr, err := dns.NewRR(s)
		if err != nil {
			panic(err)
		}
		n := strings.ToLower(rr.Header().Name)
		z.rrs[n] = append(z.rrs[n], rr)
		z.truth[strings.TrimSuffix(n, ".")+"|"+strings.ToLower(dns.TypeToString[rr.Header().Rrtype])] = true
	}
	for _, r := range []string{
		"bench.lan. 60 IN SOA ns1.bench.lan. hostmaster.bench.lan. 1 7200 900 1209600 60",
		"bench.lan. 60 IN NS ns1.bench.lan.", "bench.lan. 60 IN NS ns2.bench.lan.",
		"bench.lan. 60 IN MX 10 mail.bench.lan.", "bench.lan. 60 IN MX 20 mail2.bench.lan.",
		`bench.lan. 60 IN TXT "v=spf1 -all"`, `bench.lan. 60 IN CAA 0 issue "letsencrypt.org"`,
		"www.bench.lan. 60 IN A 192.0.2.1", "www.bench.lan. 60 IN AAAA 2001:db8::1",
		"app.bench.lan. 60 IN A 192.0.2.2", "api.bench.lan. 60 IN CNAME app.bench.lan.",
		"mail.bench.lan. 60 IN A 192.0.2.3", "ns1.bench.lan. 60 IN A 192.0.2.53",
		"_sip._tcp.bench.lan. 60 IN SRV 5 10 5060 www.bench.lan.",
		"1.2.0.192.in-addr.arpa. 60 IN PTR www.bench.lan.", "2.2.0.192.in-addr.arpa. 60 IN PTR app.bench.lan.",
	} {
		add(r)
	}
	h := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		z.mu.Lock()
		z.log = append(z.log, time.Now())
		z.mu.Unlock()
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		q := r.Question[0]
		name := strings.ToLower(q.Name)
		found := false
		for _, rr := range z.rrs[name] {
			found = true
			if rr.Header().Rrtype == q.Qtype {
				m.Answer = append(m.Answer, rr)
			}
		}
		if !found && !strings.HasSuffix(name, "arpa.") {
			m.Rcode = dns.RcodeNameError
		} else if !found {
			m.Rcode = dns.RcodeNameError
		}
		_ = w.WriteMsg(m)
	})
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	must(err)
	z.addr = pc.LocalAddr().String()
	ln, err := net.Listen("tcp", z.addr)
	must(err)
	for _, s := range []*dns.Server{{PacketConn: pc, Handler: h}, {Listener: ln, Handler: h}} {
		z.srv = append(z.srv, s)
		go func(s *dns.Server) { _ = s.ActivateAndServe() }(s)
	}
	time.Sleep(100 * time.Millisecond)
	return z
}

func (z *recServer) stop() {
	for _, s := range z.srv {
		_ = s.Shutdown()
	}
}

func (z *recServer) reset() {
	z.mu.Lock()
	z.log = nil
	z.mu.Unlock()
}

// stats is the queries received since reset, and the most in any one second.
func (z *recServer) statsNow() (n, peak int, ok bool) {
	n, peak = z.stats()
	return n, peak, true
}

func (z *recServer) stats() (n, peak int) {
	z.mu.Lock()
	defer z.mu.Unlock()
	per := map[int64]int{}
	for _, t := range z.log {
		per[t.Unix()]++
	}
	for _, c := range per {
		peak = max(peak, c)
	}
	return len(z.log), peak
}

// normalizeDNSJSON reads dnsx-style JSON lines into host → field → sorted
// values, trailing dots and case dropped.
func normalizeDNSJSON(out []byte) map[string]map[string][]string {
	res := map[string]map[string][]string{}
	for _, l := range lines(out) {
		var o map[string]any
		if json.Unmarshal([]byte(l), &o) != nil {
			continue
		}
		host, _ := o["host"].(string)
		if host == "" {
			continue
		}
		host = strings.ToLower(strings.TrimSuffix(host, "."))
		f := map[string][]string{}
		for _, t := range []string{"a", "aaaa", "cname", "mx", "ns", "txt", "srv", "caa", "soa", "ptr"} {
			xs, _ := o[t].([]any)
			for _, x := range xs {
				var v string
				switch e := x.(type) {
				case string:
					v = e
				default:
					b, _ := json.Marshal(e)
					v = string(b)
				}
				f[t] = append(f[t], strings.ToLower(strings.TrimSuffix(strings.Join(strings.Fields(v), " "), ".")))
			}
			sort.Strings(f[t])
		}
		res[host] = f
	}
	return res
}

func benchDNS() *dnsRow {
	z := newRecServer()
	defer z.stop()
	dir, _ := filepath.Abs(filepath.Join(work, "dns"))
	must(os.MkdirAll(dir, 0o755))
	res := filepath.Join(dir, "resolvers.txt")
	must(os.WriteFile(res, []byte(z.addr+"\n"), 0o644))
	names := []string{"bench.lan", "www.bench.lan", "app.bench.lan", "api.bench.lan", "mail.bench.lan", "ns1.bench.lan", "_sip._tcp.bench.lan"}
	for i := 0; i < 25; i++ {
		names = append(names, fmt.Sprintf("absent%02d.bench.lan", i))
	}
	list := filepath.Join(dir, "names.txt")
	must(os.WriteFile(list, []byte(strings.Join(names, "\n")+"\n"), 0o644))
	row := &dnsRow{Profile: prof, Names: len(names)}
	types := []string{"-a", "-aaaa", "-cname", "-mx", "-ns", "-txt", "-srv", "-caa", "-soa"}
	// azhaq dns -rl is dnsx's -rl (names a second); -dns-rate paces each query.
	aa := append(append([]string{"dns", "-l", list, "-resolvers", res, "-json", "-silent"}, types...), pick([]string(nil), []string{"-rl", politeDNS})...)
	da := append(append([]string{"-l", list, "-r", z.addr, "-json", "-silent"}, types...), pick([]string(nil), []string{"-rl", politeDNS})...)
	cmds := cmdLine(azhaq, aa...) + " vs " + cmdLine("dnsx", da...)

	// Queries are counted for the first run of each tool (the timing repeats send again).
	counted := func(args []string) ([]byte, runMeasure, int, int) {
		var n, peak int
		got := false
		out, m := timedArgs("dns", 10*time.Minute, dir, args[0], func(i int) []string {
			if i == 1 {
				n, peak, got = z.statsNow()
			}
			z.reset()
			return args[1:]
		})
		if !got {
			n, peak, _ = z.statsNow()
		}
		return out, m, n, peak
	}
	out, am, aq, ap := counted(append([]string{azhaq}, aa...))
	row.AzhaqQ, row.AzhaqPeak = aq, ap
	row.AzhaqSecs = am.Seconds
	az := normalizeDNSJSON(out)
	out, dm, dq, dp := counted(append([]string{ref("dnsx")}, da...))
	row.DnsxQ, row.DnsxPeak = dq, dp
	row.DnsxSecs = dm.Seconds
	dx := normalizeDNSJSON(out)
	// (host, type) pairs the zone holds that a tool printed values for.
	count := func(m map[string]map[string][]string) int {
		n := 0
		for h, f := range m {
			for t, v := range f {
				if len(v) > 0 && z.truth[h+"|"+t] {
					n++
				}
			}
		}
		return n
	}
	row.AzhaqOK, row.DnsxOK = count(az), count(dx)
	for h, f := range dx {
		for t, v := range f {
			if len(v) > 0 && strings.Join(v, ",") != strings.Join(az[h][t], ",") {
				row.FieldDiffs = append(row.FieldDiffs, fmt.Sprintf("%s %s: dnsx %v, azhaq %v", h, t, v, az[h][t]))
			}
		}
	}
	for h, f := range az {
		for t, v := range f {
			if len(v) > 0 && len(dx[h][t]) == 0 {
				row.FieldDiffs = append(row.FieldDiffs, fmt.Sprintf("%s %s: azhaq %v, dnsx none", h, t, v))
			}
		}
	}
	sort.Strings(row.FieldDiffs)
	barOne("dns record types", row.AzhaqOK, row.DnsxOK, row.AzhaqSecs, row.DnsxSecs, "the zone the bench serves (a name and type it holds)", cmds,
		fmt.Sprintf("%d names, 9 types; queries received azhaq %d, dnsx %d; %s%s", row.Names, row.AzhaqQ, row.DnsxQ, ratio(row.AzhaqSecs, row.DnsxSecs), azErr(am)))
	addCheck("dns record types: azhaq's JSON values equal dnsx's", len(row.FieldDiffs) == 0 && len(az) > 0, "%d differences %v", len(row.FieldDiffs), clipList(row.FieldDiffs, 4))
	if polite() {
		// The pace is counted where the queries arrive: no second takes more than the rate and a little for a retry.
		// dnsx counts names, not queries, with -rl, so it can pass the rate: azhaq is held to the rate or to what dnsx sends at the same setting.
		addCheck("dns record types: queries per second at the server within the rate, or no more than dnsx's at the same setting", row.AzhaqPeak <= max(12, row.DnsxPeak),
			"most in one second: azhaq %d, dnsx %d (rate %s per second; %d and %d queries)", row.AzhaqPeak, row.DnsxPeak, politeDNS, row.AzhaqQ, row.DnsxQ)
	}

	// Reverse lookups.
	ips := filepath.Join(dir, "ips.txt")
	must(os.WriteFile(ips, []byte("192.0.2.1\n192.0.2.2\n192.0.2.9\n"), 0o644))
	pa := []string{"dns", "-l", ips, "-resolvers", res, "-ptr", "-json", "-silent"}
	pd := []string{"-l", ips, "-r", z.addr, "-ptr", "-json", "-silent"}
	out, pam := timed("dns", 5*time.Minute, dir, azhaq, pa...)
	pz := ptrValues(out)
	out, pdm := timed("dns", 5*time.Minute, dir, ref("dnsx"), pd...)
	px := ptrValues(out)
	want := map[string]bool{"www.bench.lan": true, "app.bench.lan": true}
	okA, okD := 0, 0
	for n := range pz {
		if want[n] {
			okA++
		}
	}
	for n := range px {
		if want[n] {
			okD++
		}
	}
	barOne("dns -ptr", okA, okD, pam.Seconds, pdm.Seconds, "the zone's PTR records", cmdLine(azhaq, pa...)+" vs "+cmdLine("dnsx", pd...),
		fmt.Sprintf("azhaq %v, dnsx %v%s", sortedKeys(pz), sortedKeys(px), azErr(pam)))

	return row
}

// ptrValues are the names in the "ptr" fields of dnsx-style JSON.
func ptrValues(out []byte) map[string]bool {
	set := map[string]bool{}
	for _, f := range normalizeDNSJSON(out) {
		for _, v := range f["ptr"] {
			set[v] = true
		}
	}
	return set
}
