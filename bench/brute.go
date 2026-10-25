package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/trannghiach/azhaq/internal/dnsr"
)

// bruteRow compares active subdomain techniques with the reference tools
// on vulnweb.com, the one public zone the bench may send guesses to.
type bruteRow struct {
	Domain       string  `json:"domain"`
	Words        int     `json:"words"`
	AzhaqFound   int     `json:"azhaq_found"`
	DnsxFound    int     `json:"dnsx_found"`
	Shared       int     `json:"shared"`
	AzhaqSeconds float64 `json:"azhaq_seconds"`
	DnsxSeconds  float64 `json:"dnsx_seconds"`

	WildcardWords  int `json:"wildcard_words"`
	WildcardReal   int `json:"wildcard_real"`
	WildcardAzhaq  int `json:"wildcard_azhaq"`
	WildcardFake   int `json:"wildcard_fake"`
	WildcardNoWild int `json:"wildcard_dnsx_unfiltered"`

	PermuteAzhaq  int `json:"permute_azhaq"`
	PermuteAlterx int `json:"permute_alterx"`
	PermuteShared int `json:"permute_shared"`
}

const bruteDomain = "vulnweb.com"

func benchBrute() *bruteRow {
	dir, _ := filepath.Abs(filepath.Join(work, "brute"))
	must(os.MkdirAll(dir, 0o755))
	words, err := fetchWordlist(subdomainWords)
	must(err)
	resolvers := filepath.Join(dir, "resolvers.txt")
	must(os.WriteFile(resolvers, []byte(strings.Join(dnsr.DefaultResolvers, "\n")+"\n"), 0o644))
	stamp := time.Now().Format("150405")
	row := &bruteRow{Domain: bruteDomain, Words: len(lines(must1(os.ReadFile(words))))}

	// Brute force: the same words and resolvers for both tools.
	db := filepath.Join(dir, "brute-"+stamp+".db")
	_, m := run(bruteDomain, 15*time.Minute, dir, azhaq, "run", "-domain", bruteDomain, "-passive", "-sources", "none",
		"-skip", "azhaq-cdx,azhaq-rdap", "-dns-brute", words, "-allow", bruteDomain, "-resolvers", resolvers, "-db", db, "-json")
	row.AzhaqSeconds = m.Seconds
	az := namesFrom(db, "azhaq-dns-brute")
	out, dm := run(bruteDomain, 15*time.Minute, dir, ref("dnsx"), "-d", bruteDomain, "-w", words, "-r", resolvers, "-silent", "-wd", bruteDomain)
	row.DnsxSeconds = dm.Seconds
	dx := hostSet(lines(out))
	row.AzhaqFound, row.DnsxFound, row.Shared = len(az), len(dx), overlap(az, dx)
	addCheck("dns-brute: ≥ 95% of dnsx with the same words and resolvers", row.DnsxFound > 0 && float64(row.Shared) >= 0.95*float64(row.DnsxFound),
		"azhaq %d, dnsx %d, shared %d (%d words on %s)", row.AzhaqFound, row.DnsxFound, row.Shared, row.Words, bruteDomain)
	addCheck("dns-brute: within 2× dnsx's time", row.AzhaqSeconds <= 2*row.DnsxSeconds+1,
		"azhaq %.1fs, dnsx %.1fs", row.AzhaqSeconds, row.DnsxSeconds)

	wildcardCheck(dir, stamp, row)

	// Permutations of the live names, against alterx's patterns resolved by dnsx.
	pdb := filepath.Join(dir, "permute-"+stamp+".db")
	run(bruteDomain, 15*time.Minute, dir, azhaq, "run", "-domain", bruteDomain, "-passive", "-skip", "azhaq-cdx,azhaq-rdap",
		"-permute", "-allow", bruteDomain, "-resolvers", resolvers, "-db", pdb, "-json")
	ap := namesFrom(pdb, "azhaq-permute")
	live := liveNames(pdb, bruteDomain)
	liveFile := filepath.Join(dir, "live.txt")
	must(os.WriteFile(liveFile, []byte(strings.Join(sortedKeys(live), "\n")+"\n"), 0o644))
	cands, _ := run(bruteDomain, 5*time.Minute, dir, ref("alterx"), "-l", liveFile, "-silent")
	candFile := filepath.Join(dir, "alterx.txt")
	must(os.WriteFile(candFile, cands, 0o644))
	found, _ := run(bruteDomain, 15*time.Minute, dir, ref("dnsx"), "-l", candFile, "-r", resolvers, "-silent", "-wd", bruteDomain)
	ax := hostSet(lines(found))
	for n := range live {
		delete(ax, n)
	}
	row.PermuteAzhaq, row.PermuteAlterx, row.PermuteShared = len(ap), len(ax), overlap(ap, ax)
	return row
}

// wildcardCheck serves a zone where every label resolves, plus three real
// names with their own addresses, and brute forces it with both tools.
func wildcardCheck(dir, stamp string, row *bruteRow) {
	const zone = "wild.example.com"
	real := map[string]string{"www": "192.0.2.1", "api": "192.0.2.2", "mail": "192.0.2.3"}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	must(err)
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		name := strings.TrimSuffix(strings.ToLower(q.Name), ".")
		if strings.HasSuffix(name, "."+zone) && q.Qtype == dns.TypeA {
			ip := "192.0.2.99"
			if v, ok := real[strings.TrimSuffix(name, "."+zone)]; ok {
				ip = v
			}
			rr, _ := dns.NewRR(q.Name + " 60 IN A " + ip)
			m.Answer = append(m.Answer, rr)
		} else if !strings.HasSuffix(name, zone) {
			m.Rcode = dns.RcodeNameError
		}
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	defer srv.Shutdown()

	var words []string
	for w := range real {
		words = append(words, w)
	}
	for i := 0; i < 47; i++ {
		words = append(words, fmt.Sprintf("guess%02d", i))
	}
	list := filepath.Join(dir, "wildcard-words.txt")
	must(os.WriteFile(list, []byte(strings.Join(words, "\n")+"\n"), 0o644))
	resolver := filepath.Join(dir, "wildcard-resolver.txt")
	must(os.WriteFile(resolver, []byte(pc.LocalAddr().String()+"\n"), 0o644))

	db := filepath.Join(dir, "wildcard-"+stamp+".db")
	run(zone, 5*time.Minute, dir, azhaq, "run", "-domain", zone, "-passive", "-sources", "none", "-skip", "azhaq-cdx,azhaq-rdap",
		"-dns-brute", list, "-allow", zone, "-resolvers", resolver, "-db", db, "-json")
	az := namesFrom(db, "azhaq-dns-brute")
	fake := 0
	for n := range az {
		if _, ok := real[strings.TrimSuffix(n, "."+zone)]; !ok {
			fake++
		}
	}
	out, _ := run(zone, 5*time.Minute, dir, ref("dnsx"), "-d", zone, "-w", list, "-r", resolver, "-silent")
	row.WildcardWords, row.WildcardReal = len(words), len(real)
	row.WildcardAzhaq, row.WildcardFake, row.WildcardNoWild = len(az), fake, len(hostSet(lines(out)))
	addCheck("wildcard zone: no fake hosts", fake == 0 && len(az) == len(real),
		"%d of %d real names found, %d fake (dnsx without wildcard filtering reports %d)", len(az)-fake, len(real), fake, row.WildcardNoWild)
}

// namesFrom collects the names a collector reported in its payloads.
func namesFrom(db, collector string) map[string]bool {
	out, _ := runOut(azhaq, "export", "-db", db)
	set := map[string]bool{}
	for _, p := range readExport(out).payloads(collector) {
		names, _ := p["names"].([]any)
		for _, n := range names {
			if s, ok := n.(string); ok {
				set[s] = true
			}
		}
	}
	return set
}

// liveNames are hostnames under domain that azhaq-dns resolved.
func liveNames(db, domain string) map[string]bool {
	out, _ := runOut(azhaq, "export", "-db", db)
	set := map[string]bool{}
	for _, p := range readExport(out).payloads("azhaq-dns") {
		name, _ := p["fqdn"].(string)
		if ips, ok := p["ips"].([]any); ok && len(ips) > 0 && p["wildcard"] == nil && inDomain(name, domain) {
			set[name] = true
		}
	}
	return set
}

func hostSet(xs []string) map[string]bool {
	set := map[string]bool{}
	for _, x := range xs {
		if f := strings.Fields(x); len(f) > 0 {
			set[strings.ToLower(strings.TrimSuffix(f[0], "."))] = true
		}
	}
	return set
}

func overlap(a, b map[string]bool) int {
	n := 0
	for k := range a {
		if b[k] {
			n++
		}
	}
	return n
}

func must1[T any](v T, err error) T {
	must(err)
	return v
}
