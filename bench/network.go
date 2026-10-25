package main

import (
	"bufio"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// networkRow checks starting from networks: an AS's prefixes against the
// route objects registered for it (asnmap needs a ProjectDiscovery key
// now, so RADb is the reference), and reverse DNS against dnsx -ptr.
type networkRow struct {
	ASN         string `json:"asn"`
	AzhaqPrefix int    `json:"azhaq_prefixes"`
	RADbRoutes  int    `json:"radb_routes"`
	Shared      int    `json:"shared"`
	CIDR        string `json:"cidr"`
	AzhaqPTR    int    `json:"azhaq_ptr"`
	DnsxPTR     int    `json:"dnsx_ptr"`
	SharedPTR   int    `json:"shared_ptr"`
}

const (
	benchASN  = "AS394161"        // Tesla, a public bug bounty program
	benchCIDR = "45.33.32.128/25" // around scanme.nmap.org; reverse DNS only
)

func benchNetwork() *networkRow {
	dir, _ := filepath.Abs(filepath.Join(work, "network"))
	must(os.MkdirAll(dir, 0o755))
	row := &networkRow{ASN: benchASN, CIDR: benchCIDR}

	out, _ := run(benchASN, 5*time.Minute, dir, azhaq, "asn", "-a", benchASN, "-silent")
	az := map[string]bool{}
	for _, l := range lines(out) {
		az[l] = true
	}
	radb := radbRoutes(benchASN)
	row.AzhaqPrefix, row.RADbRoutes, row.Shared = len(az), len(radb), overlap(az, radb)
	// RADb keeps route objects nobody removed; RIPEstat lists what is
	// announced, and many announced prefixes are registered in other IRRs
	// (ARIN): a sanity check, not a coverage race.
	addCheck("asn: announced prefixes match registered routes", row.AzhaqPrefix > 0 && float64(row.Shared) >= 0.7*float64(min(row.AzhaqPrefix, row.RADbRoutes)),
		"%s: azhaq %d (RIPEstat), RADb %d, shared %d", benchASN, row.AzhaqPrefix, row.RADbRoutes, row.Shared)

	db := filepath.Join(dir, "cidr-"+time.Now().Format("150405")+".db")
	run(benchCIDR, 5*time.Minute, dir, azhaq, "run", "-cidr", benchCIDR, "-passive", "-db", db, "-quiet")
	ptr := map[string]bool{}
	exp, _ := runOut(azhaq, "export", "-db", db)
	for _, p := range readExport(exp).payloads("azhaq-ptr") {
		ip, _ := p["ip"].(string)
		if names, ok := p["ptr"].([]any); ok && len(names) > 0 {
			ptr[ip] = true
		}
	}
	pf := netip.MustParsePrefix(benchCIDR)
	var ips []string
	for a := pf.Addr(); pf.Contains(a); a = a.Next() {
		ips = append(ips, a.String())
	}
	list := filepath.Join(dir, "ips.txt")
	must(os.WriteFile(list, []byte(strings.Join(ips, "\n")+"\n"), 0o644))
	out, _ = run(benchCIDR, 5*time.Minute, dir, ref("dnsx"), "-l", list, "-ptr", "-silent")
	dx := hostSet(lines(out))
	row.AzhaqPTR, row.DnsxPTR, row.SharedPTR = len(ptr), len(dx), overlap(ptr, dx)
	addCheck("ptr: ≥ 95% of dnsx -ptr's answers", row.DnsxPTR > 0 && float64(row.SharedPTR) >= 0.95*float64(row.DnsxPTR),
		"%s: azhaq %d, dnsx %d, shared %d addresses with a reverse name", benchCIDR, row.AzhaqPTR, row.DnsxPTR, row.SharedPTR)
	return row
}

// radbRoutes asks RADb's whois for the route objects of an AS.
func radbRoutes(asn string) map[string]bool {
	out := map[string]bool{}
	conn, err := net.DialTimeout("tcp", "whois.radb.net:43", 15*time.Second)
	if err != nil {
		return out
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(60 * time.Second))
	_, _ = conn.Write([]byte("-i origin " + asn + "\r\n"))
	sc := bufio.NewScanner(conn)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "route:"); ok {
			if p, err := netip.ParsePrefix(strings.TrimSpace(v)); err == nil {
				out[p.Masked().String()] = true
			}
		}
	}
	return out
}
