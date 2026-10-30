package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// The DNS lab (bench/labdns) holds azqlab.lan: real names, a wildcard
// subzone and dangling CNAMEs. 127.0.0.1:5354 is where it usually runs
// (other streams share it); when nothing answers there the bench builds
// its own on a free port.
const labDomain = "azqlab.lan"

// labLabels are the zone's own names under labDomain.
var labLabels = []string{"www", "app", "api", "mail", "dev", "vpn", "staging", "old-shop", "assets", "docs"}

var (
	labOnce sync.Once
	labAt   string
	labProc *exec.Cmd
)

// answersAt reports whether the server at addr has an A, AAAA or CNAME
// record for name: the lab's own word, asked directly.
func answersAt(addr, name string) bool {
	cli := &dns.Client{Timeout: 3 * time.Second}
	for _, t := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeCNAME} {
		q := new(dns.Msg)
		q.SetQuestion(dns.Fqdn(name), t)
		if r, _, err := cli.Exchange(q, addr); err == nil && r.Rcode == dns.RcodeSuccess && len(r.Answer) > 0 {
			return true
		}
	}
	return false
}

// labAddr is the address of a DNS lab resolver, started once if needed.
// The returned stop is a no-op: the lab lives until the bench exits.
func labAddr() (string, func()) {
	labOnce.Do(func() {
		if answersAt("127.0.0.1:5354", "www."+labDomain) {
			labAt = "127.0.0.1:5354"
			return
		}
		bin := filepath.Join(work, "labdns")
		if out, err := exec.Command("go", "build", "-o", bin, "./bench/labdns").CombinedOutput(); err != nil {
			logf("labdns: go build: %v\n%s", err, out)
			return
		}
		l, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			return
		}
		addr := l.LocalAddr().String()
		l.Close()
		labProc = exec.Command(bin, "-addr", addr)
		if labProc.Start() != nil {
			return
		}
		for i := 0; i < 50 && !answersAt(addr, "www."+labDomain); i++ {
			time.Sleep(100 * time.Millisecond)
		}
		labAt = addr
	})
	return labAt, func() {}
}

func stopLab() {
	if labProc != nil && labProc.Process != nil {
		_ = labProc.Process.Kill()
	}
}

// labRow is the DNS-lab section: what a reviewer reproduces offline.
type labRow struct {
	Resolver string   `json:"resolver"`
	Own      bool     `json:"own_lab"`
	UDPOpen  bool     `json:"udp_open"`
	Live     []string `json:"live"`
	Truth    []string `json:"truth"`
	Dangling []string `json:"dangling"`
	Wild     []string `json:"wildcard_zone"`
}

func benchLab() *labRow {
	lab, _ := labAddr()
	row := &labRow{Resolver: lab, Own: lab != "127.0.0.1:5354"}
	if lab == "" {
		addCheck("lab: a DNS lab resolver answers", false, "nothing answers on 127.0.0.1:5354 and go build ./bench/labdns or its start failed")
		return row
	}
	dir, _ := filepath.Abs(filepath.Join(work, "lab"))
	must(os.MkdirAll(dir, 0o755))
	res := filepath.Join(dir, "resolvers.txt")
	must(os.WriteFile(res, []byte(lab+"\n"), 0o644))
	port := lab[strings.LastIndex(lab, ":")+1:]

	// A UDP port scan finds the resolver and calls it DNS.
	out, m := run("lab", 2*time.Minute, dir, azhaq, "ports", "-host", "127.0.0.1", "-p", "none", "-pu", "top,"+port, "-json", "-silent")
	for _, l := range lines(out) {
		if strings.Contains(l, `"port":`+port) && strings.Contains(l, `"udp"`) && strings.Contains(l, `"open"`) {
			row.UDPOpen = true
		}
	}
	addCheck("lab: ports -pu finds the DNS lab's UDP port open", row.UDPOpen, "azhaq ports -host 127.0.0.1 -p none -pu top,%s: %d rows%s", port, len(lines(out)), azErr(m))

	// Brute force with the lab's labels and some that are not there.
	wl := filepath.Join(dir, "words.txt")
	words := append(append([]string(nil), labLabels...), "nope", "xyz", "ghost", "wild")
	must(os.WriteFile(wl, []byte(strings.Join(words, "\n")+"\n"), 0o644))
	truth := map[string]bool{}
	for _, w := range words {
		if n := w + "." + labDomain; answersAt(lab, n) {
			truth[n] = true
		}
	}
	row.Truth = sortedKeys(truth)
	out, m = run("lab", 2*time.Minute, dir, azhaq, "subs", "-d", labDomain, "-w", wl, "-resolvers", res, "-live", "-silent", "-no-history")
	live := hostSet(lines(out))
	row.Live = sortedKeys(live)
	missing, extra := diffKeys(truth, live)
	addCheck("lab: subs -w -live gives the names the lab answers (dangling CNAMEs included, as dnsx counts them)", len(missing) == 0 && len(extra) == 0,
		"lab answers %d names, azhaq printed %d; missing %v, extra %v; azhaq subs -d %s -w WORDS -resolvers LAB -live%s", len(truth), len(live), missing, extra, labDomain, azErr(m))

	// The wildcard subzone: only the name that differs from the wildcard answer is real.
	ww := filepath.Join(dir, "wild-words.txt")
	must(os.WriteFile(ww, []byte("real\na\nb\nc\nd\n"), 0o644))
	out, m = run("lab", 2*time.Minute, dir, azhaq, "dns", "-d", "wild."+labDomain, "-w", ww, "-resolvers", res, "-silent")
	row.Wild = sortedKeys(hostSet(lines(out)))
	addCheck("lab: a wildcard subzone gives only its real name", len(row.Wild) == 1 && row.Wild[0] == "real.wild."+labDomain,
		"azhaq dns -d wild.%s -w WORDS: %v (the lab answers %d for every label; only real.wild differs)%s", labDomain, row.Wild, 5, azErr(m))

	// A passive run with the brute force names the dangling CNAMEs as takeover candidates.
	db := filepath.Join(dir, "lab-"+time.Now().Format("150405")+".db")
	r := azRun("lab", 5*time.Minute, dir, "run", "-domain", labDomain, "-passive", "-sources", "none", "-skip", "azhaq-cdx,azhaq-rdap",
		"-dns-brute", wl, "-allow", labDomain, "-resolvers", res, "-db", db)
	for _, n := range []string{"assets", "docs", "old-shop"} {
		if strings.Contains(r.stdout+r.stderr, "dangling): "+n+"."+labDomain) {
			row.Dangling = append(row.Dangling, n)
		}
	}
	sort.Strings(row.Dangling)
	addCheck("lab: run -domain -passive names the dangling CNAMEs (assets, docs, old-shop)", len(row.Dangling) == 3,
		"takeover candidates named: %v; exit %d", row.Dangling, r.exit)
	_ = fmt.Sprint
	return row
}
