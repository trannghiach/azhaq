package main

import (
	"fmt"
	"net"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

// portsRow compares the connect scan with naabu -scan-type c: on
// scanme.nmap.org (which exists to be scanned), on this machine against the
// listening sockets `ss` shows, and on 127.0.0.0/28 against listeners the
// bench opens. Both tools get the same ports and, in the polite profile,
// the same rate.
type portsRow struct {
	Profile      string     `json:"profile,omitempty"`
	Hosts        []string   `json:"hosts"`
	AzhaqOpen    int        `json:"azhaq_open"`
	NaabuOpen    int        `json:"naabu_open"`
	Shared       int        `json:"shared"`
	AzhaqSeconds float64    `json:"azhaq_seconds"`
	NaabuSeconds float64    `json:"naabu_seconds"`
	AzhaqOnly    []string   `json:"azhaq_only,omitempty"`
	NaabuOnly    []string   `json:"naabu_only,omitempty"`
	Legs         []portsLeg `json:"legs,omitempty"`
	NaabuMissing bool       `json:"naabu_missing,omitempty"`
}

type portsLeg struct {
	Target    string  `json:"target"`
	Ports     string  `json:"ports"`
	Azhaq     int     `json:"azhaq"`
	Naabu     int     `json:"naabu"`
	AzhaqOK   int     `json:"azhaq_confirmed"`
	NaabuOK   int     `json:"naabu_confirmed"`
	AzhaqSecs float64 `json:"azhaq_seconds"`
	NaabuSecs float64 `json:"naabu_seconds"`
}

// listening is the set of "ip:port" of TCP sockets in the listening state.
func listening() map[string]bool {
	out, err := exec.Command("ss", "-ltnH").Output()
	set := map[string]bool{}
	if err != nil {
		return set
	}
	for _, l := range strings.Split(string(out), "\n") {
		f := strings.Fields(l)
		if len(f) >= 4 {
			set[f[3]] = true
		}
	}
	return set
}

// listensOn reports whether port is open on 127.0.0.1 in a ss snapshot (a
// socket bound to every address counts).
func listensOn(snap map[string]bool, port string) bool {
	for _, a := range []string{"127.0.0.1:", "0.0.0.0:", "*:", "[::]:", "[::1]:"} {
		if snap[a+port] {
			return true
		}
	}
	return false
}

func benchPorts() *portsRow {
	row := &portsRow{Profile: prof, Hosts: []string{"scanme.nmap.org", "127.0.0.1", "127.0.0.0/28"}}
	naabu := ref("naabu")
	if !fileExists(naabu) {
		row.NaabuMissing = true
		addCheck("ports: naabu is installed", false, "%s is not there (Microsoft Defender may have removed it); the comparison is skipped", naabu)
		return row
	}
	rate := pick([]string(nil), []string{"-rate", politePort})
	nrate := pick([]string(nil), []string{"-rate", politePort})
	var azCmd, nbCmd, azFailed string
	add := func(l portsLeg) {
		row.Legs = append(row.Legs, l)
		row.AzhaqSeconds += l.AzhaqSecs
		row.NaabuSeconds += l.NaabuSecs
		row.AzhaqOpen += l.Azhaq
		row.NaabuOpen += l.Naabu
	}
	both := func(target, ports string, public bool) (az, nb map[string]bool, azS, nbS float64) {
		aa := append([]string{"ports", "-host", target, "-p", ports, "-silent"}, rate...)
		na := append(append([]string{"-host", target}, naabuPorts(ports)...), "-scan-type", "c", "-Pn", "-silent")
		na = append(na, nrate...)
		azCmd, nbCmd = cmdLine(azhaq, aa...), cmdLine("naabu", na...)
		var out []byte
		var m runMeasure
		if public { // one run: a host that exists to be scanned, not hammered
			out, m = run(target, 10*time.Minute, work, azhaq, aa...)
		} else {
			out, m = timed(target, 10*time.Minute, work, azhaq, aa...)
		}
		azFailed += azFail(m)
		az, azS = portSet(out), m.Seconds
		if public {
			out, m = run(target, 10*time.Minute, work, naabu, na...)
		} else {
			out, m = timed(target, 10*time.Minute, work, naabu, na...)
		}
		nb, nbS = portSet(out), m.Seconds
		return
	}

	// scanme.nmap.org, top 1000, once.
	az, nb, azS, nbS := both("scanme.nmap.org", "top-1000", true)
	// naabu's own spelling of the same list.
	l := portsLeg{Target: "scanme.nmap.org", Ports: "top-1000", Azhaq: len(az), Naabu: len(nb), AzhaqSecs: azS, NaabuSecs: nbS}
	for k := range az {
		if dialOK(k) {
			l.AzhaqOK++
		}
	}
	for k := range nb {
		if dialOK(k) {
			l.NaabuOK++
		}
	}
	add(l)
	row.AzhaqOnly, row.NaabuOnly = diffKeys(az, nb)
	barOne("ports scanme.nmap.org top-1000", l.AzhaqOK, l.NaabuOK, l.AzhaqSecs, l.NaabuSecs, "an independent TCP connect",
		azCmd+" vs "+nbCmd, fmt.Sprintf("%s; azhaq only %v, naabu only %v", share(overlap(az, nb), len(nb)), row.AzhaqOnly, row.NaabuOnly)+azFailed)

	// 127.0.0.1: the listening sockets ss shows, before and after the scan.
	ports := pick("1-65535", "top-1000")
	before := listening()
	az, nb, azS, nbS = both("127.0.0.1", ports, false)
	after := listening()
	l = portsLeg{Target: "127.0.0.1", Ports: ports, Azhaq: len(az), Naabu: len(nb), AzhaqSecs: azS, NaabuSecs: nbS}
	for k := range az {
		if _, p, ok := strings.Cut(k, ":"); ok && (listensOn(before, p) || listensOn(after, p)) {
			l.AzhaqOK++
		}
	}
	for k := range nb {
		if _, p, ok := strings.Cut(k, ":"); ok && (listensOn(before, p) || listensOn(after, p)) {
			l.NaabuOK++
		}
	}
	add(l)
	missed := func(set map[string]bool) []string {
		var m []string
		for a := range before {
			if h, p, ok := strings.Cut(a, ":"); ok && h == "127.0.0.1" && after[a] && !set["127.0.0.1:"+p] && inPorts(ports, p) {
				m = append(m, a)
			}
		}
		sort.Strings(m)
		return m
	}
	ma, mn := missed(az), missed(nb)
	barOne("ports 127.0.0.1 "+ports, l.AzhaqOK, l.NaabuOK, l.AzhaqSecs, l.NaabuSecs, "`ss -ltn` taken before and after the scan",
		azCmd+" vs "+nbCmd, fmt.Sprintf("%s; sockets listening throughout and missed: azhaq %v, naabu %v", share(overlap(az, nb), len(nb)), clipList(ma, 5), clipList(mn, 5))+azFailed)

	// 127.0.0.0/28 against listeners of the bench's own.
	truth, plist, stop := cidrListeners()
	defer stop()
	az, nb, azS, nbS = both("127.0.0.0/28", plist, false)
	l = portsLeg{Target: "127.0.0.0/28", Ports: plist, Azhaq: len(az), Naabu: len(nb), AzhaqSecs: azS, NaabuSecs: nbS}
	for k := range az {
		if truth[k] {
			l.AzhaqOK++
		}
	}
	for k := range nb {
		if truth[k] {
			l.NaabuOK++
		}
	}
	add(l)
	barOne("ports 127.0.0.0/28", l.AzhaqOK-(len(az)-l.AzhaqOK), l.NaabuOK-(len(nb)-l.NaabuOK), l.AzhaqSecs, l.NaabuSecs, "the listeners the bench opened (a port that is not one counts against)",
		azCmd+" vs "+nbCmd, fmt.Sprintf("planted %d; azhaq %d of them, %d reported; naabu %d, %d reported%s", len(truth), l.AzhaqOK, len(az), l.NaabuOK, len(nb), "")+azFailed)
	row.Shared = overlap(az, nb)
	return row
}

func inPorts(spec, p string) bool {
	n, _ := strconv.Atoi(p)
	return spec == "1-65535" || n <= 10000 // the top-1000 list reaches into the thousands; a miss here is only listed
}

func diffKeys(a, b map[string]bool) (onlyA, onlyB []string) {
	for k := range a {
		if !b[k] {
			onlyA = append(onlyA, k)
		}
	}
	for k := range b {
		if !a[k] {
			onlyB = append(onlyB, k)
		}
	}
	sort.Strings(onlyA)
	sort.Strings(onlyB)
	return
}

func portSet(out []byte) map[string]bool {
	set := map[string]bool{}
	for _, l := range lines(out) {
		set[strings.ToLower(firstField(l))] = true
	}
	return set
}

func dialOK(hostport string) bool {
	c, err := net.DialTimeout("tcp", hostport, 5*time.Second)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// cidrListeners opens listeners on several addresses of 127.0.0.0/28 and
// returns the "ip:port" truth and the port list to scan (the open ports and
// three that are closed).
func cidrListeners() (map[string]bool, string, func()) {
	var lns []net.Listener
	truth := map[string]bool{}
	var ports []string
	open := func(ip string, port int) int {
		ln, err := net.Listen("tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
		if err != nil {
			return 0
		}
		lns = append(lns, ln)
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				c.Close()
			}
		}()
		return ln.Addr().(*net.TCPAddr).Port
	}
	p1 := open("127.0.0.2", 0)
	p2 := open("127.0.0.5", 0)
	if p2 != 0 {
		open("127.0.0.9", p2)
	}
	p3 := open("127.0.0.14", 0)
	for ip, p := range map[string]int{"127.0.0.2": p1, "127.0.0.5": p2, "127.0.0.9": p2, "127.0.0.14": p3} {
		if p != 0 {
			truth[ip+":"+strconv.Itoa(p)] = true
		}
	}
	for _, p := range []int{p1, p2, p3} {
		if p != 0 {
			ports = append(ports, strconv.Itoa(p))
		}
	}
	for _, p := range freePorts(3) {
		ports = append(ports, strconv.Itoa(p))
	}
	return truth, strings.Join(ports, ","), func() {
		for _, l := range lns {
			l.Close()
		}
	}
}

// naabuPorts is azhaq's port spec in naabu's flags.
func naabuPorts(spec string) []string {
	if n, ok := strings.CutPrefix(spec, "top-"); ok {
		return []string{"-top-ports", n}
	}
	return []string{"-p", spec}
}
