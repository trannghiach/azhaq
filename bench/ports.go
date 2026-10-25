package main

import (
	"strings"
	"time"
)

// portsRow compares the connect scan with naabu -scan-type c on the hosts
// the bench may scan: scanme.nmap.org (which exists to be scanned) and
// this machine.
type portsRow struct {
	Hosts        []string `json:"hosts"`
	AzhaqOpen    int      `json:"azhaq_open"`
	NaabuOpen    int      `json:"naabu_open"`
	Shared       int      `json:"shared"`
	AzhaqSeconds float64  `json:"azhaq_seconds"`
	NaabuSeconds float64  `json:"naabu_seconds"`
	AzhaqOnly    []string `json:"azhaq_only,omitempty"`
	NaabuOnly    []string `json:"naabu_only,omitempty"`
}

func benchPorts() *portsRow {
	row := &portsRow{Hosts: []string{"scanme.nmap.org", "127.0.0.1"}}
	az, naabu := map[string]bool{}, map[string]bool{}
	for _, h := range row.Hosts {
		out, m := run(h, 10*time.Minute, work, azhaq, "ports", "-host", h, "-p", "top-1000", "-silent")
		row.AzhaqSeconds += m.Seconds
		for _, l := range lines(out) {
			az[strings.ToLower(l)] = true
		}
		out, m = run(h, 10*time.Minute, work, ref("naabu"), "-host", h, "-top-ports", "1000", "-scan-type", "c", "-silent")
		row.NaabuSeconds += m.Seconds
		for _, l := range lines(out) {
			naabu[strings.ToLower(l)] = true
		}
	}
	row.AzhaqOpen, row.NaabuOpen, row.Shared = len(az), len(naabu), overlap(az, naabu)
	for k := range az {
		if !naabu[k] {
			row.AzhaqOnly = append(row.AzhaqOnly, k)
		}
	}
	for k := range naabu {
		if !az[k] {
			row.NaabuOnly = append(row.NaabuOnly, k)
		}
	}
	addCheck("ports: ≥ 95% of naabu's open ports (connect scan, top 1000)", row.NaabuOpen > 0 && float64(row.Shared) >= 0.95*float64(row.NaabuOpen),
		"azhaq %d, naabu %d, shared %d (%s)", row.AzhaqOpen, row.NaabuOpen, row.Shared, strings.Join(row.Hosts, ", "))
	return row
}
