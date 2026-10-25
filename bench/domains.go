package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// domainRow compares passive subdomain discovery on one domain. A name is
// live when dnsx resolves it; both tools are judged on the same list.
type domainRow struct {
	Domain         string  `json:"domain"`
	AzhaqNames     int     `json:"azhaq_names"`
	SubfinderNames int     `json:"subfinder_names"`
	Live           int     `json:"live"`
	AzhaqLive      int     `json:"azhaq_live"`
	SubfinderLive  int     `json:"subfinder_live"`
	SharedLive     int     `json:"shared_live"`
	AzhaqSeconds   float64 `json:"azhaq_seconds"`
	SubSeconds     float64 `json:"subfinder_seconds"`
	CT             string  `json:"ct"`
	AzhaqURLs      int     `json:"azhaq_urls"`
	GauURLs        int     `json:"gau_urls"`
	CDX            string  `json:"cdx"`
}

func benchDomains() []domainRow {
	raw, err := os.ReadFile("bench/domains.txt")
	must(err)
	dir, _ := filepath.Abs(filepath.Join(work, "domains"))
	must(os.MkdirAll(dir, 0o755))
	stamp := time.Now().Format("150405")
	var out []domainRow
	silent := true
	for _, d := range lines(raw) {
		logf("domain %s", d)
		row := domainRow{Domain: d}
		seeds := filepath.Join(dir, d+".jsonl")
		must(os.WriteFile(seeds, []byte(fmt.Sprintf(`{"type":"Domain","keys":{"domain":%q}}`+"\n", d)), 0o644))
		db := filepath.Join(dir, d+"-"+stamp+".db")
		_, m := run(d, 15*time.Minute, dir, azhaq, "run", "-in", seeds, "-passive", "-db", db, "-json")
		row.AzhaqSeconds = m.Seconds
		exp, _ := runOut(azhaq, "export", "-db", db)
		g := readExport(exp)

		az := map[string]bool{}
		for _, r := range g.rows {
			if r.Entity.Type == "Hostname" && inDomain(r.Entity.Key, d) {
				az[r.Entity.Key] = true
			}
		}
		for _, p := range g.payloads("azhaq-ct") {
			names, _ := p["names"].([]any)
			for _, n := range names {
				if s, _ := n.(string); inDomain(s, d) {
					az[s] = true
				}
			}
			row.CT = sourceSummary(p)
			if !explained(p) {
				silent = false
			}
		}
		for _, p := range g.payloads("azhaq-cdx") {
			if _, ok := p["source"]; !ok {
				continue
			}
			row.CDX = sourceSummary(p)
			if c, _ := p["count"].(float64); c > 0 {
				row.AzhaqURLs = int(c)
			}
			if !explained(p) {
				silent = false
			}
		}

		subOut, sm := run(d, 15*time.Minute, dir, ref("subfinder"), "-d", d, "-silent")
		row.SubSeconds = sm.Seconds
		sub := map[string]bool{}
		for _, n := range lines(subOut) {
			if n = strings.ToLower(n); inDomain(n, d) {
				sub[n] = true
			}
		}
		row.AzhaqNames, row.SubfinderNames = len(az), len(sub)

		union := map[string]bool{}
		for n := range az {
			union[n] = true
		}
		for n := range sub {
			union[n] = true
		}
		list := filepath.Join(dir, d+"-names.txt")
		must(os.WriteFile(list, []byte(strings.Join(sortedKeys(union), "\n")+"\n"), 0o644))
		liveOut, _ := run(d, 15*time.Minute, dir, ref("dnsx"), "-l", list, "-silent", "-a", "-aaaa", "-cname")
		live := map[string]bool{}
		for _, n := range lines(liveOut) {
			live[strings.ToLower(strings.Fields(n)[0])] = true
		}
		row.Live = len(live)
		for n := range live {
			if az[n] {
				row.AzhaqLive++
			}
			if sub[n] {
				row.SubfinderLive++
			}
			if az[n] && sub[n] {
				row.SharedLive++
			}
		}

		gauOut, _ := run(d, 5*time.Minute, dir, ref("gau"), "--subs", "--threads", "2", "--timeout", "30", d)
		row.GauURLs = len(lines(gauOut))
		out = append(out, row)
	}
	addCheck("CT and CDX: no silent zeros", silent, "every empty CT/archive result is a failure flagged as error or degraded, or a zero every source answered")
	return out
}

func inDomain(name, domain string) bool {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	return name == domain || strings.HasSuffix(name, "."+domain)
}

// explained is false for the bug this checks: an empty result with no
// error, degraded flag or reason. Zero is a fine answer when every source
// replied with zero (vulnweb.com has no certificates in CT at all).
func explained(p map[string]any) bool {
	if c, _ := p["count"].(float64); c > 0 {
		return true
	}
	for _, k := range []string{"error", "degraded", "skipped"} {
		if _, ok := p[k]; ok {
			return true
		}
	}
	srcs, _ := p["sources"].(map[string]any)
	if len(srcs) == 0 {
		return false
	}
	for _, v := range srcs {
		r, _ := v.(map[string]any)
		if _, failed := r["error"]; failed || r["count"] == nil {
			return false
		}
	}
	return true
}

func sourceSummary(p map[string]any) string {
	srcs, _ := p["sources"].(map[string]any)
	var parts []string
	for _, name := range sortedKeysAny(srcs) {
		v, _ := srcs[name].(map[string]any)
		switch {
		case v["error"] != nil:
			parts = append(parts, name+" error")
		case v["count"] != nil:
			parts = append(parts, fmt.Sprintf("%s %v", name, v["count"]))
		default:
			parts = append(parts, fmt.Sprintf("%s %v", name, v["status"]))
		}
	}
	return strings.Join(parts, ", ")
}

func sortedKeysAny(m map[string]any) []string {
	keys := map[string]bool{}
	for k := range m {
		keys[k] = true
	}
	return sortedKeys(keys)
}

func runOut(name string, args ...string) ([]byte, error) {
	out, m := run("", 2*time.Minute, work, name, args...)
	rec.Runs = rec.Runs[:len(rec.Runs)-1] // bookkeeping, not a measured run
	if m.Error != "" {
		return out, fmt.Errorf("%s", m.Error)
	}
	return out, nil
}
