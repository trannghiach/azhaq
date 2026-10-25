package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
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
		db := filepath.Join(dir, d+"-"+stamp+".db")
		_, m := run(d, 15*time.Minute, dir, azhaq, "run", "-domain", d, "-passive", "-db", db, "-json")
		row.AzhaqSeconds = m.Seconds
		exp, _ := runOut(azhaq, "export", "-db", db)
		g := readExport(exp)

		az := map[string]bool{}
		for _, r := range g.rows {
			if r.Entity.Type == "Hostname" && inDomain(r.Entity.Key, d) {
				az[r.Entity.Key] = true
			}
		}
		for _, p := range g.payloads("azhaq-subdomains") {
			names, _ := p["names"].([]any)
			for _, n := range names {
				if s, _ := n.(string); inDomain(s, d) {
					az[s] = true
				}
			}
			row.CT = subdomainSummary(p)
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
		liveHosts = append(liveHosts, sortedKeys(live)...)
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
	addCheck("subdomain sources and archives: no silent zeros", silent, "every empty result is a failure flagged as error or degraded, or a zero every source answered")
	var azLive, subLive int
	var azTime, subTime float64
	for _, r := range out {
		azLive += r.AzhaqLive
		subLive += r.SubfinderLive
		azTime += r.AzhaqSeconds
		subTime += r.SubSeconds
	}
	addCheck("subdomains: live names ≥ 95% of subfinder's", subLive > 0 && float64(azLive) >= 0.95*float64(subLive),
		"azhaq %d, subfinder %d (all domains, no API keys)", azLive, subLive)
	addCheck("subdomains: within 2× subfinder's time", subTime > 0 && azTime <= 2*subTime,
		"azhaq %.0fs, subfinder %.0fs", azTime, subTime)
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
	answered := 0
	for _, v := range srcs {
		r, _ := v.(map[string]any)
		if _, skipped := r["skipped"]; skipped {
			continue
		}
		if _, failed := r["error"]; failed || r["count"] == nil {
			return false
		}
		answered++
	}
	return answered > 0
}

// subdomainSummary names the sources that found most and counts failures.
func subdomainSummary(p map[string]any) string {
	srcs, _ := p["sources"].(map[string]any)
	type kv struct {
		name string
		n    int
	}
	var ok []kv
	failed := 0
	for name, v := range srcs {
		r, _ := v.(map[string]any)
		switch {
		case r["skipped"] != nil:
		case r["error"] != nil && r["count"] == float64(0):
			failed++
		default:
			c, _ := r["count"].(float64)
			ok = append(ok, kv{name, int(c)})
		}
	}
	sort.Slice(ok, func(i, j int) bool { return ok[i].n > ok[j].n })
	var parts []string
	for i, x := range ok {
		if i == 3 {
			break
		}
		parts = append(parts, fmt.Sprintf("%s %d", x.name, x.n))
	}
	return fmt.Sprintf("%d answered (%s), %d failed", len(ok), strings.Join(parts, ", "), failed)
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
