package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/trannghiach/azhaq/internal/normalize"
	"github.com/trannghiach/azhaq/internal/webextract"
)

// domainRow compares passive subdomain discovery on one domain. A name is
// live when dnsx resolves it; both tools are judged on the same list.
type domainRow struct {
	Domain         string   `json:"domain"`
	AzhaqNames     int      `json:"azhaq_names"`
	SubfinderNames int      `json:"subfinder_names"`
	Live           int      `json:"live"`
	AzhaqLive      int      `json:"azhaq_live"`
	SubfinderLive  int      `json:"subfinder_live"`
	SharedLive     int      `json:"shared_live"`
	AzhaqSeconds   float64  `json:"azhaq_seconds"`      // the whole passive run: subdomains, DNS, archives
	AzhaqSubs      float64  `json:"azhaq_subs_seconds"` // until the subdomain results were in
	SubSeconds     float64  `json:"subfinder_seconds"`
	GauSeconds     float64  `json:"gau_seconds"`
	CT             string   `json:"ct"`
	AzhaqURLs      int      `json:"azhaq_urls"` // distinct, static assets left out
	GauURLs        int      `json:"gau_urls"`
	GauShared      int      `json:"gau_shared"` // gau's URLs Azhaq also listed
	CDX            string   `json:"archives"`
	Profile        string   `json:"profile,omitempty"`
	RefSeconds     float64  `json:"reference_seconds,omitempty"` // subfinder and dnsx together
	Gaps           []string `json:"gaps,omitempty"`              // confirmed live names only the reference found
}

// independentResolvers are not the two the tools are given, so a name both
// tools call live is checked by a resolver neither used.
var independentResolvers = []string{"9.9.9.9:53", "208.67.222.222:53"}

// resolvers the tools share in the domain and brute comparisons.
var sharedResolvers = []string{"1.1.1.1", "8.8.8.8"}

var liveCache = map[string]bool{}

// liveIndependent reports which names resolve (A, AAAA or CNAME) at the
// independent resolvers, asked directly by the bench.
func liveIndependent(names []string) map[string]bool {
	var todo []string
	for _, n := range names {
		if _, ok := liveCache[n]; !ok {
			todo = append(todo, n)
		}
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	next := make(chan string)
	for w := 0; w < 24; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cli := &dns.Client{Timeout: 4 * time.Second}
			for n := range next {
				ok := false
			resolve:
				for _, srv := range independentResolvers {
					for _, t := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeCNAME} {
						q := new(dns.Msg)
						q.SetQuestion(dns.Fqdn(n), t)
						if r, _, err := cli.Exchange(q, srv); err == nil && r.Rcode == dns.RcodeSuccess && len(r.Answer) > 0 {
							ok = true
							break resolve
						}
					}
				}
				mu.Lock()
				liveCache[n] = ok
				mu.Unlock()
			}
		}()
	}
	for _, n := range todo {
		next <- n
	}
	close(next)
	wg.Wait()
	out := map[string]bool{}
	for _, n := range names {
		if liveCache[n] {
			out[n] = true
		}
	}
	return out
}

func benchDomains() []domainRow {
	listFile := "bench/domains.txt"
	if f := os.Getenv("AZHAQ_BENCH_DOMAINS"); f != "" { // while developing: one small domain
		listFile = f
	}
	raw, err := os.ReadFile(listFile)
	must(err)
	dir, _ := filepath.Abs(filepath.Join(work, "domains"))
	must(os.MkdirAll(dir, 0o755))
	resFile := filepath.Join(dir, "resolvers.txt")
	must(os.WriteFile(resFile, []byte(strings.Join(sharedResolvers, "\n")+"\n"), 0o644))
	var out []domainRow
	silent := true
	for _, d := range lines(raw) {
		if polite() && !slices.Contains(politeDomains, d) {
			continue // at 10 DNS queries per second tesla.com alone takes minutes a tool
		}
		logf("domain %s", d)
		row := domainRow{Domain: d, Profile: prof}

		// azhaq subs -live: the passive sources and the DNS check, one command.
		aa := []string{"subs", "-d", d, "-live", "-json", "-silent", "-resolvers", resFile}
		if polite() {
			aa = append(aa, "-dns-rate", politeDNS)
		}
		ar := azRun(d, 30*time.Minute, dir, aa...)
		az := map[string]bool{}
		for _, l := range lines([]byte(ar.stdout)) {
			var o struct {
				Host string `json:"host"`
			}
			if json.Unmarshal([]byte(l), &o) == nil && o.Host != "" && inDomain(o.Host, d) {
				az[strings.ToLower(o.Host)] = true
			}
		}
		row.AzhaqSeconds, row.AzhaqSubs, row.AzhaqNames, row.AzhaqLive = ar.seconds, ar.seconds, len(az), len(az)
		summary := lastSummary(ar.stderr)
		if !explained(summary) && !strings.Contains(ar.stderr, "error") && !strings.Contains(ar.stderr, "failed") {
			silent = false
		}
		if _, ok := summary["sources"]; ok {
			row.CT = subdomainSummary(summary)
		}

		// subfinder, then dnsx on its names, as the pipeline a reviewer runs.
		sa := []string{"-d", d, "-silent", "-json", "-cs"}
		subOut, sm := run(d, 30*time.Minute, dir, ref("subfinder"), sa...)
		sub, srcOf := map[string]bool{}, map[string][]string{}
		for _, l := range lines(subOut) {
			var o struct {
				Host   string   `json:"host"`
				Source []string `json:"source"`
			}
			if json.Unmarshal([]byte(l), &o) == nil && o.Host != "" && inDomain(o.Host, d) {
				n := strings.ToLower(o.Host)
				sub[n], srcOf[n] = true, o.Source
			}
		}
		row.SubfinderNames, row.SubSeconds = len(sub), sm.Seconds
		list := filepath.Join(dir, d+"-"+prof+"-names.txt")
		must(os.WriteFile(list, []byte(strings.Join(sortedKeys(sub), "\n")+"\n"), 0o644))
		da := append([]string{"-l", list, "-silent", "-a", "-aaaa", "-cname", "-r", strings.Join(sharedResolvers, ",")}, pick([]string(nil), []string{"-rl", politeDNS})...)
		liveOut, dm := run(d, 30*time.Minute, dir, ref("dnsx"), da...)
		dx := map[string]bool{}
		for _, n := range lines(liveOut) {
			dx[strings.ToLower(strings.Fields(n)[0])] = true
		}
		row.SubfinderLive = len(dx)
		refSecs := sm.Seconds + dm.Seconds

		// Which of the names each tool calls live resolve at another resolver.
		claimed := map[string]bool{}
		for n := range az {
			claimed[n] = true
		}
		for n := range dx {
			claimed[n] = true
		}
		conf := liveIndependent(sortedKeys(claimed))
		row.Live = len(conf)
		var azOK, refOK int
		var gaps []string
		for n := range conf {
			if az[n] {
				azOK++
			}
			if dx[n] {
				refOK++
				if !az[n] {
					gaps = append(gaps, n)
				}
			}
			if az[n] && dx[n] {
				row.SharedLive++
			}
		}
		sort.Strings(gaps)
		row.AzhaqLive, row.SubfinderLive = azOK, refOK
		row.Gaps = gaps
		row.RefSeconds = refSecs
		unexplained := 0
		var why []string
		for _, g := range gaps {
			ok := false
			for _, src := range srcOf[g] {
				if sourceFailed(ar.stderr, src) {
					ok = true
				}
			}
			if !ok {
				unexplained++
			}
			why = append(why, fmt.Sprintf("%s (subfinder: %s)", g, strings.Join(srcOf[g], ",")))
		}
		cmds := cmdLine(azhaq, aa...) + " vs " + cmdLine("subfinder", sa...) + " | " + cmdLine("dnsx", da...)
		barOne("subs -live "+d, azOK, refOK, ar.seconds, refSecs, "a name resolving at 9.9.9.9 or 208.67.222.222 (A, AAAA or CNAME)", cmds,
			fmt.Sprintf("%s; azhaq printed %d, subfinder %d names, dnsx %d live; azhaq %d, reference %d confirmed, both %d; subfinder %.0fs + dnsx %.0fs; %s%s",
				share(row.SharedLive, refOK), len(az), len(sub), len(dx), azOK, refOK, row.SharedLive, sm.Seconds, dm.Seconds, ratio(ar.seconds, refSecs), azErr(runMeasureOf(ar))))
		addCheck("subs -live "+d+": every confirmed live name subfinder | dnsx finds is in azhaq's list or its source is named as failed", unexplained == 0,
			"%d gaps, %d unexplained: %s", len(gaps), unexplained, clipList(why, 8))
		out = append(out, row)
	}
	addCheck("subdomain sources: no silent zeros", silent, "every empty result is a failure flagged as error or degraded, or a zero every source answered")
	return out
}

func runMeasureOf(r azResult) runMeasure {
	if r.exit == 0 {
		return runMeasure{}
	}
	return runMeasure{Error: fmt.Sprintf("exit status %d %s", r.exit, lastLine(r.stderr))}
}

// lastSummary is the summary object azhaq printed on stderr.
func lastSummary(stderr string) map[string]any {
	ls := strings.Split(stderr, "\n")
	for i := len(ls) - 1; i >= 0; i-- {
		var o map[string]any
		if l := strings.TrimSpace(ls[i]); strings.HasPrefix(l, "{") && json.Unmarshal([]byte(l), &o) == nil && o["type"] == "summary" {
			return o
		}
	}
	return map[string]any{}
}

// sourceFailed: azhaq's stderr names the source as failed or degraded.
func sourceFailed(stderr, src string) bool {
	src = strings.ToLower(src)
	for _, l := range strings.Split(strings.ToLower(stderr), "\n") {
		if strings.Contains(l, src) && (strings.Contains(l, "fail") || strings.Contains(l, "error") || strings.Contains(l, "429") || strings.Contains(l, "degraded")) {
			return true
		}
	}
	return false
}

// urlSet normalizes a URL list the way Azhaq stores URLs and leaves out
// static assets and other domains.
func urlSet(raw []byte, domain string) map[string]bool {
	set := map[string]bool{}
	for _, l := range lines(raw) {
		u, err := normalize.URL(l)
		if err != nil || !strings.HasPrefix(u, "http") || !inDomain(normalize.HostFromURL(u), domain) || webextract.ClassifyURL(u) == "asset" {
			continue
		}
		set[u] = true
	}
	return set
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
