package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// The README's benchmark table is written from the newest record in
// bench/history (go run ./bench -readme), between these markers, so its
// numbers are the ones of a run and cannot drift from it.
const (
	readmeBegin = "<!-- bench:begin -->"
	readmeEnd   = "<!-- bench:end -->"
)

// newestRecord reads the record with the latest name in dir.
func newestRecord(dir string) (*record, error) {
	files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	if len(files) == 0 {
		return nil, fmt.Errorf("no record in %s", dir)
	}
	sort.Strings(files)
	raw, err := os.ReadFile(files[len(files)-1])
	if err != nil {
		return nil, err
	}
	var r record
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("%s: %v", files[len(files)-1], err)
	}
	return &r, nil
}

type tableRow struct{ job, replaces, azhaq, ref string }

func secs(s float64) string {
	if s >= 10 {
		return fmt.Sprintf("%.0f s", s)
	}
	return fmt.Sprintf("%.1f s", s)
}

// tableRows are the comparison rows of one profile.
func tableRows(ps *profileSet) []tableRow {
	var rows []tableRow
	if len(ps.Domains) > 0 {
		var aOK, rOK, gaps int
		var aT, rT float64
		for _, d := range ps.Domains {
			aOK, rOK, gaps = aOK+d.AzhaqLive, rOK+d.SubfinderLive, gaps+len(d.Gaps)
			aT, rT = aT+d.AzhaqSeconds, rT+d.RefSeconds
		}
		rows = append(rows, tableRow{fmt.Sprintf("Live subdomains, %d domains, no keys (names that resolve at a third resolver)", len(ps.Domains)), "subfinder + dnsx",
			fmt.Sprintf("%d live in %s", aOK, secs(aT)), fmt.Sprintf("%d live in %s (%d only it found)", rOK, secs(rT), gaps)})
	}
	if u := ps.URLs; u != nil {
		rows = append(rows, tableRow{"Historical URLs, " + u.Domain, "gau", fmt.Sprintf("%d, including %d of gau's %d, in %s", u.Azhaq, u.Shared, u.Gau, secs(u.AzhaqSecs)), fmt.Sprintf("%d in %s", u.Gau, secs(u.GauSecs))})
	}
	if b := ps.Brute; b != nil {
		rows = append(rows, tableRow{fmt.Sprintf("DNS brute force, %d words, the DNS lab", b.Words), "dnsx", fmt.Sprintf("%d confirmed in %s", b.AzhaqOK, secs(b.AzhaqSeconds)), fmt.Sprintf("%d in %s", b.DnsxOK, secs(b.DnsxSeconds))})
		if b.WildcardWords > 0 {
			rows = append(rows, tableRow{fmt.Sprintf("Wildcard zone, %d real names of %d", b.WildcardReal, b.WildcardWords), "dnsx", fmt.Sprintf("%d found, %d fake", b.WildcardAzhaq-b.WildcardFake, b.WildcardFake), fmt.Sprintf("%d without `-wd`", b.WildcardNoWild)})
		}
	}
	if d := ps.DNS; d != nil {
		rows = append(rows, tableRow{fmt.Sprintf("Record types (9) of %d names on a zone the bench serves", d.Names), "dnsx", fmt.Sprintf("%d answers right in %s, %d queries", d.AzhaqOK, secs(d.AzhaqSecs), d.AzhaqQ), fmt.Sprintf("%d in %s, %d queries", d.DnsxOK, secs(d.DnsxSecs), d.DnsxQ)})
	}
	if p := ps.Probe; p != nil {
		rows = append(rows, tableRow{fmt.Sprintf("Probing %d hosts (the local apps and 100 local servers)", p.Hosts), "httpx", fmt.Sprintf("%d answered, %d confirmed; status, title and tech agree on %d of %d shared; %s", p.AzhaqAnswered, p.AzhaqOK, p.All, p.Shared, secs(p.AzhaqSeconds)),
			fmt.Sprintf("%d answered, %d confirmed; %s", p.HttpxAnswered, p.HttpxOK, secs(p.HttpxSeconds))})
	}
	for _, a := range ps.Apps {
		// Two measures that must not be read as one: the whole map, and the crawler alone.
		if a.Azhaq.TruthOf > 0 && a.Katana.TruthOf > 0 {
			rows = append(rows, tableRow{"Known routes of " + a.Name + ", the whole map (`azhaq run`)", "katana `-jc -jsl`", fmt.Sprintf("%d/%d in %s", a.Azhaq.Truth, a.Azhaq.TruthOf, secs(a.Azhaq.Seconds)),
				fmt.Sprintf("%d/%d in %s", a.Katana.Truth, a.Katana.TruthOf, secs(a.Katana.Seconds))})
		}
		if a.Crawl != nil && a.CrawlKatana != nil {
			rows = append(rows, tableRow{"Known routes of " + a.Name + ", the crawler alone (`azhaq crawl`, katana's depth)", "katana `-jc -jsl`", fmt.Sprintf("%d/%d in %s", a.Crawl.Truth, a.Crawl.TruthOf, secs(a.Crawl.Seconds)),
				fmt.Sprintf("%d/%d in %s", a.CrawlKatana.Truth, a.CrawlKatana.TruthOf, secs(a.CrawlKatana.Seconds))})
		}
	}
	if d := ps.Dirs; d != nil {
		rows = append(rows, tableRow{fmt.Sprintf("Paths, %d words, Juice Shop and VAmPI", d.Words), "ffuf `-ac`", fmt.Sprintf("%d hits, %d false positives, %s", d.AzhaqHits, d.AzhaqFalse, secs(d.AzhaqSecs)), fmt.Sprintf("%d hits, %d false positives, %s", d.FfufHits, d.FfufFalse, secs(d.FfufSecs))})
		if d.AppDowns > 0 {
			rows[len(rows)-1].job += fmt.Sprintf(" (an app went down %d times during the sweep: not a measure)", d.AppDowns)
		}
	}
	if f := ps.Fuzz; f != nil {
		var aH, fH, aOK, fOK int
		var aT, fT float64
		eq, n := 0, 0
		for _, l := range f.Legs {
			aH, fH, aOK, fOK, aT, fT = aH+l.AzhaqHits, fH+l.FfufHits, aOK+l.AzhaqOK, fOK+l.FfufOK, aT+l.AzhaqSecs, fT+l.FfufSecs
			if l.ReportEqual != nil {
				n++
				if *l.ReportEqual {
					eq++
				}
			}
		}
		rep := ""
		if n > 0 {
			rep = fmt.Sprintf("; JSON report equal on %d of %d", eq, n)
		}
		rows = append(rows, tableRow{fmt.Sprintf("Fuzzing, %d words, Juice Shop and VAmPI, %d runs", f.Words, len(f.Legs)), "ffuf", fmt.Sprintf("%d hits (%d confirmed), %s%s", aH, aOK, secs(aT), rep), fmt.Sprintf("%d hits (%d confirmed), %s", fH, fOK, secs(fT))})
		if f.AppDowns > 0 {
			rows[len(rows)-1].job += fmt.Sprintf(" (an app went down %d times during the sweeps: not a measure)", f.AppDowns)
		}
	}
	if p := ps.Params; p != nil {
		rows = append(rows, tableRow{fmt.Sprintf("Parameters, %d planted, %d pages", p.PlantedTruth, len(p.Pages)), "arjun", fmt.Sprintf("%d right, %d wrong, %s", p.AzhaqPlanted, p.AzhaqWrong, secs(p.AzhaqSecs)), fmt.Sprintf("%d right, %d wrong, %s", p.ArjunPlanted, p.ArjunWrong, secs(p.ArjunSecs))})
	}
	if p := ps.Ports; p != nil {
		for _, l := range p.Legs {
			rows = append(rows, tableRow{"Open ports, " + l.Target + " " + portsLabel(l.Ports), "`naabu -scan-type c`", fmt.Sprintf("%d confirmed in %s", l.AzhaqOK, secs(l.AzhaqSecs)), fmt.Sprintf("%d confirmed in %s", l.NaabuOK, secs(l.NaabuSecs))})
		}
	}
	if s := ps.Services; s != nil {
		rows = append(rows, tableRow{fmt.Sprintf("Services named right on %d lab ports", s.Ports), "nmap `-sV`", fmt.Sprintf("%d, %d with a product, %s", s.AzhaqNamed, s.AzhaqVer, secs(s.AzhaqSecs)), fmt.Sprintf("%d, %d with a product, %s", s.NmapNamed, s.NmapVer, secs(s.NmapSecs))})
	}
	if s := ps.Shots; s != nil {
		rows = append(rows, tableRow{fmt.Sprintf("Screenshots, %d targets (not blank)", s.Targets), "gowitness", fmt.Sprintf("%d in %s", s.AzhaqOK, secs(s.AzhaqSeconds)), fmt.Sprintf("%d in %s", s.GowitnessOK, secs(s.GowitnessSecs))})
		if s.Unpaced {
			rows[len(rows)-1].job += " (gowitness has no rate option and ran at full speed: the times are not compared)"
		}
	}
	if n := ps.Notify; n != nil {
		rows = append(rows, tableRow{fmt.Sprintf("Notifications, %d messages to 2 providers, as the stub received them", n.Messages), "notify", fmt.Sprintf("%d in %s", n.AzhaqOK, secs(n.AzhaqSecs)), fmt.Sprintf("%d in %s", n.NotifyOK, secs(n.NotifySecs))})
	}
	return rows
}

// readmeBlock is the text between the markers.
func readmeBlock(r *record, version string) string {
	day := strings.SplitN(r.Date, "T", 2)[0]
	pass := 0
	for _, c := range r.Checks {
		if c.Pass {
			pass++
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Latest run (%s, v%s, commit %s; profile: %s; %d of %d checks pass). **Default** is the default flags of both tools; **polite** is `-rate %s` (HTTP; `probe -rl`, as httpx counts), `-dns-rate %s` (DNS; `dns -rl`, as dnsx counts) and `-rate %s` (ports), with the reference tool at the same rate. A result counts only when something other than azhaq confirms it, and a row is a win only when azhaq has at least the reference's results in at most 1.05 times its time. The record, with every check and the commands, is `bench/history/*.json`.\n\n",
		day, version, r.Commit, r.Profile, pass, len(r.Checks), politeHTTP, politeDNS, politePort)
	b.WriteString("| Job | Replaces | Profile | Azhaq | Reference |\n| --- | --- | --- | --- | --- |\n")
	for _, set := range []struct {
		name string
		ps   *profileSet
	}{{"default", &r.profileSet}, {"polite", r.Polite}} {
		if set.ps == nil {
			continue
		}
		for _, row := range tableRows(set.ps) {
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n", row.job, row.replaces, set.name, row.azhaq, row.ref)
		}
	}
	return b.String()
}

// writeReadme puts readmeBlock between the markers of README.md.
func writeReadme(dir string) error {
	r, err := newestRecord(dir)
	if err != nil {
		return err
	}
	version := "0.0.0"
	if b, err := os.ReadFile("CHANGELOG.md"); err == nil {
		if m := changeHead.FindStringSubmatch(string(b)); m != nil {
			version = m[1]
		}
	}
	raw, err := os.ReadFile("README.md")
	if err != nil {
		return err
	}
	text := string(raw)
	i, j := strings.Index(text, readmeBegin), strings.Index(text, readmeEnd)
	if i < 0 || j < i {
		return fmt.Errorf("README.md has no %s … %s markers", readmeBegin, readmeEnd)
	}
	text = text[:i+len(readmeBegin)] + "\n" + readmeBlock(r, version) + text[j:]
	if err := os.WriteFile("README.md", []byte(text), 0o644); err != nil {
		return err
	}
	fmt.Printf("README.md: the benchmark table is from %s (%s)\n", r.Date, r.Commit)
	return nil
}

// portsLabel is a port spec without a long list of listener ports.
func portsLabel(p string) string {
	if strings.Contains(p, ",") {
		return "(the bench's own listeners)"
	}
	return p
}
