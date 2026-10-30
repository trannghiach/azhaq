package main

import (
	"fmt"
	"sort"
	"time"
)

// urlsRow compares archived URLs with gau on vulnweb.com: passive lookups,
// one run of each per profile. The archives cannot be asked by the bench
// (the Wayback Machine refuses this machine), so a URL is confirmed by
// being on the domain and not a static asset, and the bar is that no URL
// gau lists is missing from azhaq's list.
type urlsRow struct {
	Profile   string   `json:"profile,omitempty"`
	Domain    string   `json:"domain"`
	Azhaq     int      `json:"azhaq"`
	Gau       int      `json:"gau"`
	Shared    int      `json:"shared"`
	AzhaqSecs float64  `json:"azhaq_seconds"`
	GauSecs   float64  `json:"gau_seconds"`
	GauOnly   []string `json:"gau_only,omitempty"`
}

const urlsDomain = "vulnweb.com"

func benchURLs() *urlsRow {
	row := &urlsRow{Profile: prof, Domain: urlsDomain}
	aa := []string{"urls", "-d", urlsDomain, "-silent"}
	// gau stops every provider when one cannot start, and Common Crawl's index
	// refuses connections from some networks: it runs with the providers that
	// start everywhere. The flag is gau's, the polite profile asks one at a time.
	ga := []string{"--providers", "wayback,otx,urlscan", "--timeout", "30", urlsDomain}
	if polite() {
		ga = append([]string{"--threads", "1"}, ga...)
		if helpHas("urls", "-rate") {
			aa = append(aa, "-rate", politeHTTP)
		}
	}
	ar := azRun(urlsDomain, 20*time.Minute, work, aa...)
	gOut, gm := run(urlsDomain, 20*time.Minute, work, ref("gau"), ga...)
	azURLs := urlSet([]byte(ar.stdout), urlsDomain)
	gau := urlSet(gOut, urlsDomain)
	row.Azhaq, row.Gau, row.Shared = len(azURLs), len(gau), overlap(gau, azURLs)
	row.AzhaqSecs, row.GauSecs = ar.seconds, gm.Seconds
	for u := range gau {
		if !azURLs[u] {
			row.GauOnly = append(row.GauOnly, u)
		}
	}
	sort.Strings(row.GauOnly)
	cmds := cmdLine(azhaq, aa...) + " vs " + cmdLine("gau", ga...)
	note := fmt.Sprintf("%s; azhaq %d URLs, gau %d, gau's missing from azhaq %d %v; %s%s", share(row.Shared, row.Gau), row.Azhaq, row.Gau, len(row.GauOnly),
		clipList(row.GauOnly, 4), ratio(row.AzhaqSecs, row.GauSecs), azErr(runMeasureOf(ar)))
	barOne("urls "+urlsDomain, row.Azhaq, row.Gau, row.AzhaqSecs, row.GauSecs, "being on the domain and not a static asset (the archives refuse this machine, so no other source is asked)", cmds, note)
	addCheck("urls "+urlsDomain+": every URL gau lists is in azhaq's list", len(row.GauOnly) == 0 && row.Gau > 0,
		"%d of gau's %d missing %v", len(row.GauOnly), row.Gau, clipList(row.GauOnly, 5))
	return row
}
