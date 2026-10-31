package main

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/trannghiach/azhaq/internal/normalize"
	"github.com/trannghiach/azhaq/internal/webextract"
)

// urlsRow compares archived URLs with gau on vulnweb.com: passive lookups,
// one run of each per profile. The archives cannot be asked by the bench
// (the Wayback Machine refuses this machine), so a URL is confirmed by
// being on the domain and not a static asset. azhaq drops scanner junk on
// purpose and counts it, so the bar is that no URL gau lists is lost
// silently: each is in azhaq's list or was dropped as junk, with a reason,
// and azhaq's list and its junk together are at least gau's.
type urlsRow struct {
	Profile   string   `json:"profile,omitempty"`
	Domain    string   `json:"domain"`
	Azhaq     int      `json:"azhaq"`
	Gau       int      `json:"gau"`
	Shared    int      `json:"shared"`
	AzhaqSecs float64  `json:"azhaq_seconds"`
	GauSecs   float64  `json:"gau_seconds"`
	GauOnly   []string `json:"gau_only,omitempty"` // not in azhaq's list: the old bar's loss
	// Dropped is what azhaq's -raw run holds as junk, by reason; GauJunk
	// the URLs of GauOnly among it, and Missing the rest of GauOnly.
	Dropped map[string]int    `json:"dropped_as_junk,omitempty"`
	GauJunk map[string]string `json:"gau_only_junk,omitempty"`
	Missing []string          `json:"missing,omitempty"`
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
	// What azhaq dropped is not in its list: ask for it once more with -raw,
	// which keeps every row, and tell the junk among them by the same test.
	if len(row.GauOnly) > 0 {
		ra := append(append([]string(nil), aa...), "-raw")
		raw := azStart(work, ra...).wait(20 * time.Minute)
		var all map[string]string
		all, row.GauJunk, row.Missing = junkOf([]byte(raw.stdout), urlsDomain, row.GauOnly)
		row.Dropped = reasonCounts(all)
	}
	dropped := 0
	for _, n := range row.Dropped {
		dropped += n
	}
	cmds := cmdLine(azhaq, aa...) + " vs " + cmdLine("gau", ga...)
	note := fmt.Sprintf("azhaq %d listed, %d dropped as junk (%s), gau %d, missing %d %v; %s; %s%s", row.Azhaq, dropped, reasonList(row.Dropped), row.Gau, len(row.Missing),
		clipList(row.Missing, 4), share(row.Shared, row.Gau), ratio(row.AzhaqSecs, row.GauSecs), azErr(runMeasureOf(ar)))
	barOne("urls "+urlsDomain, row.Azhaq+dropped, row.Gau, row.AzhaqSecs, row.GauSecs, "being on the domain and not a static asset, azhaq's list and the URLs it dropped as junk together (the archives refuse this machine, so no other source is asked)", cmds, note)
	addCheck("urls "+urlsDomain+": every URL gau lists is in azhaq's list or dropped as junk with a reason", len(row.Missing) == 0 && row.Gau > 0,
		"azhaq %d listed, %d dropped as junk (%s), gau %d, missing %d %v", row.Azhaq, dropped, reasonList(row.Dropped), row.Gau, len(row.Missing), clipList(row.Missing, 5))
	return row
}

// junkOf reads azhaq's -raw output: every URL on the domain, not a static
// asset, that azhaq's junk test drops, with its reason (all); and which of
// gauOnly are among them (junk, with the reason) and which are not
// (missing).
func junkOf(raw []byte, domain string, gauOnly []string) (all, junk map[string]string, missing []string) {
	all, junk = map[string]string{}, map[string]string{}
	for _, l := range lines(raw) {
		u, err := normalize.URL(l)
		if err != nil || !strings.HasPrefix(u, "http") || !inDomain(normalize.HostFromURL(u), domain) {
			continue
		}
		if why := webextract.JunkReason(u); why != "" && webextract.ClassifyURL(u) != "asset" {
			all[u] = why
		}
	}
	for _, u := range gauOnly {
		if why, ok := all[u]; ok {
			junk[u] = why
		} else {
			missing = append(missing, u)
		}
	}
	return all, junk, missing
}

func reasonCounts(m map[string]string) map[string]int {
	by := map[string]int{}
	for _, why := range m {
		by[why]++
	}
	return by
}

func reasonList(by map[string]int) string {
	if len(by) == 0 {
		return "none"
	}
	keys := make([]string, 0, len(by))
	for k := range by {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = fmt.Sprintf("%d %s", by[k], k)
	}
	return strings.Join(parts, ", ")
}
