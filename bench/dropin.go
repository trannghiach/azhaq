package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/net/html"
)

// dropinRow checks the drop-in commands and export formats: the same
// answers as a full run, through the plumbing a recon script uses.
type dropinRow struct {
	CrawlKnown    int  `json:"crawl_known"`    // Juice Shop known routes from azhaq crawl
	ProbeRows     int  `json:"probe_rows"`     // local apps answered by azhaq probe -json
	ProbeFields   bool `json:"probe_fields"`   // httpx's field names present
	OpenAPIVampi  int  `json:"openapi_vampi"`  // VAmPI spec paths in the OpenAPI export
	OpenAPICrapi  int  `json:"openapi_crapi"`  // crAPI spec paths in the OpenAPI export
	SubsLive      int  `json:"subs_live"`      // azhaq subs -live on vulnweb.com
	SubfinderLive int  `json:"subfinder_live"` // subfinder | dnsx on vulnweb.com
	SubsShared    int  `json:"subs_shared"`
	URLs          int  `json:"urls"`    // azhaq urls on vulnweb.com
	Targets       int  `json:"targets"` // targets export of the probe run
	HTMLOK        bool `json:"html_ok"` // the HTML report parses and has its sections
	HTMLBytes     int  `json:"html_bytes"`
}

func benchDropin(crapi bool) *dropinRow {
	dir, _ := filepath.Abs(filepath.Join(work, "dropin"))
	must(os.MkdirAll(dir, 0o755))
	stamp := time.Now().Format("150405")
	row := &dropinRow{}
	origin := strings.TrimSuffix(juiceURL, "/")

	// crawl, like katana: Juice Shop's known routes.
	out, _ := run("dropin", 10*time.Minute, dir, azhaq, "crawl", "-silent", "-u", juiceURL)
	truth := readTruth("bench/truth/juice-shop-v20.3.0-js.txt")
	row.CrawlKnown = matched(routes(lines(out), origin), truth)
	addCheck("drop-in: azhaq crawl finds Juice Shop's known routes", row.CrawlKnown >= 40,
		"%d/%d", row.CrawlKnown, len(truth))

	// probe, like httpx -json, on stdin.
	out = runStdin(dir, "127.0.0.1:3101\n127.0.0.1:5102\n", azhaq, "probe", "-json", "-silent")
	row.ProbeFields = true
	for _, l := range lines(out) {
		var m map[string]any
		if json.Unmarshal([]byte(l), &m) != nil {
			continue
		}
		row.ProbeRows++
		for _, k := range []string{"url", "status_code", "title", "tech", "webserver", "content_length", "host"} {
			if _, ok := m[k]; !ok {
				row.ProbeFields = false
			}
		}
	}
	addCheck("drop-in: azhaq probe reads stdin and writes httpx's JSON fields", row.ProbeRows == 2 && row.ProbeFields,
		"%d of 2 local apps, fields %v", row.ProbeRows, row.ProbeFields)

	// OpenAPI export of the routes mapped on VAmPI (and crAPI).
	vdb := filepath.Join(dir, "vampi-"+stamp+".db")
	run("dropin", 10*time.Minute, dir, azhaq, "run", "-url", vampiURL, "-db", vdb, "-quiet")
	row.OpenAPIVampi = openAPIPaths(dir, vdb, specPaths(vampiURL+"openapi.json"))
	vtruth := specPaths(vampiURL + "openapi.json")
	addCheck("export: OpenAPI of VAmPI holds every path of its own description", row.OpenAPIVampi == len(vtruth),
		"%d/%d", row.OpenAPIVampi, len(vtruth))
	if crapi {
		cdb := filepath.Join(dir, "crapi-"+stamp+".db")
		run("dropin", 10*time.Minute, dir, azhaq, "run", "-url", crapiURL, "-db", cdb, "-quiet")
		row.OpenAPICrapi = openAPIPaths(dir, cdb, crapiTruth())
		addCheck("export: OpenAPI of crAPI holds ≥ 30 of its 40 paths", row.OpenAPICrapi >= 30, "%d/40", row.OpenAPICrapi)
	}

	// subs -live, like subfinder | dnsx, on vulnweb.com.
	out, _ = run("dropin", 10*time.Minute, dir, azhaq, "subs", "-d", bruteDomain, "-live", "-silent")
	az := hostSet(lines(out))
	sub, _ := run("dropin", 10*time.Minute, dir, ref("subfinder"), "-d", bruteDomain, "-silent")
	subFile := filepath.Join(dir, "subfinder-"+stamp+".txt")
	must(os.WriteFile(subFile, sub, 0o644))
	live, _ := run("dropin", 10*time.Minute, dir, ref("dnsx"), "-l", subFile, "-silent")
	want := hostSet(lines(live))
	row.SubsLive, row.SubfinderLive, row.SubsShared = len(az), len(want), overlap(want, az)
	addCheck("drop-in: azhaq subs -live ≥ 95% of subfinder | dnsx", row.SubfinderLive > 0 && float64(row.SubsShared) >= 0.95*float64(row.SubfinderLive),
		"azhaq %d, subfinder|dnsx %d, shared %d (%s)", row.SubsLive, row.SubfinderLive, row.SubsShared, bruteDomain)

	// urls, like gau.
	out, _ = run("dropin", 10*time.Minute, dir, azhaq, "urls", "-d", bruteDomain, "-silent")
	row.URLs = len(lines(out))

	// targets and HTML from the probe run's database.
	pdb := filepath.Join(dir, "probe-"+stamp+".db")
	runStdin(dir, "127.0.0.1:3101\n127.0.0.1:5102\n", azhaq, "probe", "-silent", "-db", pdb)
	out, _ = run("dropin", time.Minute, dir, azhaq, "export", "-db", pdb, "-format", "targets")
	row.Targets = len(lines(out))
	page, _ := run("dropin", time.Minute, dir, azhaq, "export", "-db", vdb, "-format", "html")
	row.HTMLBytes = len(page)
	row.HTMLOK = htmlHas(page, "Web services", "API routes", "Map")
	addCheck("export: targets and HTML report", row.Targets == 2 && row.HTMLOK && row.URLs > 0,
		"targets %d of 2, HTML %d bytes with its sections %v, urls %d", row.Targets, row.HTMLBytes, row.HTMLOK, row.URLs)
	return row
}

// openAPIPaths exports db as OpenAPI and counts the truth paths it holds.
func openAPIPaths(dir, db string, truth map[string]bool) int {
	out, _ := run("dropin", time.Minute, dir, azhaq, "export", "-db", db, "-format", "openapi")
	var doc struct {
		Servers []struct{ URL string }
		Paths   map[string]any
	}
	if json.Unmarshal(out, &doc) != nil {
		return 0
	}
	found := map[string]bool{}
	for p := range doc.Paths {
		found[route(p)] = true
	}
	return matched(found, truth)
}

func crapiTruth() map[string]bool {
	raw, err := os.ReadFile(filepath.Join(crapiDir(), "openapi-spec", "crapi-openapi-spec.json"))
	must(err)
	var spec struct {
		Paths map[string]any `json:"paths"`
	}
	must(json.Unmarshal(raw, &spec))
	truth := map[string]bool{}
	for p := range spec.Paths {
		truth[route(p)] = true
	}
	return truth
}

// runStdin is run with input on stdin.
func runStdin(dir, input, name string, args ...string) []byte {
	f := filepath.Join(dir, "stdin.txt")
	must(os.WriteFile(f, []byte(input), 0o644))
	out, _ := run("dropin", 10*time.Minute, dir, "/bin/sh", append([]string{"-c", `"$0" "$@" < ` + f, name}, args...)...)
	return out
}

// htmlHas parses page and looks for each heading.
func htmlHas(page []byte, headings ...string) bool {
	doc, err := html.Parse(bytes.NewReader(page))
	if err != nil {
		return false
	}
	var text strings.Builder
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "h2" && n.FirstChild != nil {
			text.WriteString(n.FirstChild.Data + "\n")
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	for _, h := range headings {
		if !strings.Contains(text.String(), h) {
			return false
		}
	}
	return true
}
