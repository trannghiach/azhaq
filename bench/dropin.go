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
	CrawlKnown    int  `json:"crawl_known"`    // Juice Shop routes its pages and scripts name, from azhaq crawl
	CrawlOf       int  `json:"crawl_of"`       // of those (the known routes less CrawlMapOnly)
	CrawlMapOnly  int  `json:"crawl_map_only"` // known routes only the full map reaches (see the truth file)
	CrawlMapFound int  `json:"crawl_map_only_found"`
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
	// -json: the routes with parameters (/api/Cards/{id}) are there too;
	// the plain list holds only URLs that can be requested.
	out, _ := run("dropin", 10*time.Minute, dir, azhaq, "crawl", "-json", "-silent", "-u", juiceURL)
	truth := readTruth("bench/truth/juice-shop-v20.3.0-routes.txt")
	// A crawler asks what pages and scripts name; the truth also holds routes
	// that only the full map reaches (the id form of a collection the frontend
	// never asks for, a prefix constant, /ftp from robots.txt).
	mapOnly := readTruth("bench/truth/juice-shop-v20.3.0-full-map-only.txt")
	truth, mapOnly = splitTruth(truth, mapOnly)
	var crawled []string
	for _, l := range lines(out) {
		var r struct {
			URL string `json:"url"`
		}
		if json.Unmarshal([]byte(l), &r) == nil && r.URL != "" {
			crawled = append(crawled, r.URL)
		}
	}
	found := routes(crawled, origin)
	row.CrawlKnown, row.CrawlOf = matched(found, truth), len(truth)
	row.CrawlMapOnly, row.CrawlMapFound = len(mapOnly), matched(found, mapOnly)
	addCheck("drop-in: azhaq crawl finds every Juice Shop route its pages and scripts name", row.CrawlKnown == row.CrawlOf,
		"%d/%d (%d more known routes only the full map reaches; crawl found %d of them)", row.CrawlKnown, row.CrawlOf, row.CrawlMapOnly, row.CrawlMapFound)

	// probe, like httpx -json, on stdin.
	out = runStdin(dir, "127.0.0.1:3101\n127.0.0.1:5102\n", azhaq, "probe", "-json", "-silent")
	row.ProbeFields = true
	for _, l := range lines(out) {
		var m map[string]any
		if json.Unmarshal([]byte(l), &m) != nil {
			continue
		}
		row.ProbeRows++
		// httpx's fields that are always there; title, tech and webserver
		// are left out when empty, by httpx too.
		for _, k := range []string{"url", "input", "status_code", "content_length", "host", "host_ip", "port", "scheme", "a"} {
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

	// urls and subs have their own sections (urls, domains).

	// targets and HTML from the probe run's database.
	pdb := filepath.Join(dir, "probe-"+stamp+".db")
	runStdin(dir, "127.0.0.1:3101\n127.0.0.1:5102\n", azhaq, "probe", "-silent", "-db", pdb)
	out, _ = run("dropin", time.Minute, dir, azhaq, "export", "-db", pdb, "-format", "targets")
	row.Targets = len(lines(out))
	page, _ := run("dropin", time.Minute, dir, azhaq, "export", "-db", vdb, "-format", "html")
	row.HTMLBytes = len(page)
	row.HTMLOK = htmlHas(page, "Web services", "API routes", "Map")
	addCheck("export: targets and HTML report", row.Targets == 2 && row.HTMLOK,
		"targets %d of 2, HTML %d bytes with its sections %v", row.Targets, row.HTMLBytes, row.HTMLOK)
	return row
}

// splitTruth takes mapOnly out of truth; it returns the rest, and mapOnly
// narrowed to what truth holds.
func splitTruth(truth, mapOnly map[string]bool) (rest, only map[string]bool) {
	rest, only = map[string]bool{}, map[string]bool{}
	for t := range truth {
		if mapOnly[t] {
			only[t] = true
		} else {
			rest[t] = true
		}
	}
	return rest, only
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
