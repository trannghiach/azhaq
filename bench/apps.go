package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/trannghiach/azhaq/internal/collectors/pathscol"
)

const (
	juiceURL = "http://127.0.0.1:3101/"
	vampiURL = "http://127.0.0.1:5102/"
	ginURL   = "https://ginandjuice.shop/"
)

type appResult struct {
	Name   string    `json:"name"`
	URL    string    `json:"url"`
	Azhaq  toolScore `json:"azhaq"`
	Katana toolScore `json:"katana"`
	Ffuf   *ffufRow  `json:"ffuf,omitempty"`
}

// toolScore is what one tool found on one app.
type toolScore struct {
	Routes  int     `json:"routes"`          // distinct non-asset paths on the app's origin
	Truth   int     `json:"truth,omitempty"` // known routes found
	TruthOf int     `json:"truth_of,omitempty"`
	Shell   int     `json:"shell"` // reported URLs that are the app's catch-all page
	Seconds float64 `json:"seconds"`
	RSSMB   float64 `json:"rss_mb"`
}

// ffufRow compares the wordlist sweep with ffuf on the same list.
type ffufRow struct {
	Words      int     `json:"words"`
	AzhaqHits  int     `json:"azhaq_hits"`
	FfufHits   int     `json:"ffuf_hits"`
	Shared     int     `json:"shared"`
	AzhaqShell int     `json:"azhaq_shell"`
	FfufShell  int     `json:"ffuf_shell"`
	Seconds    float64 `json:"seconds"`
}

func startApps() error {
	logf("starting docker apps")
	cmd := exec.Command("docker", "compose", "-f", "bench/compose.yaml", "up", "-d")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("docker compose up: %v\n%s", err, out)
	}
	for _, u := range []string{juiceURL, vampiURL} {
		if err := waitUp(u, 3*time.Minute); err != nil {
			return err
		}
	}
	return nil
}

func stopApps() {
	_ = exec.Command("docker", "compose", "-f", "bench/compose.yaml", "down").Run()
}

func waitUp(u string, max time.Duration) error {
	deadline := time.Now().Add(max)
	for time.Now().Before(deadline) {
		resp, err := http.Get(u)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("%s not up after %s", u, max)
}

func benchApps() []appResult {
	dir, _ := filepath.Abs(filepath.Join(work, "apps"))
	must(os.MkdirAll(dir, 0o755))
	stamp := time.Now().Format("150405")
	db := func(name string) string { return filepath.Join(dir, name+"-"+stamp+".db") }

	var res []appResult

	// Juice Shop: JS routes, SPA catch-all pages, diff stability.
	juice := appResult{Name: "juice-shop", URL: juiceURL}
	truth := readTruth("bench/truth/juice-shop-v20.3.0-js.txt")
	g, _, m := runAzhaq(juiceURL, db("juice"))
	shell := shellHash(juiceURL)
	juice.Azhaq = scoreAzhaq(g, juiceURL, truth, shell, m)
	juice.Katana = runKatana(juiceURL, truth, shell)
	juice.Ffuf = compareFfuf(juiceURL, g, shell)
	res = append(res, juice)
	addCheck("juice-shop: JS routes ≥ 40/45", juice.Azhaq.Truth >= 40, "azhaq %d/%d, katana %d/%d", juice.Azhaq.Truth, len(truth), juice.Katana.Truth, len(truth))
	addCheck("juice-shop: no catch-all page reported as visited", juice.Azhaq.Shell == 0, "%d visited URLs return the SPA index", juice.Azhaq.Shell)

	_, _, _ = runAzhaq(juiceURL, db("juice-again"))
	sum := diffSummary(db("juice"), db("juice-again"))
	addCheck("identical runs diff empty", sum.Added == 0 && sum.Removed == 0 && sum.Observations == 0,
		"added=%d removed=%d observations=%d", sum.Added, sum.Removed, sum.Observations)

	// VAmPI: the OpenAPI document.
	vampi := appResult{Name: "vampi", URL: vampiURL}
	vtruth := specPaths(vampiURL + "openapi.json")
	g, _, m = runAzhaq(vampiURL, db("vampi"))
	vampi.Azhaq = scoreAzhaq(g, vampiURL, vtruth, shellHash(vampiURL), m)
	vampi.Katana = runKatana(vampiURL, vtruth, shellHash(vampiURL))
	res = append(res, vampi)
	addCheck("vampi: paths from /openapi.json", vampi.Azhaq.Truth == len(vtruth) && len(vtruth) > 0, "azhaq %d/%d, katana %d/%d", vampi.Azhaq.Truth, len(vtruth), vampi.Katana.Truth, len(vtruth))

	cross := diffSummary(db("juice"), db("vampi"))
	addCheck("diff across different seeds is labelled", cross.SeedsDiffer, "seeds_differ=%v", cross.SeedsDiffer)

	// ginandjuice.shop: page scripts, forms, URL templates.
	gin := appResult{Name: "ginandjuice.shop", URL: ginURL}
	gtruth := map[string]bool{"/logger": true, "/catalog/subscribe": true, "/catalog/product/stock": true}
	g, mapOut, m := runAzhaq(ginURL, db("gin"))
	gin.Azhaq = scoreAzhaq(g, ginURL, gtruth, shellHash(ginURL), m)
	formRoutes := map[string]bool{}
	for _, r := range g.rows {
		for _, f := range r.Forms {
			formRoutes[route(f.Action)] = true
		}
	}
	for r := range gtruth {
		if formRoutes[r] && !routes(g.urls(), strings.TrimSuffix(ginURL, "/"))[r] {
			gin.Azhaq.Truth++
		}
	}
	gin.Katana = runKatana(ginURL, gtruth, shellHash(ginURL))
	res = append(res, gin)
	scripts := 0
	for _, s := range []string{"stockCheck.js", "searchLogger.js", "subscribeNow.js", "xmlStockCheckPayload.js"} {
		for _, u := range g.urls() {
			if strings.HasSuffix(u, "/resources/js/"+s) {
				scripts++
				break
			}
		}
	}
	addCheck("ginandjuice: page scripts parsed", scripts == 4 && gin.Azhaq.Truth == len(gtruth),
		"%d/4 page scripts, %d/%d routes only in page scripts or script-driven forms", scripts, gin.Azhaq.Truth, len(gtruth))
	product := countLines(mapOut, `/catalog/product\?productId=`)
	blog := countLines(mapOut, `/blog/post\?postId=`)
	addCheck("ginandjuice: product and blog pages are one template each", product == 1 && blog == 1,
		"map lines: product %d, blog post %d", product, blog)
	return res
}

func runAzhaq(target, db string) (graph, []byte, runMeasure) {
	mapOut, m := run(target, 10*time.Minute, filepath.Dir(db), azhaq, "run", "-url", target, "-db", db)
	out, _ := exec.Command(azhaq, "export", "-db", db).Output()
	return readExport(out), mapOut, m
}

func scoreAzhaq(g graph, target string, truth map[string]bool, shell string, m runMeasure) toolScore {
	origin := strings.TrimSuffix(target, "/")
	found := routes(g.urls(), origin)
	s := toolScore{Routes: len(found), Truth: matched(found, truth), TruthOf: len(truth), Seconds: m.Seconds, RSSMB: m.RSSMB}
	facts := g.httpFacts()
	for _, r := range g.rows {
		if r.Entity.Type != "URL" || r.Coverage != "visited" || route(r.Entity.Key) == "/" {
			continue
		}
		p := facts[r.Entity.Key]
		st, _ := p["status"].(float64)
		if st >= 200 && st < 300 && p["body_hash"] == shell {
			s.Shell++
		}
	}
	return s
}

func runKatana(target string, truth map[string]bool, shell string) toolScore {
	out, m := run(target, 10*time.Minute, work, ref("katana"), "-u", target, "-d", "3", "-jc", "-silent", "-nc", "-timeout", "10", "-c", "10")
	urls := lines(out)
	found := routes(urls, strings.TrimSuffix(target, "/"))
	s := toolScore{Routes: len(found), Truth: matched(found, truth), TruthOf: len(truth), Seconds: m.Seconds, RSSMB: m.RSSMB}
	// katana lists what it saw; count how much of it is the catch-all page.
	n := 0
	for _, u := range urls {
		if n >= 300 || route(u) == "/" || asset(route(u)) {
			continue
		}
		n++
		if st, h := get(u); st >= 200 && st < 300 && h == shell {
			s.Shell++
		}
	}
	return s
}

// shellHash is the body hash azhaq-http would record for a path that does
// not exist on target (sha256, first 8 bytes, hex).
func shellHash(target string) string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	_, h := get(target + "bench-" + hex.EncodeToString(b[:]))
	return h
}

func get(u string) (int, string) {
	cli := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return 0, ""
	}
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	resp, err := cli.Do(req)
	if err != nil {
		return 0, ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	sum := sha256.Sum256(body)
	return resp.StatusCode, hex.EncodeToString(sum[:8])
}

// matched counts known routes a tool found. A templated route
// (/users/v1/{username}) counts when the tool found it as written, a
// concrete instance of it, or its static part (/users/v1): front-end code
// usually holds the prefix and appends the ID at run time.
func matched(found, truth map[string]bool) int {
	n := 0
	for t := range truth {
		if found[t] {
			n++
			continue
		}
		i := strings.Index(t, "{")
		if i < 0 {
			continue
		}
		re := templateRE(t)
		prefix := route(t[:i])
		for f := range found {
			if re.MatchString(f) || f == prefix {
				n++
				break
			}
		}
	}
	return n
}

// templateRE matches concrete paths of a template: {id} is one segment.
func templateRE(t string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString("^")
	for {
		i, j := strings.Index(t, "{"), strings.Index(t, "}")
		if i < 0 || j < i {
			b.WriteString(regexp.QuoteMeta(t))
			break
		}
		b.WriteString(regexp.QuoteMeta(t[:i]) + "[^/]+")
		t = t[j+1:]
	}
	b.WriteString("$")
	return regexp.MustCompile(b.String())
}

func readTruth(path string) map[string]bool {
	raw, err := os.ReadFile(path)
	must(err)
	out := map[string]bool{}
	for _, l := range lines(raw) {
		out[route(l)] = true
	}
	return out
}

// specPaths reads the paths an OpenAPI document declares, with its server
// prefix, straight from the app.
func specPaths(u string) map[string]bool {
	resp, err := http.Get(u)
	must(err)
	defer resp.Body.Close()
	var spec struct {
		Paths map[string]any `json:"paths"`
	}
	must(json.NewDecoder(resp.Body).Decode(&spec))
	out := map[string]bool{}
	for p := range spec.Paths {
		out[route(p)] = true
	}
	return out
}

type diffSum struct {
	Added        int  `json:"added"`
	Removed      int  `json:"removed"`
	Observations int  `json:"observations"`
	SeedsDiffer  bool `json:"seeds_differ"`
}

func diffSummary(a, b string) diffSum {
	out, _ := exec.Command(azhaq, "diff", "-a", a, "-b", b, "-jsonl").Output()
	var s diffSum
	for _, l := range lines(out) {
		var probe struct {
			Kind string `json:"kind"`
		}
		if json.Unmarshal([]byte(l), &probe) == nil && probe.Kind == "summary" {
			_ = json.Unmarshal([]byte(l), &s)
		}
	}
	return s
}

func countLines(out []byte, pattern string) int {
	re := regexp.MustCompile(pattern)
	n := 0
	for _, l := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "URL ") && re.MatchString(l) {
			n++
		}
	}
	return n
}

// compareFfuf runs ffuf with auto-calibration over Azhaq's default
// wordlist and compares its hits with azhaq-paths.
func compareFfuf(target string, g graph, shell string) *ffufRow {
	list := filepath.Join(work, "paths.txt")
	must(os.WriteFile(list, []byte(strings.Join(pathscol.DefaultWordlist, "\n")+"\n"), 0o644))
	result := filepath.Join(work, "ffuf.json")
	_, m := run(target, 5*time.Minute, work, ref("ffuf"), "-u", target+"FUZZ", "-w", list, "-ac", "-s",
		"-mc", "200,201,204,301,302,303,307,308,401,403", "-of", "json", "-o", result)
	row := &ffufRow{Words: len(pathscol.DefaultWordlist), Seconds: m.Seconds}
	var parsed struct {
		Results []struct {
			Input map[string]string `json:"input"`
		} `json:"results"`
	}
	if raw, err := os.ReadFile(result); err == nil {
		_ = json.Unmarshal(raw, &parsed)
	}
	ffuf := map[string]bool{}
	for _, r := range parsed.Results {
		ffuf["/"+strings.TrimPrefix(r.Input["FUZZ"], "/")] = true
	}
	az := map[string]bool{}
	for _, p := range g.payloads("azhaq-paths") {
		if path, _ := p["path"].(string); path != "" {
			az[path] = true
		}
	}
	row.AzhaqHits, row.FfufHits = len(az), len(ffuf)
	for p := range az {
		if ffuf[p] {
			row.Shared++
		}
		if st, h := get(strings.TrimSuffix(target, "/") + p); st >= 200 && st < 300 && h == shell {
			row.AzhaqShell++
		}
	}
	for p := range ffuf {
		if st, h := get(strings.TrimSuffix(target, "/") + p); st >= 200 && st < 300 && h == shell {
			row.FfufShell++
		}
	}
	return row
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
