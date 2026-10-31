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
	"sync"
	"time"

	"github.com/trannghiach/azhaq/internal/collectors/pathscol"
)

const (
	juiceURL = "http://127.0.0.1:3101/"
	vampiURL = "http://127.0.0.1:5102/"
	ginURL   = "https://ginandjuice.shop/"
)

type appResult struct {
	Name    string    `json:"name"`
	URL     string    `json:"url"`
	Azhaq   toolScore `json:"azhaq"`
	Katana  toolScore `json:"katana"`
	Jsluice toolScore `json:"jsluice"`
	Union   toolScore `json:"katana_jsluice"` // routes either found
	Grep    toolScore `json:"bundle_grep"`    // quoted paths in the scripts katana fetched
	Profile string    `json:"profile,omitempty"`
	// The drop-in crawler against katana, same depth and pace.
	Crawl       *toolScore  `json:"crawl,omitempty"`
	CrawlKatana *toolScore  `json:"crawl_katana,omitempty"`
	Ffuf        *ffufRow    `json:"ffuf,omitempty"`
	Roles       *rolesRow   `json:"roles,omitempty"`
	Browser     *browserRow `json:"browser,omitempty"`
}

// browserRow is the crawl that runs the app's scripts: azhaq -browser
// against katana -headless with the machine's Chrome.
type browserRow struct {
	Azhaq         toolScore `json:"azhaq"`
	Katana        toolScore `json:"katana"`
	KatanaStopped bool      `json:"katana_stopped,omitempty"` // still crawling at the time limit; scored on what it printed
	Limit         float64   `json:"limit_seconds"`
}

// headlessLimit bounds katana -headless, which can crawl a single-page app
// for a long time; what it printed by then is scored.
const headlessLimit = 5 * time.Minute

func compareBrowsers(target, db string, truth map[string]bool, shell string) *browserRow {
	row := &browserRow{Limit: headlessLimit.Seconds()}
	_, m := run(target, 10*time.Minute, filepath.Dir(db), azhaq, "run", "-url", target, "-db", db, "-browser", "-quiet")
	out, _ := exec.Command(azhaq, "export", "-db", db).Output()
	row.Azhaq = scoreAzhaq(readExport(out), target, truth, shell, m)
	var km runMeasure
	// -no-sandbox: Ubuntu's AppArmor refuses Chrome's sandbox to programs
	// without a profile, and chromedp starts Chrome without it too.
	row.Katana, _, km = runKatanaWith(target, truth, shell, headlessLimit, "-hl", "-system-chrome", "-nos")
	row.KatanaStopped = km.Seconds >= headlessLimit.Seconds()-1
	return row
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
	// An app that does not come up fails a check; the sections still run
	// (ensureApps tries again before each) instead of losing the whole run.
	for _, u := range []string{juiceURL, vampiURL} {
		if err := waitUp(u, 3*time.Minute); err != nil {
			addCheck("apps: the docker apps are up", false, "%v", err)
			logf("%v", err)
		}
	}
	return nil
}

// stopApps takes down the bench's own two containers (-down only): other
// streams use the shared azq-* ones, which the bench never stops.
func stopApps() {
	_ = exec.Command("docker", "compose", "-f", "bench/compose.yaml", "down").Run()
}

// appUp: the app answers GET / with 200.
func appUp(u string) bool {
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Get(u)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// ensureApps starts the bench's own two containers when one does not answer
// (Juice Shop runs out of memory after about a hundred thousand requests). It
// only ever starts: no container is stopped or restarted.
func ensureApps() {
	for _, u := range []string{juiceURL, vampiURL} {
		if !appUp(u) {
			logf("%s does not answer: docker compose up -d", u)
			_ = exec.Command("docker", "compose", "-f", "bench/compose.yaml", "up", "-d").Run()
			if err := waitUp(u, 3*time.Minute); err != nil {
				logf("%v", err)
			}
		}
	}
}

// legWithApp runs a leg that must not see its app go away: if the app is
// down afterwards it is started again and the leg runs once more.
// appRestarts counts the legs that had to run again because the app went down.
var appRestarts int

func legWithApp(app string, leg func()) {
	for i := 0; i < 2; i++ {
		if strings.Contains(app, "127.0.0.1:3101") || strings.Contains(app, "127.0.0.1:5102") {
			ensureApps()
		}
		leg()
		if appUp(app) {
			return
		}
		appRestarts++
		logf("%s went down during a leg: started again, and the leg runs once more", app)
	}
}

// freshApp restarts the bench's Juice Shop before a long sweep: it keeps
// memory for every path it is asked (176 MB to 2.7 GB in one 4,750-word
// ffuf sweep) and dies during the next, so each tool gets one just started.
func freshApp(app string) {
	if !strings.Contains(app, "127.0.0.1:3101") {
		return
	}
	_ = exec.Command("docker", "compose", "-f", "bench/compose.yaml", "restart", "juice-shop").Run()
	if err := waitUp(app, 3*time.Minute); err != nil {
		logf("%v", err)
	}
}

// waitEvery is how often waitUp asks (a variable for the tests).
var waitEvery = 2 * time.Second

func waitUp(u string, max time.Duration) error {
	deadline := time.Now().Add(max)
	cli := &http.Client{Timeout: 10 * time.Second} // a hung app must not hold the wait
	for time.Now().Before(deadline) {
		resp, err := cli.Get(u)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(waitEvery)
	}
	return fmt.Errorf("%s not up after %s", u, max)
}

// labApp is one training app of the shared labs, as .github/ci/labs.sh
// starts it. The bench's own containers (compose.yaml) are not these.
type labApp struct {
	name  string // container
	url   string // without the trailing slash
	flags []string
	image string
}

// labApps mirrors labs.sh; TestLabAppsMatchLabsScript keeps them equal.
var labApps = []labApp{
	{"azq-juice", "http://127.0.0.1:3001", []string{"-p", "127.0.0.1:3001:3000", "-e", "NODE_OPTIONS=--max-old-space-size=4096"}, "bkimminich/juice-shop"},
	{"azq-vampi", "http://127.0.0.1:5002", []string{"-p", "127.0.0.1:5002:5000", "-e", "vulnerable=1", "-e", "tokentimetolive=3600"}, "erev0s/vampi"},
	{"azq-dvga", "http://127.0.0.1:5013", []string{"-p", "127.0.0.1:5013:5013", "-e", "WEB_HOST=0.0.0.0"}, "dolevf/dvga:latest"},
	{"azq-dvna", "http://127.0.0.1:5020", []string{"-p", "127.0.0.1:5020:9090"}, "appsecco/dvna:sqlite"},
	{"azq-dvwa", "http://127.0.0.1:5030", []string{"-p", "127.0.0.1:5030:80"}, "vulnerables/web-dvwa"},
}

// labStartWait covers Juice Shop's cold start (a minute or two).
const labStartWait = 3 * time.Minute

// docker runs the docker CLI (a variable for the tests).
var docker = func(args ...string) (string, error) {
	out, err := exec.Command("docker", args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// ensureLabApp brings a lab app up when it does not answer: it starts the
// container, creates it as labs.sh does when there is none, and when a
// running one stays silent restarts it once. Nothing is done to an app that
// answers, so the shared containers other work uses are left alone.
func ensureLabApp(a labApp, wait time.Duration) error {
	if appUp(a.url + "/") {
		return nil
	}
	logf("%s does not answer", a.url)
	running, err := docker("inspect", "-f", "{{.State.Running}}", a.name)
	switch {
	case err != nil: // no such container
		if out, err := docker(append(append([]string{"run", "-d", "--name", a.name}, a.flags...), a.image)...); err != nil {
			return fmt.Errorf("%s is not up: docker run %s: %v %s", a.url, a.name, err, out)
		}
	case running != "true":
		if out, err := docker("start", a.name); err != nil {
			return fmt.Errorf("%s is not up: docker start %s: %v %s", a.url, a.name, err, out)
		}
	}
	if waitUp(a.url+"/", wait) == nil {
		return nil
	}
	logf("%s is running but silent: docker restart %s", a.url, a.name)
	if out, err := docker("restart", a.name); err != nil {
		return fmt.Errorf("%s is not up: docker restart %s: %v %s", a.url, a.name, err, out)
	}
	return waitUp(a.url+"/", wait)
}

// labSet is the lab apps a section uses, each brought up when it is used;
// one that cannot be brought up is remembered, so a case that needs it fails
// at once and the section goes on.
type labSet struct {
	apps []labApp
	wait time.Duration
	mu   sync.Mutex
	dead map[string]error
}

func newLabSet() *labSet {
	return &labSet{apps: labApps, wait: labStartWait, dead: map[string]error{}}
}

// up is nil when the app at base (an origin without a trailing slash) answers.
func (s *labSet) up(base string) error {
	s.mu.Lock()
	err, dead := s.dead[base]
	s.mu.Unlock()
	if dead {
		return err
	}
	for _, a := range s.apps {
		if a.url == base {
			if err := ensureLabApp(a, s.wait); err != nil {
				s.mu.Lock()
				s.dead[base] = err
				s.mu.Unlock()
				return err
			}
			return nil
		}
	}
	return fmt.Errorf("%s is not a lab app", base)
}

// start brings the apps up together: their cold starts overlap.
func (s *labSet) start(bases ...string) {
	var wg sync.WaitGroup
	for _, b := range bases {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.up(b); err != nil {
				logf("%v", err)
			}
		}()
	}
	wg.Wait()
}

func benchApps() []appResult {
	dir, _ := filepath.Abs(filepath.Join(work, "apps"))
	must(os.MkdirAll(dir, 0o755))
	if polite() {
		return benchAppsPolite()
	}
	stamp := time.Now().Format("150405")
	db := func(name string) string { return filepath.Join(dir, name+"-"+stamp+".db") }

	var res []appResult

	// Juice Shop: JS routes, SPA catch-all pages, diff stability.
	juice := appResult{Name: "juice-shop", URL: juiceURL}
	truth := readTruth("bench/truth/juice-shop-v20.3.0-routes.txt")
	g, _, m := runAzhaq(juiceURL, db("juice"))
	shell := shellHash(juiceURL)
	juice.Azhaq = scoreAzhaq(g, juiceURL, truth, shell, m)
	runKatanaJsluice(&juice, truth, shell)
	juice.Ffuf = compareFfuf(juiceURL, g, shell)
	addCheck("juice-shop: ≥ 90% of the server routes its frontend calls", juice.Azhaq.Truth*10 >= len(truth)*9, "azhaq %d/%d, katana %d/%d, jsluice %d/%d",
		juice.Azhaq.Truth, len(truth), juice.Katana.Truth, len(truth), juice.Jsluice.Truth, len(truth))
	addCheck("juice-shop: no catch-all page reported as visited", juice.Azhaq.Shell == 0, "%d visited URLs return the SPA index", juice.Azhaq.Shell)
	crawlCompare(&juice, truth, shell)
	juice.Roles = benchRoles(juiceURL, dir)
	juice.Browser = compareBrowsers(juiceURL, db("juice-browser"), truth, shell)
	addCheck("juice-shop: -browser finds the known routes katana -headless finds", juice.Browser.Azhaq.Truth >= juice.Browser.Katana.Truth,
		"azhaq -browser %d/%d in %.0fs, katana -headless %d/%d in %.0fs", juice.Browser.Azhaq.Truth, len(truth), juice.Browser.Azhaq.Seconds,
		juice.Browser.Katana.Truth, len(truth), juice.Browser.Katana.Seconds)
	res = append(res, juice)

	_, _, _ = runAzhaq(juiceURL, db("juice-again"))
	sum := diffSummary(db("juice"), db("juice-again"))
	addCheck("identical runs diff empty", sum.Added == 0 && sum.Removed == 0 && sum.Observations == 0,
		"added=%d removed=%d observations=%d", sum.Added, sum.Removed, sum.Observations)

	// VAmPI: the OpenAPI document.
	vampi := appResult{Name: "vampi", URL: vampiURL}
	vtruth := specPaths(vampiURL + "openapi.json")
	g, _, m = runAzhaq(vampiURL, db("vampi"))
	vampi.Azhaq = scoreAzhaq(g, vampiURL, vtruth, shellHash(vampiURL), m)
	runKatanaJsluice(&vampi, vtruth, shellHash(vampiURL))
	crawlCompare(&vampi, vtruth, shellHash(vampiURL))
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
	runKatanaJsluice(&gin, gtruth, shellHash(ginURL))
	crawlCompare(&gin, gtruth, shellHash(ginURL))
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

// slowTarget: a public site is only ever asked at 5 requests per second,
// and every target is in the polite profile.
func slowTarget(target string) bool { return polite() || strings.HasPrefix(target, "https://") }

func azPace(target string) []string {
	if slowTarget(target) {
		return []string{"-rate", politeHTTP}
	}
	return nil
}

func katanaPace(target string) []string {
	if slowTarget(target) {
		return []string{"-rl", politeHTTP}
	}
	return nil
}

func runAzhaq(target, db string) (graph, []byte, runMeasure) {
	mapOut, m := run(target, 30*time.Minute, filepath.Dir(db), azhaq, append([]string{"run", "-url", target, "-db", db}, azPace(target)...)...)
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

// runKatanaJsluice runs katana with its jsluice parser (-jsl), then jsluice
// itself on the scripts katana found (the usual pipeline), and scores each,
// their union, and a grep of those scripts for quoted paths: what a reader
// gets from the bundles by hand.
func runKatanaJsluice(a *appResult, truth map[string]bool, shell string) {
	k, urls := runKatana(a.URL, truth, shell)
	j, jurls, g := runJsluice(a.URL, urls, truth)
	origin := strings.TrimSuffix(a.URL, "/")
	found := routes(append(append([]string(nil), urls...), jurls...), origin)
	a.Katana, a.Jsluice, a.Grep = k, j, g
	a.Union = toolScore{Routes: len(found), Truth: matched(found, truth), TruthOf: len(truth), Shell: k.Shell + j.Shell,
		Seconds: k.Seconds + j.Seconds, RSSMB: max(k.RSSMB, j.RSSMB)}
}

// quotedPath is a string literal that starts with a path: "/rest/user/login".
var quotedPath = regexp.MustCompile("[\"'`](/[A-Za-z][A-Za-z0-9_.~/-]*)")

// runJsluice downloads the same-origin scripts in urls and lists the URLs
// jsluice finds in them, resolved against the app's root.
func runJsluice(target string, urls []string, truth map[string]bool) (toolScore, []string, toolScore) {
	dir, err := os.MkdirTemp(work, "jsluice-")
	must(err)
	defer os.RemoveAll(dir)
	origin := strings.TrimSuffix(target, "/")
	var files []string
	var grepped []string
	seen := map[string]bool{}
	for _, u := range urls {
		p := strings.SplitN(u, "?", 2)[0]
		if !strings.HasPrefix(u, origin+"/") || !strings.HasSuffix(p, ".js") || seen[p] || len(files) >= 64 {
			continue
		}
		seen[p] = true
		if body, ok := download(u); ok {
			f := filepath.Join(dir, fmt.Sprintf("%03d.js", len(files)))
			must(os.WriteFile(f, body, 0o644))
			files = append(files, f)
			for _, m := range quotedPath.FindAllSubmatch(body, -1) {
				grepped = append(grepped, origin+string(m[1]))
			}
		}
	}
	gr := routes(grepped, origin)
	g := toolScore{Routes: len(gr), Truth: matched(gr, truth), TruthOf: len(truth)}
	if len(files) == 0 {
		return toolScore{TruthOf: len(truth)}, nil, g
	}
	out, m := run(target, 10*time.Minute, dir, ref("jsluice"), append([]string{"urls", "-R", origin + "/"}, files...)...)
	var found []string
	for _, l := range lines(out) {
		var x struct {
			URL string `json:"url"`
		}
		if json.Unmarshal([]byte(l), &x) == nil && x.URL != "" {
			found = append(found, x.URL)
		}
	}
	r := routes(found, origin)
	return toolScore{Routes: len(r), Truth: matched(r, truth), TruthOf: len(truth), Seconds: m.Seconds, RSSMB: m.RSSMB}, found, g
}

func download(u string) ([]byte, bool) {
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Get(u)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	return body, err == nil && resp.StatusCode == http.StatusOK
}

func runKatana(target string, truth map[string]bool, shell string) (toolScore, []string) {
	s, urls, _ := runKatanaWith(target, truth, shell, 10*time.Minute, "-jsl")
	return s, urls
}

func runKatanaWith(target string, truth map[string]bool, shell string, limit time.Duration, extra ...string) (toolScore, []string, runMeasure) {
	args := append([]string{"-u", target, "-d", "3", "-jc", "-silent", "-nc", "-timeout", "10", "-c", "10"}, extra...)
	args = append(args, katanaPace(target)...)
	out, m := run(target, limit, work, ref("katana"), args...)
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
	return s, urls, m
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
		if !strings.Contains(t, "{") {
			continue
		}
		// A concrete instance of the route, or the same template whatever
		// its parameters are called; not the bare prefix (/rest/basket
		// is not /rest/basket/{id}/checkout).
		re := templateRE(t)
		for f := range found {
			if re.MatchString(f) || canonical(f) == canonical(t) {
				n++
				break
			}
		}
	}
	return n
}

var paramRE = regexp.MustCompile(`\{[^}]*\}`)

// canonical is a template with its parameters unnamed.
func canonical(t string) string { return paramRE.ReplaceAllString(t, "{}") }

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

// appChecks holds every app to the union of katana and jsluice: at least
// as many known routes, and no catch-all page reported as visited.
func appChecks(apps []appResult) {
	ok, clean := true, true
	var parts []string
	for _, a := range apps {
		if a.Azhaq.Truth < a.Union.Truth {
			ok = false
		}
		if a.Azhaq.Shell > 0 {
			clean = false
		}
		parts = append(parts, fmt.Sprintf("%s %d/%d vs %d", a.Name, a.Azhaq.Truth, a.Azhaq.TruthOf, a.Union.Truth))
	}
	addCheck("known routes ≥ katana ∪ jsluice on every app", ok, "%s", strings.Join(parts, ", "))
	addCheck("no catch-all page reported as visited on any app", clean, "%d apps", len(apps))
}

// benchAppsPolite is the crawl comparison at 5 requests per second: azhaq
// crawl against katana -jc -jsl -rl 5 on Juice Shop, VAmPI and ginandjuice.shop.
func benchAppsPolite() []appResult {
	var res []appResult
	juice := appResult{Name: "juice-shop", URL: juiceURL, Profile: prof}
	truth := readTruth("bench/truth/juice-shop-v20.3.0-routes.txt")
	crawlCompare(&juice, truth, shellHash(juiceURL))
	res = append(res, juice)
	vampi := appResult{Name: "vampi", URL: vampiURL, Profile: prof}
	vtruth := specPaths(vampiURL + "openapi.json")
	crawlCompare(&vampi, vtruth, shellHash(vampiURL))
	res = append(res, vampi)
	gin := appResult{Name: "ginandjuice.shop", URL: ginURL, Profile: prof}
	gtruth := map[string]bool{"/logger": true, "/catalog/subscribe": true, "/catalog/product/stock": true}
	crawlCompare(&gin, gtruth, shellHash(ginURL))
	res = append(res, gin)
	return res
}

// crawlCompare runs azhaq crawl and katana to the same depth and pace and
// scores the routes each found against the app's own list of routes.
func crawlCompare(a *appResult, truth map[string]bool, shell string) {
	origin := strings.TrimSuffix(a.URL, "/")
	aa := append([]string{"crawl", "-u", a.URL, "-depth", "3", "-silent"}, azPace(a.URL)...)
	run1 := timed
	if strings.HasPrefix(a.URL, "https://") {
		run1 = run // a public site: one run
	}
	out, m := run1(a.URL, 30*time.Minute, work, azhaq, aa...)
	var urls []string
	for _, l := range lines(out) {
		urls = append(urls, firstField(l))
	}
	found := routes(urls, origin)
	az := toolScore{Routes: len(found), Truth: matched(found, truth), TruthOf: len(truth), Seconds: m.Seconds, RSSMB: m.RSSMB}
	ka := append([]string{"-u", a.URL, "-d", "3", "-jc", "-jsl", "-silent", "-nc", "-timeout", "10", "-c", "10"}, katanaPace(a.URL)...)
	kout, km := run1(a.URL, 30*time.Minute, work, ref("katana"), ka...)
	kfound := routes(lines(kout), origin)
	kt := toolScore{Routes: len(kfound), Truth: matched(kfound, truth), TruthOf: len(truth), Seconds: km.Seconds, RSSMB: km.RSSMB}
	a.Crawl, a.CrawlKatana = &az, &kt
	barOne("crawl "+a.Name, az.Truth, kt.Truth, az.Seconds, kt.Seconds, "the app's own routes (its server code or OpenAPI document, or the routes only its page scripts hold)",
		cmdLine(azhaq, aa...)+" vs "+cmdLine("katana", ka...),
		fmt.Sprintf("routes found azhaq %d, katana %d; known %d and %d of %d; %s%s", az.Routes, kt.Routes, az.Truth, kt.Truth, len(truth), ratio(az.Seconds, kt.Seconds), azErr(m)))
}
