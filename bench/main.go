// Command bench measures Azhaq against the tools it replaces.
//
//	go run ./bench                 # apps and domains
//	go run ./bench -domains=false  # local apps and ginandjuice.shop only
//	go run ./bench -crapi          # also OWASP crAPI
//
// Apps run in docker (bench/compose.yaml). Reference tools are downloaded
// to bench/.work/bin at pinned versions. Public domains get passive
// lookups, and the live names of the bug bounty domains one probe each
// (GET / and the favicon) from each tool. Results print as a table and are saved as JSON in
// bench/history.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"
)

type record struct {
	Date    string `json:"date"`
	Commit  string `json:"commit"`
	Version string `json:"version,omitempty"` // azhaq version of the binary measured
	Go      string `json:"go"`
	Tools   []tool `json:"tools"`
	Profile string `json:"profile,omitempty"` // default, polite or both
	// The default profile's comparison rows are the top level, as before.
	profileSet
	Polite  *profileSet  `json:"polite,omitempty"`
	Dropin  *dropinRow   `json:"dropin,omitempty"`
	Scope   *scopeRow    `json:"scope,omitempty"`
	Network *networkRow  `json:"network,omitempty"`
	Secrets *secretsRow  `json:"secrets,omitempty"`
	Tenants *tenantsRow  `json:"tenants,omitempty"`
	Scale   *scaleRow    `json:"scale,omitempty"`
	Claims  *claimsRow   `json:"claims,omitempty"`
	Regress *regressRow  `json:"regress,omitempty"`
	Lab     *labRow      `json:"lab,omitempty"`
	Docs    *docsRow     `json:"docs,omitempty"`
	OpenAPI *openAPIRow  `json:"openapi,omitempty"`
	Checks  []check      `json:"checks"`
	Runs    []runMeasure `json:"runs"`
}

// check is one pass/fail condition the run must meet.
type check struct {
	Name   string `json:"name"`
	Pass   bool   `json:"pass"`
	Detail string `json:"detail"`
}

// runMeasure is the cost of one tool invocation.
type runMeasure struct {
	Tool    string  `json:"tool"`
	Target  string  `json:"target"`
	Seconds float64 `json:"seconds"`
	RSSMB   float64 `json:"rss_mb"`
	Error   string  `json:"error,omitempty"`
	Cached  bool    `json:"cached,omitempty"`  // replayed from today's run (refcache.go)
	Profile string  `json:"profile,omitempty"` // default or polite, for a comparison
}

// sections are what -only picks from; dockerParts need the docker apps.
var (
	sections    = []string{"apps", "dropin", "dirs", "fuzz", "scope", "secrets", "tenants", "scale", "claims", "regress", "shots", "params", "domains", "urls", "brute", "dns", "lab", "ports", "services", "network", "probe", "notify", "openapi", "docs"}
	dockerParts = []string{"dropin", "dirs", "fuzz", "scope", "scale", "shots", "params"}
	// perProfile sections compare azhaq with a reference tool and run once
	// for each profile; the others run once.
	perProfile = map[string]bool{"apps": true, "dirs": true, "fuzz": true, "shots": true, "params": true, "domains": true, "urls": true,
		"brute": true, "dns": true, "ports": true, "services": true, "probe": true, "notify": true}
)

var (
	fresh   bool
	work    string
	binDir  string
	azhaq   string
	rec     record
	verbose bool
)

func main() {
	apps := flag.Bool("apps", true, "run the app benchmark (docker apps and ginandjuice.shop)")
	domains := flag.Bool("domains", true, "run the passive domain benchmark")
	brute := flag.Bool("brute", true, "run the DNS brute-force, wildcard and permutation benchmark (the DNS lab)")
	ports := flag.Bool("ports", true, "compare the port scan with naabu on scanme.nmap.org and this machine")
	probe := flag.Bool("probe", true, "compare probing with httpx: the local apps, a fleet of local servers and three low-rate public test sites")
	network := flag.Bool("network", true, "compare ASN prefixes with RADb and reverse DNS with dnsx -ptr (needs the domain benchmark's DNS)")
	crapi := flag.Bool("crapi", false, "also run OWASP crAPI (seven containers, about 2 GB of images)")
	flag.Bool("keep", true, "leave the docker apps running (the default: shared containers are never stopped)")
	down := flag.Bool("down", false, "stop the bench's own docker apps (azhaq-bench) afterwards")
	only := flag.String("only", "", "run only these sections, comma-separated: "+strings.Join(sections, ", ")+"; the default runs them all")
	profile := flag.String("profile", "both", "default, polite or both: every comparison runs with the default flags of both tools and at a polite rate (HTTP "+politeHTTP+"/s, DNS "+politeDNS+"/s, ports "+politePort+"/s)")
	flag.IntVar(&politeWords, "polite-words", 250, "words a polite path or fuzz sweep sends (at 5 requests per second the whole list takes 16 minutes a tool and app)")
	pd := flag.String("polite-domains", "hackerone.com,vulnweb.com", "domains the polite profile looks up (at 10 DNS queries per second each takes minutes; the default profile runs bench/domains.txt)")
	flag.StringVar(&refBin, "refbin", os.Getenv("AZHAQ_REFBIN"), "a folder of reference tool binaries to use before bench/.work/bin (env AZHAQ_REFBIN)")
	flag.StringVar(&nmapAt, "nmap", os.Getenv("AZHAQ_NMAP"), "nmap, or a script that runs an unpacked one (env AZHAQ_NMAP; else nmap in PATH)")
	readme := flag.Bool("readme", false, "rewrite the benchmark table in README.md from the newest record in -out, and exit")
	toolsOnly := flag.Bool("tools-only", false, "install the reference tools (and arjun) into -work/bin and exit: for a machine that runs them by hand")
	flag.BoolVar(&fresh, "fresh", false, "run the reference tools again instead of reusing today's cached results")
	out := flag.String("out", "bench/history", "directory for the JSON record")
	flag.StringVar(&work, "work", "bench/.work", "scratch directory")
	flag.BoolVar(&verbose, "v", false, "print each command")
	flag.Parse()
	if _, err := os.Stat("go.mod"); err != nil {
		fatal("run from the repository root: go run ./bench")
	}
	if *readme {
		must(writeReadme(*out))
		return
	}
	politeDomains = strings.Split(*pd, ",")
	var profiles []string
	switch *profile {
	case "both":
		profiles = []string{profDefault, profPolite}
	case profDefault, profPolite:
		profiles = []string{*profile}
	default:
		fatal("-profile: default, polite or both, not %q", *profile)
	}
	sel := map[string]bool{}
	for _, s := range strings.Split(*only, ",") {
		if s = strings.TrimSpace(s); s == "" {
			continue
		}
		if !slices.Contains(sections, s) {
			fatal("-only: no section %q (sections: %s)", s, strings.Join(sections, ", "))
		}
		sel[s] = true
	}
	if sel["probe"] && !sel["domains"] {
		logf("-only probe without domains: the hosts are the local apps, the fleet and the three test sites")
	}
	// on: the section runs; without -only, as its own flag says.
	on := func(name string, def bool) bool {
		if len(sel) == 0 {
			return def
		}
		return sel[name]
	}

	work, _ = filepath.Abs(work)
	if refBin != "" {
		refBin, _ = filepath.Abs(refBin)
	}
	binDir = filepath.Join(work, "bin")
	azhaq = filepath.Join(binDir, "azhaq")
	rec = record{
		Date:    time.Now().UTC().Format(time.RFC3339),
		Commit:  commit(),
		Go:      runtime.Version(),
		Tools:   append(append([]tool(nil), tools...), builtTools...),
		Profile: *profile,
	}

	must(os.MkdirAll(binDir, 0o755))
	// A fresh name history per bench run: one-shot, as the reference tools are.
	must(os.Setenv("AZHAQ_DATA_DIR", filepath.Join(work, "data-"+time.Now().UTC().Format("20060102T150405"))))
	logf("building azhaq")
	if _, err := exec.Command("go", "build", "-o", azhaq, "./cmd/azhaq").CombinedOutput(); err != nil {
		fatal("go build: %v", err)
	}
	if v, err := exec.Command(azhaq, "version").Output(); err == nil {
		rec.Version = strings.TrimSpace(string(v))
	}
	if !(len(sel) == 1 && sel["regress"]) { // regress uses what $AZHAQ_REFBIN holds
		must(installTools(binDir))
		must(installBuilt(binDir))
	}
	if *toolsOnly {
		a, err := installArjun()
		must(err)
		link := filepath.Join(binDir, "arjun")
		_ = os.Remove(link)
		must(os.Symlink(a, link))
		fmt.Println(binDir)
		return
	}

	// The flags that gate a section when no -only names one.
	gate := map[string]bool{"apps": *apps, "dropin": *apps, "dirs": *apps, "fuzz": *apps, "scope": *apps, "secrets": *apps, "tenants": *apps,
		"scale": *apps, "claims": *apps, "shots": *apps, "params": *apps, "domains": *domains, "urls": *domains, "brute": *brute,
		"dns": true, "lab": true, "ports": *ports, "services": *ports, "network": *domains && *network, "probe": *probe,
		"notify": true, "openapi": *apps, "docs": true}
	docker := false
	for _, s := range append([]string{"apps"}, dockerParts...) {
		docker = docker || on(s, gate[s])
	}
	if docker {
		must(startApps())
		if *down {
			defer stopApps()
		}
	}
	if *crapi {
		must(startCrapi())
		if *down {
			defer stopCrapi()
		}
	}
	local := []string{juiceURL, vampiURL}
	if *crapi {
		local = append(local, crapiURL)
	}
	probeLocal := []string{"127.0.0.1:3101", "127.0.0.1:5102"}
	if *crapi {
		probeLocal = append(probeLocal, "127.0.0.1:8888")
	}

	// Comparison sections: each profile in turn.
	cmp := []struct {
		name string
		fn   func()
	}{
		{"apps", func() {
			cur.Apps = benchApps()
			if *crapi && !polite() {
				cur.Apps = append(cur.Apps, benchCrapi())
			}
			if len(cur.Apps) > 0 && !polite() {
				appChecks(cur.Apps)
			}
		}},
		{"dirs", func() { cur.Dirs = benchDirs(local) }},
		{"fuzz", func() { cur.Fuzz = benchFuzz([]string{juiceURL, vampiURL}) }},
		{"shots", func() { cur.Shots = benchShots() }},
		{"params", func() { cur.Params = benchParams() }},
		{"domains", func() { cur.Domains = benchDomains() }},
		{"urls", func() { cur.URLs = benchURLs() }},
		{"brute", func() { cur.Brute = benchBrute() }},
		{"dns", func() { cur.DNS = benchDNS() }},
		{"ports", func() { cur.Ports = benchPorts() }},
		{"services", func() { cur.Services = benchServices() }},
		{"probe", func() { cur.Probe = benchProbe(probeLocal) }},
		{"notify", func() { cur.Notify = benchNotify() }},
	}
	for _, p := range profiles {
		prof = p
		if p == profDefault {
			cur = &rec.profileSet
		} else {
			rec.Polite = &profileSet{}
			cur = rec.Polite
		}
		for _, c := range cmp {
			if on(c.name, gate[c.name]) {
				if docker {
					ensureApps()
				}
				s0 := time.Now()
				logf("%s: %s", p, c.name)
				c.fn()
				logf("%s: %s took %.0fs", p, c.name, time.Since(s0).Seconds())
			}
		}
	}
	prof, cur = "", nil

	// The rest run once.
	if docker {
		ensureApps()
	}
	if on("dropin", gate["dropin"]) {
		rec.Dropin = benchDropin(*crapi)
	}
	if on("scope", gate["scope"]) {
		rec.Scope = benchScope(juiceURL)
	}
	if on("secrets", gate["secrets"]) {
		rec.Secrets = benchSecrets()
	}
	if on("tenants", gate["tenants"]) {
		rec.Tenants = benchTenants()
	}
	if on("scale", gate["scale"]) {
		rec.Scale = benchScale(juiceURL)
	}
	if on("claims", gate["claims"]) {
		rec.Claims = benchClaims()
	}
	if on("regress", false) {
		rec.Regress = benchRegress()
	}
	if on("network", gate["network"]) {
		rec.Network = benchNetwork()
	}
	if on("lab", gate["lab"]) {
		rec.Lab = benchLab()
	}
	if on("openapi", gate["openapi"]) {
		rec.OpenAPI = benchOpenAPI()
	}
	if on("docs", gate["docs"]) {
		rec.Docs = benchDocs()
	}

	stopLab()
	printReport()
	must(os.MkdirAll(*out, 0o755))
	name := filepath.Join(*out, time.Now().UTC().Format("2006-01-02T150405")+"-"+rec.Commit+".json")
	raw, _ := json.MarshalIndent(rec, "", "  ")
	must(os.WriteFile(name, append(raw, '\n'), 0o644))
	fmt.Printf("\nrecord %s\n", name)
	for _, c := range rec.Checks {
		if !c.Pass {
			os.Exit(1)
		}
	}
}

func commit() string {
	out, err := exec.Command("git", "rev-parse", "--short", "HEAD").Output()
	if err != nil {
		return "unknown"
	}
	c := strings.TrimSpace(string(out))
	if st, _ := exec.Command("git", "status", "--porcelain", "--untracked-files=no").Output(); len(bytes.TrimSpace(st)) > 0 {
		c += "-dirty"
	}
	return c
}

// run executes a command with stdin closed (katana waits on a non-terminal
// stdin otherwise), records its wall time and peak memory, and returns
// stdout.
func run(target string, timeout time.Duration, dir string, name string, args ...string) ([]byte, runMeasure) {
	var key string
	var before map[string]bool
	if refCacheable(name) {
		key = refKey(target, dir, name, args)
		if out, m, ok := replayRef(key); ok {
			if verbose {
				logf("$ %s %s (today's run, replayed)", filepath.Base(name), strings.Join(args, " "))
			}
			m.Target, m.Profile = target, prof
			rec.Runs = append(rec.Runs, m)
			return out, m
		}
		before = existing(dir, args)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Stdin = nil
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if verbose {
		logf("$ %s %s", filepath.Base(name), strings.Join(args, " "))
	}
	t0 := time.Now()
	m := runMeasure{Tool: filepath.Base(name), Target: target, Profile: prof}
	err := cmd.Start()
	if err != nil && name != azhaq {
		markGone(filepath.Base(name), err.Error()) // a reference that cannot start has no time to compare
	}
	if err == nil {
		done := make(chan struct{})
		peak := make(chan int64)
		go func() { peak <- watchHWM(cmd.Process.Pid, done) }()
		err = cmd.Wait()
		close(done)
		m.RSSMB = float64(<-peak) / 1024
	}
	m.Seconds = time.Since(t0).Seconds()
	if err != nil {
		m.Error = strings.ReplaceAll(strings.TrimSpace(err.Error()+" "+lastLine(stderr.String())), work, "bench/.work")
	}
	rec.Runs = append(rec.Runs, m)
	if key != "" {
		keepRef(key, dir, args, before, stdout.Bytes(), m)
	}
	return stdout.Bytes(), m
}

// watchHWM samples the peak resident size (VmHWM, KB) of a running process.
// rusage is no use here: a child started with vfork inherits the parent's
// high-water mark at exec.
func watchHWM(pid int, done <-chan struct{}) int64 {
	var peak int64
	path := fmt.Sprintf("/proc/%d/status", pid)
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		if raw, err := os.ReadFile(path); err == nil {
			for _, l := range strings.Split(string(raw), "\n") {
				if strings.HasPrefix(l, "VmHWM:") {
					var kb int64
					fmt.Sscanf(strings.TrimSpace(strings.TrimPrefix(l, "VmHWM:")), "%d", &kb)
					peak = max(peak, kb)
				}
			}
		}
		select {
		case <-done:
			return peak
		case <-tick.C:
		}
	}
}

// ref is the path of a reference tool: -refbin's, else the pinned one in bench/.work/bin.
func ref(name string) string {
	if refBin != "" {
		if p := filepath.Join(refBin, name); fileExists(p) {
			return p
		}
	}
	return filepath.Join(binDir, name)
}

// addCheck records a pass/fail condition; a comparison's name carries its
// profile, so the same check in both profiles reads as two.
func addCheck(name string, pass bool, format string, a ...any) {
	if prof != "" {
		name = "[" + prof + "] " + name
	}
	rec.Checks = append(rec.Checks, check{Name: name, Pass: pass, Detail: fmt.Sprintf(format, a...)})
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return lines[len(lines)-1]
}

func logf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "bench: "+format+"\n", a...)
}

func fatal(format string, a ...any) {
	logf(format, a...)
	os.Exit(2)
}

func must(err error) {
	if err != nil {
		fatal("%v", err)
	}
}
