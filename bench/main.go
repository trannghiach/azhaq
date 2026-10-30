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
	Date    string       `json:"date"`
	Commit  string       `json:"commit"`
	Go      string       `json:"go"`
	Tools   []tool       `json:"tools"`
	Apps    []appResult  `json:"apps,omitempty"`
	Domains []domainRow  `json:"domains,omitempty"`
	Brute   *bruteRow    `json:"brute,omitempty"`
	Probe   *probeRow    `json:"probe,omitempty"`
	Dropin  *dropinRow   `json:"dropin,omitempty"`
	Ports   *portsRow    `json:"ports,omitempty"`
	Dirs    *dirsRow     `json:"dirs,omitempty"`
	Params  *paramsRow   `json:"params,omitempty"`
	Scope   *scopeRow    `json:"scope,omitempty"`
	Network *networkRow  `json:"network,omitempty"`
	Shots   *shotsRow    `json:"shots,omitempty"`
	Secrets *secretsRow  `json:"secrets,omitempty"`
	Tenants *tenantsRow  `json:"tenants,omitempty"`
	Scale   *scaleRow    `json:"scale,omitempty"`
	Claims  *claimsRow   `json:"claims,omitempty"`
	Regress *regressRow  `json:"regress,omitempty"`
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
	Cached  bool    `json:"cached,omitempty"` // replayed from today's run (refcache.go)
}

// sections are what -only picks from; dockerParts need the docker apps.
var (
	sections    = []string{"apps", "dropin", "dirs", "scope", "secrets", "tenants", "scale", "claims", "regress", "shots", "params", "domains", "brute", "ports", "network", "probe"}
	dockerParts = []string{"dropin", "dirs", "scope", "scale", "shots", "params"}
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
	brute := flag.Bool("brute", true, "run the DNS brute-force, wildcard and permutation benchmark (vulnweb.com only)")
	ports := flag.Bool("ports", true, "compare the port scan with naabu on scanme.nmap.org and this machine")
	probe := flag.Bool("probe", true, "compare probing with httpx: live names of the benchmark domains, ginandjuice.shop and the local apps")
	network := flag.Bool("network", true, "compare ASN prefixes with RADb and reverse DNS with dnsx -ptr (needs the domain benchmark's DNS)")
	crapi := flag.Bool("crapi", false, "also run OWASP crAPI (seven containers, about 2 GB of images)")
	keep := flag.Bool("keep", false, "leave the docker apps running")
	only := flag.String("only", "", "run only these sections, comma-separated: "+strings.Join(sections, ", ")+"; the default runs them all")
	flag.BoolVar(&fresh, "fresh", false, "run the reference tools again instead of reusing today's cached results")
	out := flag.String("out", "bench/history", "directory for the JSON record")
	flag.StringVar(&work, "work", "bench/.work", "scratch directory")
	flag.BoolVar(&verbose, "v", false, "print each command")
	flag.Parse()
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
		logf("-only probe without domains: the hosts are the local apps and ginandjuice.shop only")
	}
	// on: the section runs; without -only, as its own flag says.
	on := func(name string, def bool) bool {
		if len(sel) == 0 {
			return def
		}
		return sel[name]
	}

	if _, err := os.Stat("go.mod"); err != nil {
		fatal("run from the repository root: go run ./bench")
	}
	work, _ = filepath.Abs(work)
	binDir = filepath.Join(work, "bin")
	azhaq = filepath.Join(binDir, "azhaq")
	rec = record{
		Date:   time.Now().UTC().Format(time.RFC3339),
		Commit: commit(),
		Go:     runtime.Version(),
		Tools:  append(append([]tool(nil), tools...), builtTools...),
	}

	must(os.MkdirAll(binDir, 0o755))
	// A fresh name history per bench run: one-shot, as the reference tools are.
	must(os.Setenv("AZHAQ_DATA_DIR", filepath.Join(work, "data-"+time.Now().UTC().Format("20060102T150405"))))
	logf("building azhaq")
	if _, err := exec.Command("go", "build", "-o", azhaq, "./cmd/azhaq").CombinedOutput(); err != nil {
		fatal("go build: %v", err)
	}
	if !(len(sel) == 1 && sel["regress"]) { // regress uses what $AZHAQ_REFBIN holds
		must(installTools(binDir))
		must(installBuilt(binDir))
	}

	docker := on("apps", *apps)
	for _, s := range dockerParts {
		docker = docker || on(s, *apps)
	}
	if docker {
		must(startApps())
		if !*keep {
			defer stopApps()
		}
	}
	if on("apps", *apps) {
		rec.Apps = benchApps()
	}
	if *crapi {
		must(startCrapi())
		if !*keep {
			defer stopCrapi()
		}
		rec.Apps = append(rec.Apps, benchCrapi())
	}
	if len(rec.Apps) > 0 {
		appChecks(rec.Apps)
	}
	if on("dropin", *apps) {
		rec.Dropin = benchDropin(*crapi)
	}
	if on("dirs", *apps) {
		local := []string{juiceURL, vampiURL}
		if *crapi {
			local = append(local, crapiURL)
		}
		rec.Dirs = benchDirs(local)
	}
	if on("scope", *apps) {
		rec.Scope = benchScope(juiceURL)
	}
	if on("secrets", *apps) {
		rec.Secrets = benchSecrets()
	}
	if on("tenants", *apps) {
		rec.Tenants = benchTenants()
	}
	if on("scale", *apps) {
		rec.Scale = benchScale(juiceURL)
	}
	if on("claims", *apps) {
		rec.Claims = benchClaims()
	}
	if on("regress", false) {
		rec.Regress = benchRegress()
	}
	if on("shots", *apps) {
		rec.Shots = benchShots([]string{juiceURL, vampiURL, ginURL, "http://rest.vulnweb.com/"})
	}
	if on("params", *apps) {
		rec.Params = benchParams([]string{
			juiceURL + "rest/products/search", juiceURL + "rest/user/whoami", vampiURL + "users/v1",
			ginURL + "catalog", ginURL + "blog/",
		})
	}
	if on("domains", *domains) {
		rec.Domains = benchDomains()
	}
	if on("brute", *brute) {
		rec.Brute = benchBrute()
	}
	if on("ports", *ports) {
		rec.Ports = benchPorts()
	}
	if on("network", *domains && *network) {
		rec.Network = benchNetwork()
	}
	if on("probe", *probe) {
		var local []string
		if docker {
			local = append(local, "127.0.0.1:3101", "127.0.0.1:5102")
		}
		if *crapi {
			local = append(local, "127.0.0.1:8888")
		}
		rec.Probe = benchProbe(local)
	}

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
			m.Target = target
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
	m := runMeasure{Tool: filepath.Base(name), Target: target}
	err := cmd.Start()
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

func ref(name string) string { return filepath.Join(binDir, name) }

func addCheck(name string, pass bool, format string, a ...any) {
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
