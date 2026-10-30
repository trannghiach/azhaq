package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// regressRow holds the checks for findings that reviewers raised and that
// need the local apps or this machine (REGRESSIONS.md). Each row is named
// by its finding. A row of an open finding that is not met passes the run
// (the finding is open) and says so in its detail and in Met.
type regressRow struct {
	Rows    []regressItem `json:"rows"`
	Seconds float64       `json:"seconds"`
}

type regressItem struct {
	ID     string `json:"id"`
	Open   bool   `json:"open,omitempty"`
	Met    bool   `json:"met"`
	Detail string `json:"detail"`
}

// The local apps these checks use: the azq-* containers, not the bench's own.
const regressJuice, regressVampi = claimJuice + "/", claimVampi + "/"

// refTool is a reference tool: in the bench's bin, or in $AZHAQ_REFBIN.
func refTool(name string) (string, bool) {
	for _, dir := range []string{binDir, os.Getenv("AZHAQ_REFBIN")} {
		if dir == "" {
			continue
		}
		if p := filepath.Join(dir, name); fileExists(p) {
			return p, true
		}
	}
	return "", false
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

// record adds one regress check. met is whether the finding's pass
// condition holds; an open finding's unmet condition does not fail the run.
func (r *regressRow) record(id string, open, met bool, format string, a ...any) {
	detail := fmt.Sprintf(format, a...)
	r.Rows = append(r.Rows, regressItem{ID: id, Open: open, Met: met, Detail: detail})
	name := "regress " + id + ": " + strings.SplitN(detail, ";", 2)[0]
	if open {
		if !met {
			detail = "NOT MET (open finding): " + detail
		}
		addCheck("regress (open) "+id, true, "%s", detail)
	} else {
		addCheck("regress "+id, met, "%s", detail)
	}
	logf("%s: met %v", name, met)
}

func benchRegress() *regressRow {
	t0 := time.Now()
	row := &regressRow{}
	dir, _ := filepath.Abs(filepath.Join(work, "regress-"+time.Now().Format("150405")))
	must(os.MkdirAll(dir, 0o755))
	for _, u := range []string{regressJuice, regressVampi} {
		if err := waitUp(u, 20*time.Second); err != nil {
			addCheck("regress: the local apps are up", false, "%v", err)
			return row
		}
	}
	// While developing: REGRESS_ONLY=SAF-03,PRB-07 runs those checks only.
	only := map[string]bool{}
	for _, id := range strings.Split(os.Getenv("REGRESS_ONLY"), ",") {
		if id = strings.TrimSpace(id); id != "" {
			only[id] = true
		}
	}
	for _, c := range []struct {
		id string
		fn func()
	}{
		{"SAF-03", func() { row.saf03(dir) }}, {"SAF-09", func() { row.saf09(dir) }}, {"PRB-13", func() { row.dirsTime(dir) }},
		{"PRB-07", row.prb07}, {"PRB-14", func() { row.prb14(dir) }}, {"PRB-18", func() { row.prb18(dir) }},
		{"MAP-27", func() { row.map27(dir) }}, {"SPD-01", func() { row.spd01(dir) }},
	} {
		if len(only) == 0 || only[c.id] {
			c.fn()
		}
	}
	row.Seconds = time.Since(t0).Seconds()
	return row
}

// SAF-03: the summary's requests, the ledger and an independent proxy
// agree for the Chrome paths on a live page with a WebSocket (Juice Shop)
// and for the plain HTTP map. The claims section's cases do the counting.
func (r *regressRow) saf03(dir string) {
	c := &claims{row: &claimsRow{}, only: map[string]bool{}, dir: dir}
	if _, err := exec.LookPath("google-chrome"); err == nil {
		c.chrome = true
	} else if _, err := exec.LookPath("chromium"); err == nil {
		c.chrome = true
	}
	if !c.chrome {
		r.record("SAF-03", false, false, "no Chrome here: the Chrome request count was not checked")
		return
	}
	c.caseBrowser()
	c.caseShots()
	met := true
	var parts []string
	for _, cr := range c.row.Rows {
		met = met && cr.Pass
		parts = append(parts, fmt.Sprintf("%s %s: summary %d, ledger %d, proxy %d", cr.Case, cr.Pace, cr.Summary, cr.Ledger, cr.Counter))
	}
	r.record("SAF-03", false, met && len(parts) > 0, "run -browser and shots on Juice Shop at three paces, summary = ledger = proxy; %s", strings.Join(parts, " | "))
}

// SAF-09: an MCP server whose budget is spent refuses a port scan, and a
// scan with budget left counts its connects (the listener's count is the
// evidence).
func (r *regressRow) saf09(dir string) {
	px, err := newCountProxy(regressJuice)
	must(err)
	defer px.close()
	l := startTCP("silent")
	defer l.ln.Close()
	port := fmt.Sprint(l.port())
	m := startMCP(dir, "-allow", "127.0.0.1", "-max-requests", "60", "-dir", filepath.Join(dir, "mcp-ports.d"))
	defer m.stop()
	m.init()
	spent := false
	for range 4 { // map until the budget is spent
		id := m.mapCall(px.origin, "w")
		res := m.read(id)
		if _, text := mcpSummary(res[id]); strings.Contains(text, "spent") {
			spent = true
			break
		}
	}
	scan := func() (string, int, bool) {
		id := m.write("tools/call", map[string]any{"name": "azhaq_ports", "arguments": map[string]any{"hosts": []string{"127.0.0.1"}, "ports": port}}, false)
		res := m.read(id)
		var out struct {
			IsError bool `json:"isError"`
		}
		_ = json.Unmarshal(res[id], &out)
		n, text := mcpSummary(res[id])
		return text, n, out.IsError
	}
	before := l.accepts.Load()
	text, _, isErr := scan()
	sent := l.accepts.Load() - before
	r.record("SAF-09", false, spent && isErr && strings.Contains(text, "spent") && sent == 0,
		"azhaq_ports after the budget of 60 was spent; the map calls spent it %v, the scan was refused %v (%s), connects at the listener %d",
		spent, isErr, clip(text, 90), sent)

	// With budget left: a fresh server; the scan's connects are counted.
	m2 := startMCP(dir, "-allow", "127.0.0.1", "-max-requests", "60", "-rate", "50", "-dir", filepath.Join(dir, "mcp-ports2.d"))
	defer m2.stop()
	m2.init()
	before = l.accepts.Load()
	id := m2.write("tools/call", map[string]any{"name": "azhaq_ports", "arguments": map[string]any{"hosts": []string{"127.0.0.1"}, "ports": port}}, false)
	res := m2.read(id)
	n, text := mcpSummary(res[id])
	got := l.accepts.Load() - before
	r.record("SAF-09", false, n >= 1 && int64(n) == got,
		"azhaq_ports with budget left; summary requests %d, connects at the listener %d (%s)", n, got, clip(text, 60))
}

// dirsTime: dirs and params at their default flags against ffuf and arjun
// (PRB-13), and the same hits as ffuf -ac.
func (r *regressRow) dirsTime(dir string) {
	words, err := fetchWordlist(webWords)
	must(err)
	ffuf, ok := refTool("ffuf")
	if !ok {
		r.record("PRB-13", false, false, "ffuf not found (bin or $AZHAQ_REFBIN)")
		return
	}
	for _, app := range []string{regressJuice, regressVampi} {
		azOut, am := run(app, 10*time.Minute, dir, azhaq, "dirs", "-u", app, "-w", words, "-silent")
		ffOut, fm := run(app, 10*time.Minute, dir, ffuf, "-u", app+"FUZZ", "-w", words, "-ac", "-s")
		az, ff := map[string]bool{}, map[string]bool{}
		for _, l := range lines(azOut) {
			az[l] = true
		}
		for _, l := range lines(ffOut) {
			ff[app+l] = true
		}
		shared := overlap(az, ff)
		r.record("PRB-13", false, am.Seconds <= 1.2*fm.Seconds+0.5 && float64(shared) >= float64(len(ff)),
			"dirs at default flags on %s: azhaq %.1fs, ffuf %.1fs (azhaq <= 1.2x ffuf + 0.5s); hits azhaq %d, ffuf %d, shared %d", app, am.Seconds, fm.Seconds, len(az), len(ff), shared)
	}
	arjun := filepath.Join(os.Getenv("AZHAQ_REFBIN"), "arjun-venv", "bin", "arjun")
	if !fileExists(arjun) {
		arjun = filepath.Join(work, "arjun-"+arjunVersion, "bin", "arjun")
	}
	pwords, err := fetchWordlist(paramWords)
	must(err)
	if !fileExists(arjun) {
		r.record("PRB-13", false, false, "arjun not found for the params timing")
		return
	}
	page := regressJuice + "rest/products/search"
	_, am := run(page, 20*time.Minute, dir, azhaq, "params", "-u", page, "-w", pwords, "-silent")
	_, jm := run(page, 20*time.Minute, dir, arjun, "-u", page, "-w", pwords, "-q", "-oJ", filepath.Join(dir, "arjun.json"))
	r.record("PRB-13", false, am.Seconds <= 2*jm.Seconds,
		"params at default flags on %s: azhaq %.1fs, arjun %.1fs (azhaq <= 2x arjun)", page, am.Seconds, jm.Seconds)
}

// listening is the TCP ports in the LISTEN state on this machine.
func listening() map[string]bool {
	out, _ := exec.Command("ss", "-ltnH").Output()
	set := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 4 {
			continue
		}
		addr := f[3]
		host, port := addr[:strings.LastIndex(addr, ":")], addr[strings.LastIndex(addr, ":")+1:]
		if host == "127.0.0.1" || host == "0.0.0.0" || host == "*" || host == "[::]" || host == "[::ffff:127.0.0.1]" {
			set[port] = true
		}
	}
	return set
}

// PRB-07: a full TCP sweep of 127.0.0.1 holds every port that listened the
// whole time and none that listened at neither end.
func (r *regressRow) prb07() {
	met, detail := true, []string{}
	for i := range 3 {
		before := listening()
		res := azExec(".", 10*time.Minute, "ports", "-host", "127.0.0.1", "-p", "full", "-json")
		after := listening()
		found := map[string]bool{}
		for _, l := range lines([]byte(res.stdout)) {
			var row struct {
				Port int `json:"port"`
			}
			if json.Unmarshal([]byte(l), &row) == nil && row.Port > 0 {
				found[fmt.Sprint(row.Port)] = true
			}
		}
		// A port that listened throughout and is not open must be said in
		// the summary (neither accepted nor refused: a full accept queue).
		var missed, phantom []string
		for p := range before {
			if after[p] && !found[p] && !strings.Contains(res.stderr, p) {
				missed = append(missed, p)
			}
		}
		for p := range found {
			if !before[p] && !after[p] {
				phantom = append(phantom, p)
			}
		}
		// The note names the first eight and counts the rest ("+8 more").
		if m := regexp.MustCompile(`\+(\d+) more`).FindStringSubmatch(res.stderr); m != nil {
			n, _ := strconv.Atoi(m[1])
			missed = missed[:max(0, len(missed)-n)]
		}
		sort.Strings(missed)
		sort.Strings(phantom)
		if len(missed)+len(phantom) > 0 {
			met = false
		}
		detail = append(detail, fmt.Sprintf("sweep %d: %d open, %d listening before, missed and not covered by the note %v, listed but never listening %v", i+1, len(found), len(before), missed, phantom))
	}
	r.record("PRB-07", true, met, "ports -p full on 127.0.0.1 against ss -ltn before and after; %s", strings.Join(detail, "; "))
}

// PRB-14: dirs holds at most 40 MB at 4,751 words.
func (r *regressRow) prb14(dir string) {
	words, err := fetchWordlist(webWords)
	must(err)
	_, am := run(regressJuice, 10*time.Minute, dir, azhaq, "dirs", "-u", regressJuice, "-w", words, "-silent")
	r.record("PRB-14", true, am.RSSMB > 0 && am.RSSMB <= 40, "dirs on Juice Shop with %d words; peak %.0f MB (<= 40 MB)", len(lines(must1(os.ReadFile(words)))), am.RSSMB)
}

// PRB-18: one screenshot of Juice Shop in at most twice gowitness's time.
func (r *regressRow) prb18(dir string) {
	chrome, err := exec.LookPath("google-chrome")
	if err != nil {
		r.record("PRB-18", true, false, "no Chrome here")
		return
	}
	gow, ok := refTool("gowitness")
	if !ok {
		r.record("PRB-18", true, false, "gowitness not found (bin or $AZHAQ_REFBIN)")
		return
	}
	_, am := run("shots", 5*time.Minute, dir, azhaq, "shots", "-u", regressJuice, "-dir", filepath.Join(dir, "p18-azhaq"), "-silent")
	_, gm := run("shots", 5*time.Minute, dir, gow, "scan", "single", "-u", regressJuice, "--chrome-path", chrome, "-s", filepath.Join(dir, "p18-gowitness"), "-T", "30")
	r.record("PRB-18", true, am.Seconds <= 2*gm.Seconds, "one screenshot of Juice Shop: azhaq %.1fs, gowitness %.1fs (azhaq <= 2x)", am.Seconds, gm.Seconds)
}

// timedRun runs azhaq with extra environment and returns its wall time.
func timedRun(dir string, env []string, args ...string) float64 {
	cmd := exec.Command(azhaq, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	t0 := time.Now()
	_ = cmd.Run()
	return time.Since(t0).Seconds()
}

// MAP-27: the first run on a cold cache takes at most 1.5x the median of
// the next three.
func (r *regressRow) map27(dir string) {
	home := filepath.Join(dir, "cold-home")
	must(os.MkdirAll(home, 0o755))
	env := []string{"HOME=" + home, "XDG_CONFIG_HOME=" + home + "/config", "XDG_CACHE_HOME=" + home + "/cache", "XDG_DATA_HOME=" + home + "/data", "AZHAQ_DATA_DIR=" + home + "/azhaq"}
	var secs []float64
	for i := range 4 {
		secs = append(secs, timedRun(dir, env, "run", "-url", regressJuice, "-db", filepath.Join(dir, fmt.Sprintf("cold%d.db", i)), "-quiet"))
	}
	rest := append([]float64(nil), secs[1:]...)
	sort.Float64s(rest)
	r.record("MAP-27", true, secs[0] <= 1.5*rest[1], "run on Juice Shop with a fresh HOME and XDG dirs; first %.1fs, next three %.1f %.1f %.1f (first <= 1.5x the median %.1fs)", secs[0], secs[1], secs[2], secs[3], rest[1])
}

// SPD-01: a run with Chrome holds at most 250 MB.
func (r *regressRow) spd01(dir string) {
	if _, err := exec.LookPath("google-chrome"); err != nil {
		r.record("SPD-01", true, false, "no Chrome here")
		return
	}
	_, m := run("browser", 10*time.Minute, dir, azhaq, "run", "-url", regressJuice, "-browser", "-db", filepath.Join(dir, "spd01.db"), "-quiet")
	r.record("SPD-01", true, m.RSSMB > 0 && m.RSSMB <= 250, "run -browser on Juice Shop; azhaq's peak %.0f MB (<= 250 MB), %.1fs", m.RSSMB, m.Seconds)
}
