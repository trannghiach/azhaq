package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// arjun (GPL-3.0) runs as a separate program from its own virtualenv; it
// is a reference, not a dependency.
const arjunVersion = "2.2.7"

func installArjun() (string, error) {
	if refBin != "" {
		if p := filepath.Join(refBin, "arjun-venv", "bin", "arjun"); fileExists(p) {
			return p, nil
		}
	}
	dir := filepath.Join(work, "arjun-"+arjunVersion)
	bin := filepath.Join(dir, "bin", "arjun")
	if _, err := os.Stat(bin); err == nil {
		return bin, nil
	}
	logf("installing arjun %s", arjunVersion)
	if out, err := exec.Command("python3", "-m", "venv", dir).CombinedOutput(); err != nil {
		return "", &httpError{"python3 -m venv", strings.TrimSpace(string(out))}
	}
	if out, err := exec.Command(filepath.Join(dir, "bin", "pip"), "install", "-q", "arjun=="+arjunVersion).CombinedOutput(); err != nil {
		return "", &httpError{"pip install arjun", strings.TrimSpace(string(out))}
	}
	return bin, nil
}

// paramsRow compares parameter discovery with arjun on a server the bench
// plants known parameters in, on the local apps and on two low-rate pages of
// a public test site, with the same names and settings.
type paramsRow struct {
	Profile   string   `json:"profile,omitempty"`
	Pages     []string `json:"pages"`
	Words     int      `json:"words"`
	Azhaq     []string `json:"azhaq"`
	Arjun     []string `json:"arjun"`
	Shared    int      `json:"shared"`
	AzhaqSecs float64  `json:"azhaq_seconds"`
	ArjunSecs float64  `json:"arjun_seconds"`
	// Planted: the pages whose every parameter is known.
	PlantedTruth int     `json:"planted_truth"`
	AzhaqPlanted int     `json:"azhaq_planted"`
	ArjunPlanted int     `json:"arjun_planted"`
	AzhaqWrong   int     `json:"azhaq_wrong"` // names reported on a planted page that it does not read
	ArjunWrong   int     `json:"arjun_wrong"`
	GinAzhaqSecs float64 `json:"gin_azhaq_seconds,omitempty"`
	GinArjunSecs float64 `json:"gin_arjun_seconds,omitempty"`
}

// plantedParams serves pages that read known parameters: a parameter that
// is present changes the body, and no other does. It is the ground truth
// the tools are scored against.
func plantedParams() (base string, truth map[string]map[string]bool, stop func()) {
	reads := map[string][]string{
		"/search": {"q", "page", "sort", "limit", "lang"},
		"/item":   {"id", "format", "debug"},
	}
	truth = map[string]map[string]bool{}
	for p, ns := range reads {
		truth[p] = map[string]bool{}
		for _, n := range ns {
			truth[p][n] = true
		}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	must(err)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ns, ok := reads[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		fmt.Fprintf(w, "<html><title>%s</title><body>results", r.URL.Path)
		for _, n := range ns {
			if v := r.URL.Query().Get(n); v != "" {
				fmt.Fprintf(w, "\n<p>%s applied</p>", n)
			}
		}
		fmt.Fprint(w, "</body></html>")
	})}
	go srv.Serve(ln)
	return "http://" + ln.Addr().String(), truth, func() { _ = srv.Close() }
}

func benchParams() *paramsRow {
	words, err := fetchWordlist(paramWords)
	must(err)
	arjun, err := installArjun()
	must(err)
	dir, _ := filepath.Abs(filepath.Join(work, "params"))
	must(os.MkdirAll(dir, 0o755))
	base, truth, stop := plantedParams()
	defer stop()
	pages := []string{base + "/search", base + "/item", juiceURL + "rest/products/search", juiceURL + "rest/user/whoami", vampiURL + "users/v1"}
	ginWords := firstWords(words, 1000, filepath.Join(dir, "gin-words.txt"))
	gin := []string{ginURL + "catalog", ginURL + "blog/"}
	if polite() {
		// At 5 requests per second every page costs minutes: the planted pages and Juice Shop's
		// search; the public site is asked at 5 per second in the default profile already.
		pages, gin = pages[:3], nil
	}
	row := &paramsRow{Profile: prof, Pages: append(append([]string(nil), pages...), gin...), Words: len(lines(must1(os.ReadFile(words))))}
	for _, t := range truth {
		row.PlantedTruth += len(t)
	}
	az, aj := map[string]bool{}, map[string]bool{}
	var azCmd, ajCmd, azFailed string
	one := func(p, wl string, public bool) (azNames, ajNames []string) {
		// A public test site is always asked at 5 requests per second.
		slow := polite() || public
		var azPace, ajPace []string
		if slow {
			azPace, ajPace = []string{"-rate", politeHTTP}, []string{"--rate-limit", politeHTTP}
		}
		aa := append([]string{"params", "-u", p, "-w", wl, "-silent"}, azPace...)
		out, m := timed(p, 20*time.Minute, dir, azhaq, aa...)
		azFailed += azFail(m)
		if public {
			row.GinAzhaqSecs += m.Seconds
		} else {
			row.AzhaqSecs += m.Seconds
		}
		azCmd = cmdLine(azhaq, aa...)
		for _, l := range lines(out) {
			u, names, _ := strings.Cut(l, " ")
			for _, n := range strings.Split(names, ",") {
				if n = strings.TrimSpace(n); n != "" {
					azNames = append(azNames, strings.TrimSuffix(u, "/")+" "+n)
				}
			}
		}
		res := filepath.Join(dir, "arjun.json")
		ja := append([]string{"-u", p, "-w", wl, "-oJ", res, "-q", "--disable-redirects"}, ajPace...)
		_ = os.Remove(res)
		// arjun writes a file: rerun for the median with the file removed first.
		_, jm := runArjunTimed(p, dir, arjun, ja, res)
		if public {
			row.GinArjunSecs += jm.Seconds
		} else {
			row.ArjunSecs += jm.Seconds
		}
		ajCmd = cmdLine("arjun", ja...)
		var got map[string]struct {
			Params []string `json:"params"`
		}
		if raw, err := os.ReadFile(res); err == nil && json.Unmarshal(raw, &got) == nil {
			for u, r := range got {
				for _, n := range r.Params {
					ajNames = append(ajNames, strings.TrimSuffix(u, "/")+" "+n)
				}
			}
		}
		return
	}
	for _, p := range pages {
		an, jn := one(p, words, false)
		path := "/" + strings.TrimPrefix(strings.TrimPrefix(p, base), "/")
		pt, planted := truth[path]
		if strings.HasPrefix(p, base) {
			for _, n := range an {
				_, name, _ := strings.Cut(n, " ")
				if pt[name] && planted {
					row.AzhaqPlanted++
				} else {
					row.AzhaqWrong++
				}
			}
			for _, n := range jn {
				_, name, _ := strings.Cut(n, " ")
				if pt[name] && planted {
					row.ArjunPlanted++
				} else {
					row.ArjunWrong++
				}
			}
		}
		for _, n := range an {
			az[n] = true
		}
		for _, n := range jn {
			aj[n] = true
		}
	}
	for _, p := range gin {
		an, jn := one(p, ginWords, true)
		for _, n := range an {
			az[n] = true
		}
		for _, n := range jn {
			aj[n] = true
		}
	}
	row.Azhaq, row.Arjun, row.Shared = sortedKeys(az), sortedKeys(aj), overlap(az, aj)
	sort.Strings(row.Azhaq)
	cmds := azCmd + " vs " + ajCmd
	note := fmt.Sprintf("%s; planted pages: azhaq %d right %d wrong, arjun %d right %d wrong, of %d; all pages azhaq %d, arjun %d, shared %d; %s", share(row.Shared, len(aj)),
		row.AzhaqPlanted, row.AzhaqWrong, row.ArjunPlanted, row.ArjunWrong, row.PlantedTruth, len(az), len(aj), row.Shared, ratio(row.AzhaqSecs, row.ArjunSecs)) + azFailed
	if len(gin) > 0 {
		addCheck("params: ginandjuice.shop (2 pages, 1,000 names, 5 requests per second) time ≤ 1.05× arjun's", row.GinAzhaqSecs <= row.GinArjunSecs*1.05,
			"azhaq %.1fs, arjun %.1fs", row.GinAzhaqSecs, row.GinArjunSecs)
	}
	barOne("params", row.AzhaqPlanted-row.AzhaqWrong, row.ArjunPlanted-row.ArjunWrong, row.AzhaqSecs, row.ArjunSecs, "the planted server's own list of the parameters it reads (wrong names count against)", cmds, note)
	return row
}

// runArjunTimed runs arjun with the median-of-three rule, removing its
// output file before each run.
func runArjunTimed(target, dir, bin string, args []string, res string) ([]byte, runMeasure) {
	out, m := run(target, 20*time.Minute, dir, bin, args...)
	if m.Error != "" || m.Seconds >= slowRun {
		return out, m
	}
	keep, _ := os.ReadFile(res)
	secs := []float64{m.Seconds}
	noCache = true
	for i := 1; i < 3; i++ {
		_ = os.Remove(res)
		if _, m2 := run(target, 20*time.Minute, dir, bin, args...); m2.Error == "" {
			secs = append(secs, m2.Seconds)
		}
	}
	noCache = false
	_ = os.WriteFile(res, keep, 0o644)
	sort.Float64s(secs)
	m.Seconds = secs[len(secs)/2]
	return out, m
}

// firstWords writes the first n lines of a wordlist to path.
func firstWords(src string, n int, path string) string {
	ls := lines(must1(os.ReadFile(src)))
	if len(ls) > n {
		ls = ls[:n]
	}
	must(os.WriteFile(path, []byte(strings.Join(ls, "\n")+"\n"), 0o644))
	return path
}
