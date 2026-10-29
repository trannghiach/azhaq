package main

import (
	"encoding/json"
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

// paramsRow compares parameter discovery with arjun on pages of the bench
// apps, with the same names.
type paramsRow struct {
	Pages     []string `json:"pages"`
	Words     int      `json:"words"`
	Azhaq     []string `json:"azhaq"`
	Arjun     []string `json:"arjun"`
	Shared    int      `json:"shared"`
	AzhaqSecs float64  `json:"azhaq_seconds"`
	ArjunSecs float64  `json:"arjun_seconds"`
}

func benchParams(pages []string) *paramsRow {
	words, err := fetchWordlist(paramWords)
	must(err)
	arjun, err := installArjun()
	must(err)
	dir, _ := filepath.Abs(filepath.Join(work, "params"))
	must(os.MkdirAll(dir, 0o755))
	row := &paramsRow{Pages: pages, Words: len(lines(must1(os.ReadFile(words))))}
	az, aj := map[string]bool{}, map[string]bool{}
	for _, p := range pages {
		// Both at their defaults on the local apps; on a public test site
		// both at the same low pace.
		var azPace, ajPace []string
		if !strings.Contains(p, "127.0.0.1") {
			azPace, ajPace = []string{"-rate", "20"}, []string{"--rate-limit", "20"}
		}
		out, m := run(p, 10*time.Minute, dir, azhaq, append([]string{"params", "-u", p, "-w", words, "-silent"}, azPace...)...)
		row.AzhaqSecs += m.Seconds
		for _, l := range lines(out) {
			u, names, _ := strings.Cut(l, " ")
			for _, n := range strings.Split(names, ",") {
				if n != "" {
					az[strings.TrimSuffix(u, "/")+" "+n] = true
				}
			}
		}
		res := filepath.Join(dir, "arjun.json")
		_ = os.Remove(res)
		_, m = run(p, 10*time.Minute, dir, arjun, append([]string{"-u", p, "-w", words, "-oJ", res, "-q", "--disable-redirects"}, ajPace...)...)
		row.ArjunSecs += m.Seconds
		var got map[string]struct {
			Params []string `json:"params"`
		}
		if raw, err := os.ReadFile(res); err == nil && json.Unmarshal(raw, &got) == nil {
			for u, r := range got {
				for _, n := range r.Params {
					aj[strings.TrimSuffix(u, "/")+" "+n] = true
				}
			}
		}
	}
	row.Azhaq, row.Arjun, row.Shared = sortedKeys(az), sortedKeys(aj), overlap(az, aj)
	sort.Strings(row.Azhaq)
	addCheck("params: ≥ 95% of arjun's parameters on the bench pages", len(aj) > 0 && float64(row.Shared) >= 0.95*float64(len(aj)),
		"azhaq %d, arjun %d, shared %d (%d pages, %d names)", len(az), len(aj), row.Shared, len(pages), row.Words)
	return row
}
