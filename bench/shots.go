package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// shotsRow compares screenshots with gowitness on the same targets and
// the same Chrome.
type shotsRow struct {
	Targets       int     `json:"targets"`
	Azhaq         int     `json:"azhaq"`
	Gowitness     int     `json:"gowitness"`
	AzhaqSeconds  float64 `json:"azhaq_seconds"`
	GowitnessSecs float64 `json:"gowitness_seconds"`
}

func benchShots(targets []string) *shotsRow {
	chrome, err := exec.LookPath("google-chrome")
	if err != nil {
		if chrome, err = exec.LookPath("chromium"); err != nil {
			logf("screenshots: no Chrome, skipped")
			return nil
		}
	}
	dir, _ := filepath.Abs(filepath.Join(work, "shots-"+time.Now().Format("150405")))
	must(os.MkdirAll(dir, 0o755))
	list := filepath.Join(dir, "targets.txt")
	must(os.WriteFile(list, []byte(strings.Join(targets, "\n")+"\n"), 0o644))
	row := &shotsRow{Targets: len(targets)}

	out, m := run("shots", 10*time.Minute, dir, azhaq, "shots", "-l", list, "-dir", filepath.Join(dir, "azhaq"), "-silent")
	row.Azhaq, row.AzhaqSeconds = len(lines(out)), m.Seconds
	_, m = run("shots", 10*time.Minute, dir, ref("gowitness"), "scan", "file", "-f", list, "--chrome-path", chrome,
		"-s", filepath.Join(dir, "gowitness"), "-t", "4", "-T", "30")
	row.GowitnessSecs = m.Seconds
	files, _ := os.ReadDir(filepath.Join(dir, "gowitness"))
	row.Gowitness = len(files)
	addCheck("screenshots: ≥ 95% of gowitness's", row.Gowitness > 0 && float64(row.Azhaq) >= 0.95*float64(row.Gowitness),
		"azhaq %d in %.0fs, gowitness %d in %.0fs, %d targets, 4 tabs each", row.Azhaq, row.AzhaqSeconds, row.Gowitness, row.GowitnessSecs, row.Targets)
	return row
}
