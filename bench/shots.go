package main

import (
	"fmt"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// shotsRow compares screenshots with gowitness on the same targets and
// the same Chrome: the five local apps and three pages the bench serves
// (a login page, a default web server page, an admin page).
type shotsRow struct {
	Profile       string  `json:"profile,omitempty"`
	Targets       int     `json:"targets"`
	Azhaq         int     `json:"azhaq"`
	Gowitness     int     `json:"gowitness"`
	AzhaqOK       int     `json:"azhaq_confirmed"` // files that decode and are not one colour
	GowitnessOK   int     `json:"gowitness_confirmed"`
	AzhaqSeconds  float64 `json:"azhaq_seconds"`
	GowitnessSecs float64 `json:"gowitness_seconds"`
}

// shotPages serves three pages with content a blank screenshot would lack.
func shotPages() (base string, stop func()) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	must(err)
	page := func(title, body string) string {
		return `<html><head><title>` + title + `</title><style>body{font-family:sans-serif;margin:40px}.box{background:#246;color:#fff;padding:20px;width:300px}</style></head><body>` + body + `</body></html>`
	}
	pages := map[string]string{
		"/login": page("Sign in", `<div class="box"><h1>Sign in</h1><form><input name=user><input type=password name=pw><button>Log in</button></form></div>`),
		"/nginx": page("Welcome to nginx!", `<h1>Welcome to nginx!</h1><p>If you see this page, the nginx web server is successfully installed and working.</p>`),
		"/admin": page("Admin", `<div class="box"><h1>Admin</h1></div><table border=1><tr><td>users</td><td>12</td></tr><tr><td>orders</td><td>345</td></tr></table>`),
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p, ok := pages[r.URL.Path]; ok {
			fmt.Fprint(w, p)
			return
		}
		http.NotFound(w, r)
	})}
	go srv.Serve(ln)
	return "http://" + ln.Addr().String(), func() { _ = srv.Close() }
}

func benchShots() *shotsRow {
	chrome, err := exec.LookPath("google-chrome")
	if err != nil {
		if chrome, err = exec.LookPath("chromium"); err != nil {
			logf("screenshots: no Chrome, skipped")
			addCheck("screenshots: Chrome is installed", false, "neither google-chrome nor chromium is in PATH")
			return nil
		}
	}
	base, stop := shotPages()
	defer stop()
	targets := []string{juiceURL, vampiURL, "http://127.0.0.1:5013/", "http://127.0.0.1:5020/", "http://127.0.0.1:5030/", base + "/login", base + "/nginx", base + "/admin"}
	if polite() {
		// At 5 requests per second the eight pages took over seven minutes a tool.
		targets = []string{juiceURL, base + "/login", base + "/nginx", base + "/admin"}
	}
	dir, _ := filepath.Abs(filepath.Join(work, "shots-"+time.Now().Format("150405")+"-"+prof))
	must(os.MkdirAll(dir, 0o755))
	list := filepath.Join(dir, "targets.txt")
	must(os.WriteFile(list, []byte(strings.Join(targets, "\n")+"\n"), 0o644))
	row := &shotsRow{Profile: prof, Targets: len(targets)}

	azArgs := func(i int) []string {
		a := []string{"shots", "-l", list, "-dir", filepath.Join(dir, fmt.Sprintf("azhaq%d", i)), "-silent"}
		return append(a, pick([]string(nil), []string{"-rate", politeHTTP})...)
	}
	// gowitness has no rate option, so it runs with its defaults in both
	// profiles (with -t 1 it shoots the first page and times out on the rest).
	gwArgs := func(i int) []string {
		return []string{"scan", "file", "-f", list, "--chrome-path", chrome, "-s", filepath.Join(dir, fmt.Sprintf("gowitness%d", i)), "-q"}
	}
	out, m := timedArgs("shots", 20*time.Minute, dir, azhaq, azArgs)
	row.Azhaq, row.AzhaqSeconds = len(lines(out)), m.Seconds
	row.AzhaqOK = countShots(filepath.Join(dir, "azhaq0"))
	_, gm := timedArgs("shots", 20*time.Minute, dir, ref("gowitness"), gwArgs)
	row.GowitnessSecs = gm.Seconds
	row.GowitnessOK = countShots(filepath.Join(dir, "gowitness0"))
	row.Gowitness = row.GowitnessOK
	if files, _ := os.ReadDir(filepath.Join(dir, "gowitness0")); len(files) > 0 {
		row.Gowitness = len(files)
	}
	barOne("screenshots", row.AzhaqOK, row.GowitnessOK, row.AzhaqSeconds, row.GowitnessSecs, "the image files: each decodes and is not one colour",
		cmdLine(azhaq, azArgs(0)...)+" vs "+cmdLine("gowitness", gwArgs(0)...),
		fmt.Sprintf("%s; %d targets; azhaq listed %d, gowitness wrote %d files; %s%s", share(row.AzhaqOK, row.GowitnessOK), row.Targets, row.Azhaq, row.Gowitness, ratio(row.AzhaqSeconds, row.GowitnessSecs), azErr(m)))
	return row
}

// countShots counts the image files in dir that decode and hold more than
// one colour: a screenshot of a blank page is not a result.
func countShots(dir string) int {
	n := 0
	files, _ := os.ReadDir(dir)
	for _, f := range files {
		fh, err := os.Open(filepath.Join(dir, f.Name()))
		if err != nil {
			continue
		}
		img, _, err := image.Decode(fh)
		fh.Close()
		if err != nil {
			continue
		}
		b := img.Bounds()
		seen := map[uint32]bool{}
		for y := b.Min.Y; y < b.Max.Y && len(seen) < 2; y += max(1, b.Dy()/40) {
			for x := b.Min.X; x < b.Max.X && len(seen) < 2; x += max(1, b.Dx()/40) {
				r, g, bl, _ := img.At(x, y).RGBA()
				seen[(r>>11)<<10|(g>>11)<<5|bl>>11] = true
			}
		}
		if len(seen) > 1 {
			n++
		}
	}
	return n
}
