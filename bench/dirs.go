package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// dirsRow compares the path sweep with ffuf -ac on the local apps, with
// the same wordlist and settings: the default flags of both, or both at
// -rate 5.
type dirsRow struct {
	Profile    string   `json:"profile,omitempty"`
	AppDowns   int      `json:"app_down_during_sweep,omitempty"` // an app crashed under the sweep: the row is not a measure
	Words      int      `json:"words"`
	Apps       []string `json:"apps"`
	AzhaqHits  int      `json:"azhaq_hits"`
	FfufHits   int      `json:"ffuf_hits"`
	Shared     int      `json:"shared"`
	AzhaqFalse int      `json:"azhaq_false"` // hits that answer like a path that does not exist
	FfufFalse  int      `json:"ffuf_false"`
	AzhaqSecs  float64  `json:"azhaq_seconds"`
	FfufSecs   float64  `json:"ffuf_seconds"`
	FfufOnly   []string `json:"ffuf_only,omitempty"`
	AzhaqOnly  []string `json:"azhaq_only,omitempty"`
}

// realPaths are paths the bench apps serve, kept in a polite sweep's short
// list so it has something to find.
var realPaths = []string{"ftp", "api", "rest", "assets", "robots.txt", "users", "books", "admin", "login", "metrics", "createdb",
	"openapi.json", "profile", "redirect", "promotion", "video", "snippets", "encryptionkeys", "support", "logs"}

// sweepList is the wordlist for a sweep: the whole file by default, and in
// the polite profile every Nth word plus realPaths, politeWords in all.
func sweepList(src, name string) (string, int) {
	all := lines(must1(os.ReadFile(src)))
	if !polite() {
		return src, len(all)
	}
	step := max(1, len(all)/max(1, politeWords-len(realPaths)))
	seen := map[string]bool{}
	var words []string
	for i := 0; i < len(all); i += step {
		if !seen[all[i]] {
			seen[all[i]] = true
			words = append(words, all[i])
		}
	}
	for _, w := range realPaths {
		if !seen[w] {
			seen[w] = true
			words = append(words, w)
		}
	}
	p := filepath.Join(work, name+"-polite.txt")
	must(os.WriteFile(p, []byte(strings.Join(words, "\n")+"\n"), 0o644))
	return p, len(words)
}

func benchDirs(apps []string) *dirsRow {
	src, err := fetchWordlist(webWords)
	must(err)
	words, n := sweepList(src, "dirs")
	row := &dirsRow{Profile: prof, Words: n, Apps: apps}
	rate := pick([]string(nil), []string{"-rate", politeHTTP})
	az, ff := map[string]bool{}, map[string]bool{}
	var azCmd, ffCmd, azBad string
	downs0 := appRestarts
	defer func() { row.AppDowns = appRestarts - downs0 }()
	for _, app := range apps {
		var aOut, fOut []byte
		var aSecs, fSecs float64
		legWithApp(app, func() {
			aa := append([]string{"dirs", "-u", app, "-w", words, "-silent"}, rate...)
			freshApp(app)
			out, m := timed(app, 40*time.Minute, work, azhaq, aa...)
			aOut, aSecs, azCmd = out, m.Seconds, cmdLine(azhaq, aa...)
			azBad = azFail(m)
			fa := append([]string{"-u", app + "FUZZ", "-w", words, "-ac", "-s"}, pick([]string(nil), []string{"-rate", politeHTTP})...)
			freshApp(app)
			out, m = timed(app, 40*time.Minute, work, ref("ffuf"), fa...)
			fOut, fSecs, ffCmd = out, m.Seconds, cmdLine("ffuf", fa...)
		})
		row.AzhaqSecs += aSecs
		row.FfufSecs += fSecs
		for _, l := range lines(aOut) {
			az[firstField(l)] = true
		}
		for _, l := range lines(fOut) {
			ff[app+l] = true
		}
	}
	row.AzhaqHits, row.FfufHits, row.Shared = len(az), len(ff), overlap(az, ff)
	azOK, ffOK := 0, 0
	for u := range az {
		if softHit(u) {
			row.AzhaqFalse++
		} else {
			azOK++
		}
		if !ff[u] {
			row.AzhaqOnly = append(row.AzhaqOnly, u)
		}
	}
	for u := range ff {
		if softHit(u) {
			row.FfufFalse++
		} else {
			ffOK++
		}
		if !az[u] {
			row.FfufOnly = append(row.FfufOnly, u)
		}
	}
	sort.Strings(row.FfufOnly)
	sort.Strings(row.AzhaqOnly)
	note := fmt.Sprintf("%s; hits azhaq %d, ffuf %d, shared %d; %d words, %d apps; %s; ffuf only %v", share(row.Shared, row.FfufHits), row.AzhaqHits, row.FfufHits,
		row.Shared, row.Words, len(apps), ratio(row.AzhaqSecs, row.FfufSecs), clipList(row.FfufOnly, 6)) + azBad + downNote(appRestarts-downs0)
	barOne("dirs", azOK, ffOK, row.AzhaqSecs, row.FfufSecs, "a request that is not the app's catch-all answer", azCmd+" vs "+ffCmd, note)
	addCheck("dirs: no more false positives than ffuf", row.AzhaqFalse <= row.FfufFalse,
		"hits that answer like a missing path: azhaq %d, ffuf %d", row.AzhaqFalse, row.FfufFalse)
	return row
}

// firstField is the URL of a result line (azhaq dirs prints more after it).
func firstField(l string) string {
	if f := strings.Fields(l); len(f) > 0 {
		return f[0]
	}
	return l
}

func clipList(xs []string, n int) string {
	if len(xs) <= n {
		return fmt.Sprint(xs)
	}
	return fmt.Sprintf("%v … %d more", xs[:n], len(xs)-n)
}

// softHit is true when u answers exactly like a sibling path that cannot
// exist: same status and the same body once each path is removed from it.
func softHit(u string) bool {
	st, body := getBody(u)
	dir := strings.TrimSuffix(u, path.Base(strings.TrimSuffix(u, "/")))
	missing := "azhaqbenchmissing" + hex.EncodeToString(randBytes(4))
	st2, body2 := getBody(dir + missing)
	if st != st2 {
		return false
	}
	strip := func(b []byte, p string) string { return strings.ReplaceAll(string(b), p, "") }
	return hashOf(strip(body, path.Base(strings.TrimSuffix(u, "/")))) == hashOf(strip(body2, missing))
}

func getBody(u string) (int, []byte) {
	cli := &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := cli.Get(u)
	if err != nil {
		return 0, nil
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	return resp.StatusCode, b
}

func hashOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func readFile(p string) ([]byte, error) { return os.ReadFile(p) }

func randBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}
