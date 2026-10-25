package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"path"
	"strings"
	"time"
)

// dirsRow compares the path sweep with ffuf -ac on the local apps, with
// the same wordlist and rate.
type dirsRow struct {
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
}

const dirsRate = "300"

func benchDirs(apps []string) *dirsRow {
	words, err := fetchWordlist(webWords)
	must(err)
	row := &dirsRow{Words: len(lines(must1(readFile(words)))), Apps: apps}
	az, ff := map[string]bool{}, map[string]bool{}
	for _, app := range apps {
		out, m := run(app, 20*time.Minute, work, azhaq, "dirs", "-u", app, "-w", words, "-rate", dirsRate, "-silent")
		row.AzhaqSecs += m.Seconds
		for _, l := range lines(out) {
			az[l] = true
		}
		out, m = run(app, 20*time.Minute, work, ref("ffuf"), "-u", app+"FUZZ", "-w", words, "-ac", "-rate", dirsRate, "-s")
		row.FfufSecs += m.Seconds
		for _, l := range lines(out) {
			ff[app+l] = true
		}
	}
	row.AzhaqHits, row.FfufHits, row.Shared = len(az), len(ff), overlap(az, ff)
	for u := range az {
		if softHit(u) {
			row.AzhaqFalse++
		}
	}
	for u := range ff {
		if softHit(u) {
			row.FfufFalse++
		}
		if !az[u] {
			row.FfufOnly = append(row.FfufOnly, u)
		}
	}
	addCheck("dirs: ≥ 95% of ffuf -ac's hits, same wordlist and rate", row.FfufHits > 0 && float64(row.Shared) >= 0.95*float64(row.FfufHits),
		"azhaq %d, ffuf %d, shared %d (%d words, %d apps)", row.AzhaqHits, row.FfufHits, row.Shared, row.Words, len(apps))
	addCheck("dirs: no more false positives than ffuf", row.AzhaqFalse <= row.FfufFalse,
		"hits that answer like a missing path: azhaq %d, ffuf %d", row.AzhaqFalse, row.FfufFalse)
	return row
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
