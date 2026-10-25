package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// secretsRow compares credentials found in scripts with jsluice secrets,
// on a page whose script has planted, fake values of known formats
// (bench/truth/secrets.js): the bench apps carry none.
type secretsRow struct {
	Azhaq   int `json:"azhaq"`
	Jsluice int `json:"jsluice"`
	Shared  int `json:"shared"`
}

func benchSecrets() *secretsRow {
	raw, err := os.ReadFile("bench/truth/secrets.js")
	must(err)
	script := bytes.ReplaceAll(raw, []byte("@@"), nil) // the split that keeps secret scanners off the fixture
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	must(err)
	defer ln.Close()
	site := "http://" + ln.Addr().String() + "/"
	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/app.js" {
			w.Header().Set("Content-Type", "application/javascript")
			w.Write(script)
			return
		}
		fmt.Fprint(w, `<html><title>secrets</title><script src="/app.js"></script></html>`)
	}))
	dir, _ := filepath.Abs(filepath.Join(work, "secrets"))
	must(os.MkdirAll(dir, 0o755))
	plain := filepath.Join(dir, "app.js")
	must(os.WriteFile(plain, script, 0o644))
	db := filepath.Join(dir, "secrets-"+time.Now().Format("150405")+".db")
	run("secrets", 5*time.Minute, dir, azhaq, "run", "-url", site, "-db", db, "-quiet")
	out, _ := runOut(azhaq, "export", "-db", db, "-format", "secrets")
	az := map[string]bool{}
	for _, l := range lines(out) {
		if f := strings.Split(l, "\t"); len(f) >= 3 {
			az[f[2]] = true
		}
	}
	out, _ = run("secrets", time.Minute, dir, ref("jsluice"), "secrets", plain)
	js := map[string]bool{}
	for _, l := range lines(out) {
		var f struct {
			Data map[string]any `json:"data"`
		}
		if json.Unmarshal([]byte(l), &f) != nil {
			continue
		}
		for _, k := range []string{"key", "secret"} {
			if v, ok := f.Data[k].(string); ok {
				js[v] = true
			}
		}
	}
	row := &secretsRow{Azhaq: len(az), Jsluice: len(js), Shared: overlap(js, az)}
	addCheck("secrets: everything jsluice finds in the planted script, and more", row.Jsluice > 0 && row.Shared == row.Jsluice && row.Azhaq > row.Jsluice,
		"azhaq %d values, jsluice %d, shared %d", row.Azhaq, row.Jsluice, row.Shared)
	return row
}
