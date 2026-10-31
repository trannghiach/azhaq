package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/trannghiach/azhaq/internal/hunt"
)

// hunt weighs the roles verdicts by their text; the text lives here.
func TestHuntKnowsTheRolesVerdicts(t *testing.T) {
	for _, v := range []string{verdictCross, verdictAnyoneSecrets, verdictWriteCross, verdictWriteAnyone, verdictWriteUnread} {
		rows, err := hunt.ReadRoles(strings.NewReader(`{"url":"http://t/x","verdict":"` + v + `"}`))
		if err != nil || len(rows) != 1 {
			t.Fatal(err)
		}
		if got := hunt.Build(hunt.Input{Roles: rows}); len(got) != 1 || got[0].Score < 90 {
			t.Errorf("verdict %q does not rank: %+v", v, got)
		}
	}
}

func TestHuntFlags(t *testing.T) {
	if err := cmdHunt([]string{"-db", t.TempDir() + "/none.db", "-limit", "0"}); err == nil {
		t.Error("-limit 0 is a usage error")
	}
	if err := cmdHunt([]string{"-db", t.TempDir() + "/none.db", "-roles", "/nonexistent/roles.jsonl"}); err == nil {
		t.Error("a missing -roles file is an error")
	}
}

// The next line of a cross-role row is a command to paste: the roles run's
// directory, from the row, from the folder of the -roles file, or from the
// newest azhaq-roles-* folder; never a placeholder.
func TestHuntNextNamesTheRolesDirectory(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><title>x</title></html>"))
	}))
	defer srv.Close()
	work := t.TempDir()
	t.Chdir(work)
	db := filepath.Join(work, "w.db")
	if _, _, err := captureBoth(t, func() error { return cmdRun([]string{"-url", srv.URL + "/", "-db", db, "-json"}) }); err != nil && exitCode(err) != exitPartial {
		t.Fatal(err)
	}
	row := func(path, dir string) string {
		d := ""
		if dir != "" {
			d = `,"dir":"` + dir + `"`
		}
		return `{"url":"` + srv.URL + path + `","verdict":"reads another role's object","confidence":"proved"` + d + "}\n"
	}
	nextOf := func(file string) string {
		out, _, err := captureBoth(t, func() error { return cmdHunt([]string{"-db", db, "-roles", file, "-json"}) })
		if err != nil {
			t.Fatal(err)
		}
		var r struct{ Next string }
		if err := json.Unmarshal([]byte(strings.SplitN(out, "\n", 2)[0]), &r); err != nil {
			t.Fatalf("%v: %q", err, out)
		}
		return r.Next
	}
	write := func(name, body string) string {
		if err := os.WriteFile(name, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return name
	}
	// A row that names its directory.
	if n := nextOf(write("rows.jsonl", row("/basket/mine", "/runs/azhaq-roles-1"))); !strings.Contains(n, "azhaq roles show -dir /runs/azhaq-roles-1 ") {
		t.Errorf("row's dir: %q", n)
	}
	// An older roles output: the folder of the file holds roles.db.
	if err := os.MkdirAll("mine", 0o755); err != nil {
		t.Fatal(err)
	}
	write(filepath.Join("mine", "roles.db"), "")
	n := nextOf(write(filepath.Join("mine", "rows.jsonl"), row("/basket/mine", "")))
	if want := filepath.Join(work, "mine"); !strings.Contains(n, "azhaq roles show -dir "+want+" ") {
		t.Errorf("file's folder: %q, want %s", n, want)
	}
	// Else the newest of the default names.
	for _, d := range []string{"azhaq-roles-20261030-090000", "azhaq-roles-20261031-101500"} {
		os.MkdirAll(d, 0o755)
		write(filepath.Join(d, "roles.db"), "")
	}
	n = nextOf(write("loose.jsonl", row("/basket/mine", "")))
	if want := filepath.Join(work, "azhaq-roles-20261031-101500"); !strings.Contains(n, "azhaq roles show -dir "+want+" ") || strings.Contains(n, "DIR") {
		t.Errorf("newest default: %q", n)
	}
}
