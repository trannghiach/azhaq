package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A drop-in command's resume says which command it resumed, and prints the
// rows the run found (the map's, as run prints them).
func TestResumeNamesTheDropInCommand(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html><title>"+r.URL.Path+"</title></html>")
	}))
	defer srv.Close()
	dir := t.TempDir()
	list := filepath.Join(dir, "t.txt")
	var urls []string
	for _, p := range []string{"a", "b", "c", "d"} {
		urls = append(urls, srv.URL+"/"+p)
	}
	if err := os.WriteFile(list, []byte(strings.Join(urls, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	db := filepath.Join(dir, "p.db")
	_, errOut, err := captureBoth(t, func() error {
		return cmdProbe([]string{"-l", list, "-db", db, "-max-requests", "2", "-json", "-ledger", "off", "-allow", "127.0.0.1"})
	})
	if exitCode(err) != exitLimit {
		t.Fatalf("probe: exit %d\n%s", exitCode(err), errOut)
	}
	out, errOut, err := captureBoth(t, func() error { return cmdResume([]string{"-db", db, "-json"}) })
	if err != nil {
		t.Fatalf("resume: %v\n%s", err, errOut)
	}
	rep := lastReport(t, errOut)
	if rep.Command != "probe" || rep.Results != len(lines(out)) || rep.Results == 0 {
		t.Errorf("the summary says command %q, %d results, %d rows printed", rep.Command, rep.Results, len(lines(out)))
	}
	for _, u := range urls {
		if !strings.Contains(out, `"key":"`+u+`"`) {
			t.Errorf("no row for %s:\n%s", u, out)
		}
	}
	if !strings.Contains(strings.Join(rep.Notes, "\n"), "a resumed probe run prints the rows of the map") {
		t.Errorf("no note says what the rows are: %v", rep.Notes)
	}
}
