package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// A path a -dirs sweep asked and the server answered is a requested row:
// "capped" is for work a limit kept from being sent, and none was hit.
func TestRunDirsRowsAreNotCappedWhenNoLimitWasHit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/":
			fmt.Fprint(w, "<html><title>home</title></html>")
		case "/rest", "/assets", "/login":
			fmt.Fprintf(w, "<html><title>%s</title>found</html>", r.URL.Path)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	t.Chdir(t.TempDir())
	out, errOut, code := cli(t, "run", "-url", srv.URL+"/", "-dirs", wlist(t, "rest", "assets", "login", "nothere"), "-dirs-ac=false",
		"-dirs-mc", "all", "-no-paths", "-depth", "0", "-no-favicon", "-allow", "127.0.0.1", "-json")
	if code != exitOK {
		t.Fatalf("exit %d\n%s", code, errOut)
	}
	seen := 0
	for _, r := range jsonRows(t, out) {
		u, _ := r["key"].(string)
		if u == srv.URL+"/" || r["type"] != "URL" {
			continue
		}
		seen++
		want := "visited"
		if u == srv.URL+"/nothere" {
			want = "gone" // asked, and the server says it is not there
		}
		if r["coverage"] != want {
			t.Errorf("%s was requested and answered %v: coverage %v, want %s", u, r["status"], r["coverage"], want)
		}
		if r["status"] == nil {
			t.Errorf("%s has no status, though the sweep read one", u)
		}
	}
	if seen < 3 {
		t.Errorf("%d rows besides the front page, want the paths found:\n%s", seen, out)
	}
}
