package main

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/trannghiach/azhaq/store"
	"github.com/trannghiach/azhaq/types"
)

// A drop-in's target list is a temporary file, gone when azhaq resume
// runs: the workspace's copy stands in for it.
func TestResumeListFromWorkspace(t *testing.T) {
	db := filepath.Join(t.TempDir(), "w.db")
	st, err := store.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetMeta("list:r1", "http://a.test/\nhttp://b.test/"); err != nil {
		t.Fatal(err)
	}
	st.Close()
	got, err := listFromWorkspace(db, "r1", []string{"-list=/tmp/azhaq-list-gone", "-dirs", "words.txt"})
	if err != nil || !reflect.DeepEqual(got, []string{"-list=@run", "-dirs", "words.txt"}) || !reflect.DeepEqual(storedList, []string{"http://a.test/", "http://b.test/"}) {
		t.Fatalf("%q %v, list %q", got, err, storedList)
	}
	seeds, _, err := loadList("@run")
	if err != nil || len(seeds) != 2 {
		t.Fatalf("seeds %v %v", seeds, err)
	}
	if _, err := listFromWorkspace(db, "r2", []string{"-list", "-"}); err == nil {
		t.Error("a list neither on disk nor in the workspace resumed")
	}
	if got := keptArgs([]string{"-list", "-"}); !reflect.DeepEqual(got, []string{"-list=-"}) {
		t.Errorf("stdin list kept as %q", got)
	}
	// A list file changed since: the run continues the targets it began with.
	changed := filepath.Join(t.TempDir(), "t.txt")
	if err := os.WriteFile(changed, []byte("http://evil.test/\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	storedList = nil
	got, err = listFromWorkspace(db, "r1", []string{"-list", changed})
	if err != nil || !reflect.DeepEqual(got, []string{"-list", "@run"}) || len(storedList) != 2 {
		t.Errorf("changed file: %q %v, list %q", got, err, storedList)
	}
	// Files are kept absolute: azhaq resume may run from elsewhere.
	if got := keptArgs([]string{"-dirs", "words.txt", "-screenshots=shots"}); !filepath.IsAbs(strings.TrimPrefix(got[0], "-dirs=")) || !filepath.IsAbs(strings.TrimPrefix(got[1], "-screenshots=")) {
		t.Errorf("relative files kept as %q", got)
	}
}

func TestStreamFound(t *testing.T) {
	out, _, err := captureBoth(t, func() error {
		see := streamFound(false)
		for _, p := range []string{`{"url":"http://a.test/x"}`, `{"url":"http://a.test/x"}`} {
			see(types.Entity{}, types.Observation{Kind: "url", Payload: []byte(p)})
		}
		see(types.Entity{}, types.Observation{Kind: "application", Payload: []byte(`{"url":"http://a.test/","status":200,"title":"Home"}`)})
		see(types.Entity{}, types.Observation{Kind: "dns", Payload: []byte(`{"fqdn":"w.a.test","ips":["192.0.2.1"],"wildcard":true}`)})
		return nil
	})
	want := "found  url     http://a.test/x\nfound  answer  http://a.test/  [200] Home\n"
	if err != nil || out != want {
		t.Errorf("%q, want %q", out, want)
	}
}

// A run stored with the options that held GETs back by name goes on
// without them, and the resume says so.
func TestResumeDropsRemovedFlags(t *testing.T) {
	got, gone := dropRemovedFlags([]string{"-url", "https://app.test/", "-all-gets", "-get-words", "exec,import", "-depth=2", "--get-words=x", "-all-gets=true", "-skip", "azhaq-dns"})
	want := []string{"-url", "https://app.test/", "-depth=2", "-skip", "azhaq-dns"}
	if !slices.Equal(got, want) {
		t.Errorf("args %q, want %q", got, want)
	}
	if !slices.Equal(gone, []string{"-all-gets", "-get-words", "-get-words", "-all-gets"}) {
		t.Errorf("gone %q", gone)
	}
}
