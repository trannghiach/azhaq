package main

import (
	"path/filepath"
	"reflect"
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
