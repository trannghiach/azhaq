package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/trannghiach/azhaq/engine"
	"github.com/trannghiach/azhaq/store"
	"github.com/trannghiach/azhaq/types"
)

func TestRunParamsKeepsWhatParamsFinds(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Has("q") {
			fmt.Fprint(w, `{"status":"success","data":[`+strings.Repeat(`{"id":1,"name":"Apple Juice","price":1.99},`, 40)+`{"id":2}]}`)
			return
		}
		fmt.Fprint(w, `{"status":"success","data":[]}`)
	}))
	defer srv.Close()
	dir := t.TempDir()
	words := filepath.Join(dir, "q.txt")
	var ws []string
	for i := 0; i < 20; i++ {
		ws = append(ws, fmt.Sprintf("word%d", i))
	}
	ws = append(ws, "q")
	os.WriteFile(words, []byte(strings.Join(ws, "\n")+"\n"), 0o644)
	db := filepath.Join(dir, "r.db")
	_, rep, code := runContract(t, "run", "-url", srv.URL+"/rest/products/search", "-params", words, "-no-paths", "-depth", "0", "-max-requests", "35", "-timeout", "15s", "-db", db)
	if code != exitOK {
		t.Fatalf("exit %d, notes %q", code, rep.Notes)
	}
	st, err := store.OpenExisting(db)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ents, _ := st.Entities()
	obs, _ := st.Observations()
	seed := types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/rest/products/search"}}
	var got []string
	for _, r := range engine.BuildMap(ents, []types.Seed{seed}, obs, nil, false) {
		if strings.HasSuffix(r.Entity.Key, "/rest/products/search") {
			got = r.Params
		}
	}
	if len(got) != 1 || got[0] != "q" {
		t.Errorf("the map row's params %v, want [q]: what -params found is lost", got)
	}
}
