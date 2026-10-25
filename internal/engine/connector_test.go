package engine_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/trannghiach/azhaq/internal/catalog"
	"github.com/trannghiach/azhaq/internal/collectors/fake"
	"github.com/trannghiach/azhaq/internal/connector"
	"github.com/trannghiach/azhaq/internal/engine"
	"github.com/trannghiach/azhaq/internal/store"
	"github.com/trannghiach/azhaq/internal/types"
)

func TestIngestFile(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	eng := &engine.Engine{Store: st}
	facts, err := connector.ReadFile(filepath.Join("..", "..", "fixtures", "facts.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	hints, err := eng.Ingest(context.Background(), facts)
	if err != nil {
		t.Fatal(err)
	}
	if !hasTypeKey(st, types.TypeHostname, "api.example.test") {
		ents, _ := st.Entities()
		t.Fatalf("ingested hostname missing: %+v", ents)
	}
	if len(hints) == 0 {
		t.Fatal("want hints from ingest")
	}
	obs, _ := st.Observations()
	if len(obs) == 0 {
		t.Fatal("want observations from ingest")
	}
}

func TestExecThenNative(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	cat := catalog.New()
	fake.Register(cat, "www.example.test")
	eng := &engine.Engine{Cat: cat, Store: st}

	script := `echo '{"kind":"hint","seed":{"type":"Domain","keys":{"domain":"example.test"}}}'`
	facts, err := connector.Exec(context.Background(), []string{"/bin/sh", "-c", script}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hints, err := eng.Ingest(context.Background(), facts)
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.RunLocal(context.Background(), hints, engine.Budgets{MaxDepth: 2, MaxItems: 16}); err != nil {
		t.Fatal(err)
	}
	obs, _ := st.Observations()
	for _, o := range obs {
		if o.Collector == "azhaq-fake" {
			return
		}
	}
	t.Fatalf("connector hint did not reach native collector: ents/obs=%v", obs)
}
