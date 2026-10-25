package engine_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/trannghiach/azhaq/catalog"
	"github.com/trannghiach/azhaq/collectors"
	"github.com/trannghiach/azhaq/engine"
	"github.com/trannghiach/azhaq/store"
	"github.com/trannghiach/azhaq/types"
)

// Map a domain passively from a program of your own.
func Example() {
	dir, _ := os.MkdirTemp("", "azhaq")
	defer os.RemoveAll(dir)
	st, err := store.Open(filepath.Join(dir, "example.db"))
	if err != nil {
		panic(err)
	}
	defer st.Close()

	cat := catalog.New()
	collectors.RegisterAll(cat, nil)
	eng := &engine.Engine{Cat: cat, Store: st}

	budgets := engine.DefaultBudgets()
	budgets.Passive = true // third-party sources and DNS only
	seeds := []types.Seed{{Type: types.TypeDomain, Keys: map[string]string{"domain": "example.test"}}}
	if err := eng.RunLocal(context.Background(), seeds, budgets); err != nil {
		panic(err)
	}
	ents, _ := st.Entities()
	fmt.Println(len(ents) > 0)
	// Output: true
}
