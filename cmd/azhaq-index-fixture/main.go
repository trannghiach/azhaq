// Offline stand-in for a paid internet index. Not shipped inside the azhaq binary.
// Reads seed JSONL on stdin, writes hint/observation JSONL on stdout.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/trannghiach/azhaq/internal/connector"
	"github.com/trannghiach/azhaq/types"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "azhaq-index-fixture: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	data := flag.String("data", os.Getenv("AZHAQ_INDEX"), "local index JSON")
	flag.Parse()
	if *data == "" {
		*data = findIndex()
	}
	idx, err := connector.LoadHostIndex(*data)
	if err != nil {
		return err
	}
	facts, err := connector.ReadJSONL(os.Stdin)
	if err != nil {
		return err
	}
	var seeds []types.Seed
	for _, f := range facts {
		if f.Kind == "seed" && f.Seed != nil {
			seeds = append(seeds, *f.Seed)
		}
	}
	enc := json.NewEncoder(os.Stdout)
	for _, f := range idx.FactsFor(seeds, *data) {
		if err := enc.Encode(f); err != nil {
			return err
		}
	}
	return nil
}

func findIndex() string {
	if v := os.Getenv("AZHAQ_INDEX"); v != "" {
		return v
	}
	var cands []string
	walk := func(start string) {
		dir := start
		for i := 0; i < 8; i++ {
			cands = append(cands, filepath.Join(dir, "fixtures", "index.json"))
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}
	if wd, err := os.Getwd(); err == nil {
		walk(wd)
	}
	if exe, err := os.Executable(); err == nil {
		walk(filepath.Dir(exe))
	}
	for _, c := range cands {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			return c
		}
	}
	return "fixtures/index.json"
}
