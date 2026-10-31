package main

import (
	"os"
	"strings"
	"testing"
)

// The lists the docs give must hold every value the code has: a state or
// verdict a user meets in the output is one they can look up.
func TestDocsListTheCodesValues(t *testing.T) {
	read := func(p string) string {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	readme, concepts := read("../../README.md"), read("../../docs/CONCEPTS.md")
	runPage, rolesPage := read("../../docs/commands/run.md"), read("../../docs/commands/roles.md")
	for _, c := range []string{"visited", "catchall", "error", "gone", "hint", "skipped", "capped"} {
		for name, doc := range map[string]string{"README.md": readme, "CONCEPTS.md": concepts, "commands/run.md": runPage} {
			if !strings.Contains(doc, "`"+c+"`") {
				t.Errorf("%s does not say what coverage %q means", name, c)
			}
		}
		if fs := flagsOf("query"); fs == nil || !strings.Contains(fs.Lookup("coverage").Usage, c) {
			t.Errorf("query -coverage help leaves out %q", c)
		}
	}
	for v := range verdictOrder {
		if !strings.Contains(rolesPage, v) {
			t.Errorf("commands/roles.md does not list the roles verdict %q", v)
		}
	}
}
