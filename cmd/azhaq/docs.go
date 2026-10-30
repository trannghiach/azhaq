package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/trannghiach/azhaq"
	"github.com/trannghiach/azhaq/docs"
)

// topics are the documents azhaq docs prints, in the order it lists them.
var topics = []struct{ name, file, about string }{
	{"readme", "", "what Azhaq does, install, examples, benchmarks"},
	{"recipes", "RECIPES.md", "how do I…: map an app, log in, find IDOR, test writes, map a program, resume, watch, export, GraphQL, MCP, live subdomains"},
	{"concepts", "CONCEPTS.md", "what the words mean: a map row, coverage, kinds, exit codes, roles verdicts, what Azhaq sends"},
	{"troubleshooting", "TROUBLESHOOTING.md", "why is my URL hint, the map looks thin, exit 3, exit 4, Chrome, where is my database"},
	{"output", "OUTPUT.md", "what every command prints: fields, the summary, exit codes"},
	{"mcp", "MCP.md", "serving Azhaq to MCP clients: tools, scope lock, budget"},
	{"connector", "CONNECTOR.md", "feeding other tools' results in: facts and connectors"},
	{"architecture", "ARCHITECTURE.md", "how the engine works: seeds, collectors, the graph"},
}

func cmdDocs(args []string) error {
	fs := newFlags("docs")
	if err := parse(fs, args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		fmt.Println("azhaq docs TOPIC prints one of:")
		for _, t := range topics {
			fmt.Printf("  %-16s %s\n", t.name, t.about)
		}
		return nil
	}
	want := strings.ToLower(strings.TrimSuffix(fs.Arg(0), ".md"))
	for _, t := range topics {
		if t.name != want {
			continue
		}
		if t.file == "" {
			_, err := os.Stdout.WriteString(azhaq.README)
			return err
		}
		raw, err := docs.Files.ReadFile(t.file)
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(raw)
		return err
	}
	return usagef("no topic %q; azhaq docs lists them", fs.Arg(0))
}
