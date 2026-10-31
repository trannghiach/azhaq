package main

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/trannghiach/azhaq"
	"github.com/trannghiach/azhaq/docs"
)

// topics are the documents azhaq docs prints, in the order it lists them.
var topics = []struct{ name, file, about string }{
	{"readme", "", "what Azhaq does, install, examples, benchmarks"},
	{"migrating", "MIGRATING.md", "coming from subfinder, dnsx, httpx, katana, ffuf, gau, arjun, naabu, nmap, gowitness, asnmap or notify: their flags next to Azhaq's"},
	{"recipes", "RECIPES.md", "how do I…: map an app, log in, find IDOR, test writes, map a program, resume, watch, export, GraphQL, MCP, live subdomains"},
	{"concepts", "CONCEPTS.md", "what the words mean: a map row, coverage, evidence, kinds, scope, budget, the ledger, roles verdicts, what Azhaq sends"},
	{"troubleshooting", "TROUBLESHOOTING.md", "why is my URL hint, the map looks thin, exit 3, exit 4, Chrome, where is my database"},
	{"output", "OUTPUT.md", "what every command prints: the summary, exit codes, the ledger; each command's fields are on its page"},
	{"mcp", "MCP.md", "serving Azhaq to MCP clients: tools, scope lock, budget"},
	{"connector", "CONNECTOR.md", "feeding other tools' results in: facts and connectors"},
	{"architecture", "ARCHITECTURE.md", "how the engine works: seeds, collectors, the graph"},
}

// commandPageName is what a command's name looks like: the pages of docs/commands.
var commandPageName = regexp.MustCompile(`^[a-z][a-z-]*$`)

// docsOverview is what azhaq docs prints before the list of topics.
const docsOverview = `azhaq maps what an application or a bug bounty program exposes, and who may
read and write it. One binary, one SQLite workspace you can query, export and
diff. It stands in for subfinder, dnsx, httpx, katana, ffuf, gau, arjun, naabu,
gowitness, asnmap and notify, with their flags and JSON fields, and adds access
control, scope, a request budget and a ledger of what was sent.

Start with:
  azhaq run -url https://app.example.com/ -db app.db     map a web app or API
  azhaq roles -role anon -role 'u=Authorization: Bearer ...' -- -url URL
                                                         who may read what
  azhaq hunt -db app.db                                  where to look first
  azhaq subs -d example.com -live                        subdomains that resolve
  azhaq probe -l hosts.txt -json                         web services of hosts
  azhaq ports -host HOST -p top-1000                     open ports, named

More: azhaq help all lists every command, azhaq help COMMAND shows its flags
and examples (azhaq help COMMAND all: every flag), azhaq help -json lists them
for a program. Coming from another tool:
azhaq docs migrating has its flags next to Azhaq's.

`

func cmdDocs(args []string) error {
	fs := newFlags("docs")
	flagsCmd := fs.String("flags", "", "print the Markdown table of the flags of this command, made from the data help -json lists")
	flagsInto := fs.String("flags-into", "", "rewrite the flag table of each NAME.md page in this directory, between its flags:begin and flags:end markers (go run ./cmd/azhaq docs -flags-into docs/commands)")
	if err := parse(fs, args); err != nil {
		return err
	}
	if *flagsCmd != "" || *flagsInto != "" {
		if fs.NArg() > 0 || *flagsCmd != "" && *flagsInto != "" {
			return usagef("-flags and -flags-into take no topic and are not used together")
		}
		if *flagsInto != "" {
			return updateFlagTables(*flagsInto)
		}
		table, err := flagTableMarkdown(*flagsCmd)
		if err != nil {
			return usagef("%v", err)
		}
		_, err = os.Stdout.WriteString(table)
		return err
	}
	if fs.NArg() == 0 {
		fmt.Print(docsOverview)
		fmt.Println("azhaq docs TOPIC prints one of:")
		for _, t := range topics {
			fmt.Printf("  %-16s %s\n", t.name, t.about)
		}
		fmt.Printf("  %-16s %s\n", "COMMAND", "the page of one command: azhaq docs ports (commands/mcp for mcp, which is also a topic)")
		return nil
	}
	want := strings.ToLower(strings.TrimSuffix(fs.Arg(0), ".md"))
	page, onlyCommand := strings.CutPrefix(want, "commands/")
	if onlyCommand {
		want = page
	}
	for _, t := range topics {
		if t.name != want || onlyCommand {
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
	if commandPageName.MatchString(want) {
		if raw, err := docs.Files.ReadFile("commands/" + want + ".md"); err == nil {
			_, err = os.Stdout.Write(raw)
			return err
		}
	}
	return usagef("no topic or command %q; azhaq docs lists them", fs.Arg(0))
}
