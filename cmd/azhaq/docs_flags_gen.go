package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// The flag tables of docs/commands/NAME.md are made from the flag sets
// help -json lists, so a page cannot say a flag the binary does not have.
// A page holds one between these markers, and azhaq docs -flags-into
// rewrites what is between them.
const (
	flagsBegin = "<!-- flags:begin "
	flagsEnd   = "<!-- flags:end -->"
)

var flagsBlock = regexp.MustCompile(`(?s)<!-- flags:begin ([^>]*?) -->\n.*?` + regexp.QuoteMeta(flagsEnd))

// tableFlags are the flags a flags block of that name lists: a command's, or
// those of roles show, which help -json holds under no command of its own.
func tableFlags(name string) ([]flagInfo, error) {
	if name == "roles show" {
		return flagInfos(describe(cmdRolesShow)), nil
	}
	if _, ok := lookup(name); !ok {
		return nil, fmt.Errorf("no command %q; azhaq help lists them", name)
	}
	return flagInfos(flagsOf(name)), nil
}

// tableCell makes text safe for a cell of a Markdown table.
func tableCell(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	return strings.ReplaceAll(s, "|", `\|`)
}

// flagTableMarkdown is the Markdown table of one command's flags: a row for
// each, in the order help lists them, a repeatable one marked in its type.
func flagTableMarkdown(name string) (string, error) {
	infos, err := tableFlags(name)
	if err != nil {
		return "", err
	}
	if len(infos) == 0 {
		if name == "resume" {
			return "`resume` takes the flags of [`run`](run.md#flags): the run's flags are read back from the database; flags given here are added and win.\n", nil
		}
		return "`" + name + "` takes no flags.\n", nil
	}
	var b strings.Builder
	b.WriteString("| Flag | Type | Default | Meaning |\n| --- | --- | --- | --- |\n")
	for _, f := range infos {
		typ := f.Type
		if f.Repeatable {
			typ += ", repeatable"
		}
		def := ""
		if f.Default != "" {
			def = "`" + tableCell(f.Default) + "`"
		}
		fmt.Fprintf(&b, "| `-%s` | %s | %s | %s |\n", f.Name, typ, def, tableCell(f.Usage))
	}
	return b.String(), nil
}

// rewriteFlagBlocks puts the current table between each pair of markers of
// a page. A block that names no command, or has no end marker, is an error.
func rewriteFlagBlocks(text string) (string, error) {
	if n, m := strings.Count(text, flagsBegin), len(flagsBlock.FindAllString(text, -1)); n != m {
		return "", fmt.Errorf("a %q marker has no %q after it", strings.TrimSpace(flagsBegin), flagsEnd)
	}
	var out strings.Builder
	last := 0
	for _, m := range flagsBlock.FindAllStringSubmatchIndex(text, -1) {
		name := strings.TrimSpace(text[m[2]:m[3]])
		table, err := flagTableMarkdown(name)
		if err != nil {
			return "", err
		}
		out.WriteString(text[last:m[0]])
		out.WriteString(flagsBegin + name + " -->\n" + table + flagsEnd)
		last = m[1]
	}
	out.WriteString(text[last:])
	return out.String(), nil
}

// updateFlagTables rewrites the flag tables of every page in dir and names
// the pages it changed on stderr.
func updateFlagTables(dir string) error {
	pages, err := filepath.Glob(filepath.Join(dir, "*.md"))
	if err != nil {
		return err
	}
	if len(pages) == 0 {
		return fmt.Errorf("no .md page in %s", dir)
	}
	for _, p := range pages {
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		text, err := rewriteFlagBlocks(string(raw))
		if err != nil {
			return fmt.Errorf("%s: %v", p, err)
		}
		if text == string(raw) {
			continue
		}
		if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "azhaq docs: updated %s\n", p)
	}
	return nil
}
