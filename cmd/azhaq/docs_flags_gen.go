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
	return commandFlags(name), nil
}

// tableCell makes text safe for a cell of a Markdown table.
func tableCell(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	return strings.ReplaceAll(s, "|", `\|`)
}

// flagRows is the Markdown table of flags: a row for each, a repeatable one
// marked in its type. kind adds a column that says why a flag is hidden.
func flagRows(infos []flagInfo, kind func(flagInfo) string) string {
	var b strings.Builder
	if kind == nil {
		b.WriteString("| Flag | Type | Default | Meaning |\n| --- | --- | --- | --- |\n")
	} else {
		b.WriteString("| Flag | Type | Default | Meaning | Kind |\n| --- | --- | --- | --- | --- |\n")
	}
	for _, f := range infos {
		typ := f.Type
		if f.Repeatable {
			typ += ", repeatable"
		}
		def := ""
		if f.Default != "" {
			def = "`" + tableCell(f.Default) + "`"
		}
		fmt.Fprintf(&b, "| `-%s` | %s | %s | %s |", f.Name, typ, def, tableCell(f.Usage))
		if kind != nil {
			fmt.Fprintf(&b, " %s |", kind(f))
		}
		b.WriteString("\n")
	}
	return b.String()
}

// hiddenKind is how a hidden flag's reason reads in a table.
func hiddenKind(f flagInfo) string {
	switch why := f.Why; {
	case strings.HasPrefix(why, "compat:"):
		return strings.TrimPrefix(why, "compat:") + "'s name"
	case why == whyAlias:
		return "other name"
	case why == whyAccepted:
		return "accepted, no effect"
	}
	return "rarely needed"
}

// hiddenSummary heads the folded table of the hidden flags: what they are,
// and how many.
func hiddenSummary(l helpLayout) string {
	var parts []string
	for _, h := range l.hidden {
		switch {
		case strings.HasPrefix(h.why, "compat:"):
			parts = append(parts, "flags familiar from "+strings.TrimPrefix(h.why, "compat:"))
		case h.why == whyAlias:
			parts = append(parts, "other names")
		case h.why == whyAccepted:
			parts = append(parts, "flags accepted with no effect")
		default:
			parts = append(parts, "rarely used flags")
		}
	}
	text := strings.Join(parts, ", ")
	if i := strings.LastIndex(text, ", "); i >= 0 {
		text = text[:i] + " and " + text[i+2:]
	}
	return fmt.Sprintf("%s (%d)", strings.ToUpper(text[:1])+text[1:], l.hiddenCount())
}

// flagTableMarkdown is the Markdown of one command's flags: the shown ones
// in a table under each task heading, in the order -h prints them, and the
// hidden ones in a folded second table.
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
	l := layoutFlags(name, infos)
	var b strings.Builder
	for i, s := range l.shown {
		if i > 0 {
			b.WriteString("\n")
		}
		if s.title != "" {
			fmt.Fprintf(&b, "**%s**\n\n", s.title)
		}
		b.WriteString(flagRows(s.flags, nil))
	}
	if len(l.hidden) > 0 {
		var hidden []flagInfo
		for _, h := range l.hidden {
			hidden = append(hidden, h.flags...)
		}
		fmt.Fprintf(&b, "\n<details>\n<summary>%s</summary>\n\n%s\n</details>\n", hiddenSummary(l), flagRows(hidden, hiddenKind))
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
