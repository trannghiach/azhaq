package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The tables of a command have one row for each flag help -json lists, in
// the shown tables or the folded one of the hidden flags, a repeatable flag
// marked in its type, and a | in a usage text escaped.
func TestFlagTableHasOneRowPerFlag(t *testing.T) {
	for _, c := range buildManifest().Commands {
		if len(c.Flags) == 0 {
			continue
		}
		table, err := flagTableMarkdown(c.Name)
		if err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		rows := map[string]string{}
		for _, l := range strings.Split(table, "\n") {
			if strings.HasPrefix(l, "| `-") {
				rest := strings.TrimPrefix(l, "| `-")
				name := rest[:strings.Index(rest, "`")]
				if _, dup := rows[name]; dup {
					t.Errorf("%s: two rows for -%s", c.Name, name)
				}
				rows[name] = l
			}
		}
		if len(rows) != len(c.Flags) {
			t.Errorf("%s: %d rows, want %d (one for each flag)", c.Name, len(rows), len(c.Flags))
		}
		for _, f := range c.Flags {
			row := rows[f.Name]
			switch {
			case row == "":
				t.Errorf("%s: no row for -%s", c.Name, f.Name)
			case f.Repeatable && !strings.Contains(row, "repeatable"):
				t.Errorf("%s: -%s is repeatable and the row does not say so: %s", c.Name, f.Name, row)
			case f.Default != "" && !strings.Contains(row, "`"+tableCell(f.Default)+"`"):
				t.Errorf("%s: the row of -%s leaves out its default %q: %s", c.Name, f.Name, f.Default, row)
			}
		}
		// Hidden flags are in the folded table, shown ones above it.
		folded := table[max(strings.Index(table, "<details>"), 0):]
		if strings.Contains(table, "<details>") != (hiddenCountOf(c.Flags) > 0) {
			t.Errorf("%s: a folded table of hidden flags where none are hidden, or none where some are", c.Name)
		}
		for _, f := range c.Flags {
			inFolded := strings.Contains(folded, "| `-"+f.Name+"` |") && strings.Contains(table, "<details>")
			if inFolded != f.Hidden {
				t.Errorf("%s: -%s hidden=%v but its row is in the folded table: %v", c.Name, f.Name, f.Hidden, inFolded)
			}
		}
	}
	table, err := flagTableMarkdown("probe")
	if err != nil {
		t.Fatal(err)
	}
	shown, folded, _ := strings.Cut(table, "<details>")
	for part, pipes := range map[string]int{shown: 5, folded: 6} {
		for _, l := range strings.Split(part, "\n") {
			if strings.HasPrefix(l, "| `-") && strings.Count(strings.ReplaceAll(l, `\|`, ""), "|") != pipes {
				t.Errorf("a row with a cell split by a pipe (want %d pipes): %s", pipes, l)
			}
		}
	}
}

func hiddenCountOf(flags []flagInfo) int {
	n := 0
	for _, f := range flags {
		if f.Hidden {
			n++
		}
	}
	return n
}

// roles show takes flags of its own that help -json lists under no
// command, and a command with none says so.
func TestFlagTableOfRolesShowAndOfACommandWithoutFlags(t *testing.T) {
	table, err := flagTableMarkdown("roles show")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"-dir", "-method", "-body", "-json"} {
		if !strings.Contains(table, "| `"+f+"` |") {
			t.Errorf("roles show: no row for %s", f)
		}
	}
	table, err = flagTableMarkdown("resume")
	if err != nil || !strings.Contains(table, "run.md#flags") {
		t.Errorf("resume: %q, %v", table, err)
	}
	if _, err := flagTableMarkdown("nonesuch"); err == nil {
		t.Error("a command that does not exist has a table")
	}
}

// The blocks between the markers are rewritten, the text around them is
// kept, a second rewrite changes nothing, and a block that cannot be
// rewritten is an error.
func TestRewriteFlagBlocks(t *testing.T) {
	page := "# azhaq scope\n\ntext before\n\n" + flagsBegin + "scope -->\nold\n" + flagsEnd + "\n\ntext after\n"
	out, err := rewriteFlagBlocks(page)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := flagTableMarkdown("scope")
	if !strings.Contains(out, flagsBegin+"scope -->\n"+want+flagsEnd+"\n\ntext after\n") || !strings.HasPrefix(out, "# azhaq scope\n\ntext before\n\n") {
		t.Errorf("the block was not rewritten in place:\n%s", out)
	}
	again, err := rewriteFlagBlocks(out)
	if err != nil || again != out {
		t.Errorf("a second rewrite changed the page: %v", err)
	}
	for _, bad := range []string{
		flagsBegin + "nonesuch -->\n" + flagsEnd,
		flagsBegin + "scope -->\nno end marker",
	} {
		if _, err := rewriteFlagBlocks(bad); err == nil {
			t.Errorf("no error for %q", bad)
		}
	}
}

// docs -flags prints the table, and -flags-into rewrites the pages of a
// directory.
func TestDocsFlagsCommands(t *testing.T) {
	out, err := captureStdout(t, func() error { return cmdDocs([]string{"-flags", "scope"}) })
	want, _ := flagTableMarkdown("scope")
	if err != nil || out != want {
		t.Errorf("docs -flags scope: %v\n%s", err, out)
	}
	if err := cmdDocs([]string{"-flags", "nonesuch"}); exitCode(err) != exitUsage {
		t.Errorf("docs -flags nonesuch: %v", err)
	}
	if err := cmdDocs([]string{"-flags", "scope", "-flags-into", "x"}); exitCode(err) != exitUsage {
		t.Errorf("both flags: %v", err)
	}
	dir := t.TempDir()
	page := filepath.Join(dir, "scope.md")
	if err := os.WriteFile(page, []byte("# azhaq scope\n"+flagsBegin+"scope -->\nstale\n"+flagsEnd+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := cmdDocs([]string{"-flags-into", dir}); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(page)
	if !strings.Contains(string(raw), want) || strings.Contains(string(raw), "stale") {
		t.Errorf("the page was not rewritten:\n%s", raw)
	}
	if err := cmdDocs([]string{"-flags-into", t.TempDir()}); err == nil {
		t.Error("a directory with no page is not an error")
	}
}
