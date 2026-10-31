package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/trannghiach/azhaq/docs"
)

// docs/commands holds one page for each command, and the page's flag table
// is the one the binary makes: go generate ./docs rewrites it.

// noPage are the commands without a page: help and version say all there is
// to say, and bench is a self-test.
var noPage = map[string]bool{"help": true, "version": true, "bench": true}

// commandPages are the files of docs/commands.
func commandPages() []string {
	files, _ := filepath.Glob("../../docs/commands/*.md")
	return files
}

func TestEveryCommandHasAPage(t *testing.T) {
	want := map[string]bool{}
	for _, c := range buildManifest().Commands {
		if noPage[c.Name] {
			continue
		}
		want[c.Name] = true
		file := "../../docs/commands/" + c.Name + ".md"
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Errorf("azhaq %s has no page: write docs/commands/%s.md (a title, ## Synopsis and a flags block)", c.Name, c.Name)
			continue
		}
		page := string(raw)
		if !strings.HasPrefix(page, "# azhaq "+c.Name+"\n") {
			t.Errorf("%s does not start with the title '# azhaq %s'", file, c.Name)
		}
		for _, h := range []string{"\n## Synopsis\n", "\n## Flags\n", flagsBegin + c.Name + " -->\n", "\n" + flagsEnd} {
			if !strings.Contains(page, h) {
				t.Errorf("%s has no %q", file, strings.TrimSpace(h))
			}
		}
	}
	for _, p := range commandPages() {
		if name := strings.TrimSuffix(filepath.Base(p), ".md"); !want[name] {
			t.Errorf("%s is the page of no command help -json lists", p)
		}
	}
	if len(want) < 30 {
		t.Errorf("only %d commands need a page", len(want))
	}
}

func TestCommandPagesHoldCurrentFlagTables(t *testing.T) {
	pages := commandPages()
	if len(pages) == 0 {
		t.Fatal("no pages in docs/commands")
	}
	for _, p := range pages {
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		want, err := rewriteFlagBlocks(string(raw))
		if err != nil {
			t.Errorf("%s: %v", p, err)
			continue
		}
		if want != string(raw) {
			t.Errorf("%s: a flags table differs from what the binary makes: run `go generate ./docs` (or `go run ./cmd/azhaq docs -flags-into docs/commands`) and commit it; flags are changed in the code, not in the page", p)
		}
	}
}

// azhaq docs prints the page of a command, and the pages in the binary are
// the ones in the repository.
func TestDocsPrintsACommandPage(t *testing.T) {
	out, err := captureStdout(t, func() error { return cmdDocs([]string{"scope"}) })
	if err != nil || !strings.HasPrefix(out, "# azhaq scope\n") {
		t.Errorf("docs scope: %v\n%.200s", err, out)
	}
	out, err = captureStdout(t, func() error { return cmdDocs([]string{"commands/mcp"}) })
	if err != nil || !strings.HasPrefix(out, "# azhaq mcp\n") {
		t.Errorf("docs commands/mcp: %v\n%.200s", err, out)
	}
	// mcp is a topic too, and the topic comes first.
	out, err = captureStdout(t, func() error { return cmdDocs([]string{"mcp"}) })
	if raw, _ := os.ReadFile("../../docs/MCP.md"); err != nil || out != string(raw) {
		t.Errorf("docs mcp does not print docs/MCP.md: %v", err)
	}
	for _, bad := range []string{"nonesuch", "commands/nonesuch", "../README", "commands/../OUTPUT"} {
		if err := cmdDocs([]string{bad}); exitCode(err) != exitUsage {
			t.Errorf("docs %s: %v", bad, err)
		}
	}
	for _, p := range commandPages() {
		name := filepath.Base(p)
		raw, err := docs.Files.ReadFile("commands/" + name)
		disk, _ := os.ReadFile(p)
		if err != nil || len(raw) == 0 || string(raw) != string(disk) {
			t.Errorf("azhaq docs %s: the embedded page is not %s", strings.TrimSuffix(name, ".md"), p)
		}
	}
}

// A link to a file leads to a file, and a link to a heading to a heading
// that is there: the pages move text between them, and a moved heading
// must not leave a link behind.
func TestDocLinksLeadToHeadings(t *testing.T) {
	files := []string{"../../README.md"}
	more, _ := filepath.Glob("../../docs/*.md")
	files = append(files, more...)
	files = append(files, commandPages()...)
	headings := map[string]map[string]bool{}
	anchorsOf := func(path string) map[string]bool {
		if a, ok := headings[path]; ok {
			return a
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		a := map[string]bool{}
		seen := map[string]int{}
		for _, l := range strings.Split(stripFences(string(raw)), "\n") {
			h := strings.TrimLeft(l, "#")
			if len(l)-len(h) == 0 || len(l)-len(h) > 6 || !strings.HasPrefix(h, " ") {
				continue
			}
			slug := headingSlug(h)
			if n := seen[slug]; n > 0 {
				a[slug+"-"+string(rune('0'+n))] = true
			} else {
				a[slug] = true
			}
			seen[slug]++
		}
		headings[path] = a
		return a
	}
	link := regexp.MustCompile(`\]\(([^)\s]+)\)`)
	code := regexp.MustCompile("`[^`\n]*`")
	n := 0
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		text := code.ReplaceAllString(stripFences(string(raw)), "")
		for _, m := range link.FindAllStringSubmatch(text, -1) {
			target := m[1]
			if strings.Contains(target, "://") || strings.HasPrefix(target, "mailto:") {
				continue
			}
			n++
			path, anchor, _ := strings.Cut(target, "#")
			dest := f
			if path != "" {
				dest = filepath.Join(filepath.Dir(f), path)
				if _, err := os.Stat(dest); err != nil {
					t.Errorf("%s links to %s, which is not there", f, target)
					continue
				}
			}
			if anchor == "" || !strings.HasSuffix(dest, ".md") {
				continue
			}
			if !anchorsOf(dest)[anchor] {
				t.Errorf("%s links to %s: %s has no heading #%s", f, target, dest, anchor)
			}
		}
	}
	if n < 50 {
		t.Errorf("only %d links checked", n)
	}
}

// stripFences blanks the lines of fenced code blocks, so a # in a shell
// comment is no heading and a ]( in an example is no link.
func stripFences(text string) string {
	lines := strings.Split(text, "\n")
	in := false
	for i, l := range lines {
		if strings.HasPrefix(strings.TrimSpace(l), "```") {
			in = !in
			lines[i] = ""
			continue
		}
		if in {
			lines[i] = ""
		}
	}
	return strings.Join(lines, "\n")
}

// headingSlug is the anchor GitHub gives a heading: lower case, only
// letters, digits, spaces, hyphens and underscores kept, spaces to hyphens.
func headingSlug(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	h = regexp.MustCompile(`[^\p{L}\p{N} _-]`).ReplaceAllString(h, "")
	return strings.ReplaceAll(h, " ", "-")
}
