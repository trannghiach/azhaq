package main

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"
)

// Docs-drift checks for findings that were fixed in the docs only
// (REGRESSIONS.md). Each names its row.

func readDoc(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func docLines(doc string) []string { return strings.Split(doc, "\n") }

// SAF-14: the tables of what Azhaq sends name the HEAD that a port's
// banner grab sends.
func TestRegressSAF14DocsNameThePortsHEAD(t *testing.T) {
	for _, c := range []struct{ file, marker string }{
		{"../../README.md", "`-ports`"},
		{"../../docs/CONCEPTS.md", "A port's service"},
	} {
		found := false
		for _, l := range docLines(readDoc(t, c.file)) {
			if strings.Contains(l, c.marker) && strings.Contains(l, "TCP connect") {
				found = true
				if !strings.Contains(l, "HEAD /") {
					t.Errorf("%s: the line on ports does not name its HEAD request: %s", c.file, l)
				}
			}
		}
		if !found {
			t.Errorf("%s has no line on what a port scan sends", c.file)
		}
	}
}

// ROL-15: the roles recipe says a role of headers carries no cookie-only
// state.
func TestRegressROL15DocsSayHeaderRolesLackCookies(t *testing.T) {
	recipes := readDoc(t, "../../docs/RECIPES.md")
	i := strings.Index(recipes, "## 3. Find IDOR and BOLA")
	j := strings.Index(recipes, "## 4. ")
	if i < 0 || j < i {
		t.Fatal("recipe 3 not found")
	}
	section := recipes[i:j]
	if !strings.Contains(section, "whoami") || !strings.Contains(section, "cookie") || !strings.Contains(section, "-role-login") {
		t.Error("recipe 3 does not say that a role of headers shows no behaviour that needs a cookie")
	}
}

// ROL-20: the README's roles section names show -dir.
func TestRegressROL20READMENamesRolesShowDir(t *testing.T) {
	if !strings.Contains(readDoc(t, "../../README.md"), "`azhaq roles show -dir DIR URL` prints the answers") {
		t.Error("README does not document azhaq roles show -dir")
	}
}

// DOC-01: no public text says an active option needs an -allow scope; the
// targets given are its scope.
func TestRegressDOC01ScopeRuleOfActiveOptions(t *testing.T) {
	bad := regexp.MustCompile("(?i)needs? (its flag, )?an? `?-allow`? scope|need(s)? a scope|refuses? without `?-allow")
	docs := []string{"../../README.md", "../../docs/ARCHITECTURE.md", "../../docs/CONCEPTS.md", "../../docs/OUTPUT.md",
		"../../docs/RECIPES.md", "../../docs/TROUBLESHOOTING.md", "../../docs/MCP.md"}
	for _, d := range docs {
		for _, l := range docLines(readDoc(t, d)) {
			if bad.MatchString(l) {
				t.Errorf("%s says an active option needs a scope: %s", d, l)
			}
		}
	}
	raw, _ := json.Marshal(buildManifest())
	if m := bad.FindString(string(raw)); m != "" {
		t.Errorf("help says %q", m)
	}
	found := false
	for _, l := range docLines(readDoc(t, "../../docs/ARCHITECTURE.md")) {
		if strings.Contains(l, "an `Active` collector needs its flag") {
			found = true
			if !strings.Contains(l, "targets given") {
				t.Errorf("ARCHITECTURE.md does not say the targets given are the scope: %s", l)
			}
		}
	}
	if !found {
		t.Error("ARCHITECTURE.md has no line on active collectors")
	}
}

// REL-02: every file the README links to by a relative path is in the
// release archive.
func TestRegressREL02ReadmeLinksAreInTheArchive(t *testing.T) {
	yaml := readDoc(t, "../../.goreleaser.yaml")
	inArchive := map[string]bool{}
	for _, l := range docLines(yaml) {
		if f, ok := strings.CutPrefix(strings.TrimSpace(l), "- "); ok && !strings.Contains(f, ":") {
			inArchive[f] = true
		}
	}
	if !inArchive["README.md"] || !inArchive["LICENSE"] {
		t.Fatalf("archive files not read from .goreleaser.yaml: %v", inArchive)
	}
	link := regexp.MustCompile(`\]\(([^)\s]+)\)`)
	n := 0
	for _, m := range link.FindAllStringSubmatch(readDoc(t, "../../README.md"), -1) {
		target := m[1]
		if strings.Contains(target, "://") || strings.HasPrefix(target, "#") || strings.HasPrefix(target, "mailto:") {
			continue
		}
		target, _, _ = strings.Cut(target, "#")
		n++
		if !inArchive[target] {
			t.Errorf("README links to %s, which the release archive does not hold", target)
		}
		if _, err := os.Stat("../../" + target); err != nil {
			t.Errorf("README links to %s, which is not in the repository", target)
		}
	}
	if n < 5 {
		t.Errorf("only %d relative links found", n)
	}
}

// DOC-02 (open, release owner): the benchmark header of the README names
// the release the numbers were measured on, the newest one in the
// CHANGELOG that is not the one under way.
func TestRegressDOC02ReadmeBenchmarkVersion(t *testing.T) {
	t.Skip("open: DOC-02 (a release step: the bench is run on the tag, then the header is written)")
	readme := readDoc(t, "../../README.md")
	m := regexp.MustCompile(`Latest run \(\d{4}-\d\d-\d\d, v([0-9.]+)`).FindStringSubmatch(readme)
	if m == nil {
		t.Fatal("README has no 'Latest run (date, vX)' header")
	}
	heads := regexp.MustCompile(`(?m)^## v([0-9.]+)`).FindAllStringSubmatch(readDoc(t, "../../CHANGELOG.md"), -1)
	if len(heads) < 2 {
		t.Fatal("CHANGELOG has no released version")
	}
	if m[1] != heads[1][1] {
		t.Errorf("README's benchmark is of v%s, the latest release is v%s", m[1], heads[1][1])
	}
}
