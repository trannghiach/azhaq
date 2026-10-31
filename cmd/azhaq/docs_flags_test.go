package main

import (
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/trannghiach/azhaq/docs"
)

// The flags the public docs name must exist: a command line in a doc runs,
// and a flag in a sentence about a command is one that command takes.

var publicDocs = append([]string{
	"../../README.md",
	"../../docs/ARCHITECTURE.md",
	"../../docs/CONCEPTS.md",
	"../../docs/CONNECTOR.md",
	"../../docs/MCP.md",
	"../../docs/MIGRATING.md",
	"../../docs/OUTPUT.md",
	"../../docs/RECIPES.md",
	"../../docs/TROUBLESHOOTING.md",
}, commandPages()...)

// foreignFlags are flags of other tools the docs name, to say azhaq has no
// such flag. Anything else a doc names has to be one of azhaq's.
var foreignFlags = map[string]bool{
	"scraperfile": true, "scrapers": true, "search": true, "audit-log": true,
	"preflight-anyhost": true, "jc": true, "jsl": true, "headless": true, "cwu": true, "xhr": true, "sV": true,
}

var flagTok = regexp.MustCompile(`^--?[A-Za-z][A-Za-z0-9-]*(=.*)?$`)

// flagTable is every command's flags as help -json lists them.
type flagTable struct {
	byCmd map[string]map[string]bool
	all   map[string]bool
}

func newFlagTable() flagTable {
	ft := flagTable{byCmd: map[string]map[string]bool{}, all: map[string]bool{}}
	for _, c := range buildManifest().Commands {
		set := map[string]bool{}
		for _, f := range c.Flags {
			set[f.Name] = true
			ft.all[f.Name] = true
		}
		ft.byCmd[c.Name] = set
	}
	ft.byCmd["help"] = map[string]bool{"json": true}
	ft.byCmd["roles show"] = rolesShowFlags()
	for n := range ft.byCmd["roles show"] {
		ft.all[n] = true
	}
	ft.byCmd["resume"] = ft.byCmd["run"]
	return ft
}

// rolesShowFlags are the flags of azhaq roles show, which help -json does
// not list under a command of its own.
func rolesShowFlags() map[string]bool {
	wasDescribing, wasDescribed := describing, described
	describing, described = true, nil
	stdout, stderr := os.Stdout, os.Stderr
	if null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0); err == nil {
		os.Stdout, os.Stderr = null, null
		defer null.Close()
	}
	_ = cmdRolesShow([]string{"-h"})
	os.Stdout, os.Stderr = stdout, stderr
	fs := described
	describing, described = wasDescribing, wasDescribed
	set := map[string]bool{}
	if fs != nil {
		fs.VisitAll(func(f *flag.Flag) { set[f.Name] = true })
	}
	return set
}

// shellWords splits a command line into one word list per command: at | ;
// && and a redirect, with quoted text kept as one word, and stops at a
// comment.
func shellWords(s string) [][]string {
	var segs [][]string
	var cur []string
	var word strings.Builder
	inWord, quote, skip := false, rune(0), false
	flush := func() {
		if inWord && !skip {
			cur = append(cur, word.String())
		}
		word.Reset()
		inWord = false
	}
	end := func() {
		flush()
		if len(cur) > 0 {
			segs = append(segs, cur)
		}
		cur, skip = nil, false
	}
	rs := []rune(s)
	for i, r := range rs {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				word.WriteRune(r)
			}
			inWord = true
		case r == '\'' || r == '"':
			quote, inWord = r, true
			word.WriteRune('x') // a quoted word is a value, never a flag
		case r == ' ' || r == '\t':
			flush()
		case r == '#' && !inWord:
			end()
			return segs
		case r == '|' || r == ';' || (r == '&' && i+1 < len(rs) && rs[i+1] == '&'):
			end()
		case r == '>' || r == '<':
			flush()
			skip = true
		default:
			word.WriteRune(r)
			inWord = true
		}
	}
	end()
	return segs
}

// docFlagName is the name in a flag word (-ac=false is ac), or "".
func docFlagName(w string) string {
	if !flagTok.MatchString(w) {
		return ""
	}
	n := strings.TrimLeft(w, "-")
	n, _, _ = strings.Cut(n, "=")
	if regexp.MustCompile(`^T[0-5]$`).MatchString(n) {
		return "T" // nmap's -T0 to -T5
	}
	if len(n) > 1 && strings.ToUpper(n) == n {
		return "" // -GET or -NOAUTH is output, not a flag
	}
	return n
}

// checkCommandLine reports the flags of every azhaq command on the line
// that the command does not have.
func (ft flagTable) checkCommandLine(line string) []string {
	var bad []string
	for _, words := range shellWords(line) {
		at := -1
		for i, w := range words {
			if w == "azhaq" {
				at = i
				break
			}
		}
		if at < 0 || at+1 >= len(words) {
			continue
		}
		cmd := words[at+1]
		if cmd == "roles" && at+2 < len(words) && words[at+2] == "show" {
			cmd, at = "roles show", at+1
		}
		set, ok := ft.byCmd[cmd]
		if !ok || len(set) == 0 {
			continue
		}
		afterDashes := false
		for _, w := range words[at+2:] {
			if w == "--" {
				afterDashes = true
				continue
			}
			n := docFlagName(w)
			if n == "" || n == "h" || n == "help" {
				continue
			}
			use := set
			if afterDashes {
				if cmd != "roles" && cmd != "watch" {
					break
				}
				use = ft.byCmd["run"]
			}
			if !use[n] {
				bad = append(bad, fmt.Sprintf("azhaq %s has no flag -%s (in: %s)", cmd, n, strings.TrimSpace(line)))
			}
		}
	}
	return bad
}

// codeSpans are the `inline code` pieces of a line, with a table's \| undone.
func codeSpans(line string) []string {
	var out []string
	for {
		i := strings.IndexByte(line, '`')
		if i < 0 {
			return out
		}
		j := strings.IndexByte(line[i+1:], '`')
		if j < 0 {
			return out
		}
		out = append(out, strings.ReplaceAll(line[i+1:i+1+j], `\|`, "|"))
		line = line[i+2+j:]
	}
}

// boldCommand is the command a README paragraph that starts **name** or
// **name -opt** is about, else "".
var boldCommand = regexp.MustCompile("^\\*\\*`?([a-z]+)")

// withAzhaq puts "azhaq " before a span that starts with a command name and
// carries flags (`urls -retries N`), so it is checked as that command's.
func (ft flagTable) withAzhaq(sp string) string {
	words := strings.Fields(sp)
	if len(words) < 2 || strings.Contains(sp, "azhaq ") {
		return sp
	}
	if _, ok := ft.byCmd[words[0]]; !ok {
		return sp
	}
	for _, w := range words[1:] {
		if docFlagName(w) != "" {
			return "azhaq " + sp
		}
	}
	return sp
}

// checkDoc checks one document's text. A MIGRATING section names the
// commands it covers in `<!-- azhaq: a b -->`; a README paragraph that
// starts **fuzz** is about fuzz; elsewhere a flag has to be some command's.
func (ft flagTable) checkDoc(name, text string) []string {
	var bad []string
	lines := strings.Split(text, "\n")
	inFence := false
	var ctx []string
	var joined string
	for _, l := range lines {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "```") {
			inFence = !inFence
			joined = ""
			continue
		}
		if inFence {
			if strings.HasSuffix(t, `\`) {
				joined += strings.TrimSuffix(t, `\`) + " "
				continue
			}
			for _, b := range ft.checkCommandLine(joined + t) {
				bad = append(bad, name+": "+b)
			}
			joined = ""
			continue
		}
		if m := regexp.MustCompile(`^<!-- azhaq: (.*) -->$`).FindStringSubmatch(t); m != nil {
			ctx = strings.Fields(m[1])
			continue
		}
		if strings.HasPrefix(t, "#") {
			ctx = nil
			continue
		}
		if strings.HasPrefix(t, "**") && !strings.HasSuffix(name, "MIGRATING.md") {
			ctx = nil
			if m := boldCommand.FindStringSubmatch(t); m != nil {
				if _, ok := ft.byCmd[m[1]]; ok {
					ctx = []string{m[1]}
				}
			}
		}
		cells := []string{t}
		migTable := strings.HasSuffix(name, "MIGRATING.md") && strings.HasPrefix(t, "|")
		if migTable {
			cells = regexp.MustCompile(`[^\\]\|`).Split(" "+t, -1)
			if len(cells) > 1 {
				cells = cells[1:] // the cell before the first |
			}
		}
		for ci, cell := range cells {
			if migTable && ci == 0 {
				continue // the other tool's column
			}
			for _, sp := range codeSpans(cell) {
				sp = ft.withAzhaq(sp)
				for _, b := range ft.checkCommandLine(sp) {
					bad = append(bad, name+": "+b)
				}
				if strings.Contains(sp, "azhaq ") {
					continue
				}
				words := strings.Fields(sp)
				if len(words) == 0 {
					continue
				}
				// A span about azhaq starts with a flag, or sits in the
				// azhaq column of a table; another tool's flag is written
				// with its tool's name in front.
				if docFlagName(words[0]) == "" && !(migTable && ci == 1) {
					continue
				}
				for _, w := range words {
					n := docFlagName(w)
					if n == "" || n == "h" || n == "help" || foreignFlags[n] {
						continue
					}
					ok := ft.all[n]
					if len(ctx) > 0 {
						ok = false
						for _, c := range ctx {
							if ft.byCmd[c][n] || (c == "roles" || c == "watch") && ft.byCmd["run"][n] {
								ok = true
							}
						}
					}
					if !ok {
						bad = append(bad, fmt.Sprintf("%s: no command %v has the flag -%s (in: `%s`)", name, ctx, n, sp))
					}
				}
			}
		}
	}
	return bad
}

func TestDocsNameOnlyFlagsThatExist(t *testing.T) {
	ft := newFlagTable()
	for _, d := range publicDocs {
		for _, b := range ft.checkDoc(d, readDoc(t, d)) {
			t.Error(b)
		}
	}
}

// The check itself: a flag that does not exist is caught in a command line,
// in a table of MIGRATING and in a sentence about a command.
func TestDocsFlagCheckCatchesABadFlag(t *testing.T) {
	ft := newFlagTable()
	for _, c := range []struct{ name, text string }{
		{"README.md", "```\nazhaq probe -l hosts.txt -nonesuch\n```"},
		{"README.md", "run `azhaq dns -d example.com -nonesuch` now"},
		{"README.md", "```\nazhaq subs -d a.com | azhaq probe \\\n  -nonesuch\n```"},
		{"README.md", "**fuzz** takes `-mc`, `-nonesuch`."},
		{"README.md", "A flag `-nonesuch` nobody has."},
		{"docs/MIGRATING.md", "<!-- azhaq: dirs -->\n| `-x` | `-nonesuch` | n |"},
		{"docs/MIGRATING.md", "<!-- azhaq: dirs -->\nUse `-nonesuch`."},
		{"README.md", "```\nazhaq roles -role anon -- -nonesuch\n```"},
	} {
		if len(ft.checkDoc(c.name, c.text)) == 0 {
			t.Errorf("not caught: %q", c.text)
		}
	}
	for _, c := range []struct{ name, text string }{
		{"README.md", "```\nazhaq probe -l hosts.txt -mc 200 # -nonesuch\nazhaq subs -d a.com | azhaq probe -silent\n```"},
		{"README.md", "run `azhaq dns -d example.com -json 'x -nonesuch'`"},
		{"README.md", "**fuzz** takes `-mc`, and `-scraperfile` is not here, `ffuf -nonesuch`."},
		{"docs/MIGRATING.md", "<!-- azhaq: dirs -->\n| `-nonesuch` | `-mc` | `ffuf -x` and `-fc` |"},
	} {
		if bad := ft.checkDoc(c.name, c.text); len(bad) != 0 {
			t.Errorf("wrongly caught %q: %v", c.text, bad)
		}
	}
}

// MIGRATING has a section for each tool azhaq stands in for, with the
// commands it covers named, a table of flags, and three command lines.
func TestMigratingCoversTheTools(t *testing.T) {
	doc := readDoc(t, "../../docs/MIGRATING.md")
	sections := regexp.MustCompile(`(?m)^## `).Split(doc, -1)[1:]
	ft := newFlagTable()
	for _, tool := range []string{"subfinder", "dnsx", "httpx", "katana", "ffuf", "gau", "arjun", "naabu", "nmap", "gowitness", "notify"} {
		var sec string
		for _, s := range sections {
			if strings.HasPrefix(s, tool+" ") || strings.HasPrefix(s, tool+":") {
				sec = s
			}
		}
		if sec == "" {
			t.Errorf("MIGRATING has no section for %s", tool)
			continue
		}
		m := regexp.MustCompile(`<!-- azhaq: (.*) -->`).FindStringSubmatch(sec)
		if m == nil {
			t.Errorf("%s: the section does not name its commands", tool)
		} else {
			for _, c := range strings.Fields(m[1]) {
				if _, ok := ft.byCmd[c]; !ok {
					t.Errorf("%s: no command %q", tool, c)
				}
			}
		}
		if rows := regexp.MustCompile(`(?m)^\| .*\|$`).FindAllString(sec, -1); len(rows) < 8 {
			t.Errorf("%s: the table has %d rows", tool, len(rows))
		}
		block := regexp.MustCompile("(?s)```\n(.*?)```").FindStringSubmatch(sec)
		if block == nil {
			t.Errorf("%s: no command lines", tool)
			continue
		}
		n := 0
		for _, l := range strings.Split(block[1], "\n") {
			if strings.Contains(l, "azhaq ") {
				n++
			}
		}
		if n < 3 {
			t.Errorf("%s: %d command lines, want 3", tool, n)
		}
		if !strings.Contains(sec, "What differs on purpose") || !strings.Contains(sec, "On top:") {
			t.Errorf("%s: no account of what differs or what azhaq adds", tool)
		}
	}
	// Every link inside the page leads to a heading.
	anchors := map[string]bool{}
	for _, l := range strings.Split(doc, "\n") {
		if h, ok := strings.CutPrefix(l, "## "); ok {
			a := strings.ToLower(h)
			a = regexp.MustCompile("[^a-z0-9 _-]").ReplaceAllString(a, "")
			anchors[strings.ReplaceAll(a, " ", "-")] = true
		}
	}
	for _, m := range regexp.MustCompile(`\]\(#([^)]+)\)`).FindAllStringSubmatch(doc, -1) {
		if !anchors[m[1]] {
			t.Errorf("MIGRATING links to #%s, which is no heading", m[1])
		}
	}
}

// azhaq docs with no topic is the overview, then the list of topics, and
// every command it shows is one that runs.
func TestDocsOverview(t *testing.T) {
	out, err := captureStdout(t, func() error { return cmdDocs(nil) })
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"azhaq help", "azhaq help -json", "azhaq docs migrating", "azhaq docs TOPIC prints one of:", "subfinder", "gowitness"} {
		if !strings.Contains(out, want) {
			t.Errorf("the overview does not say %q", want)
		}
	}
	starts := 0
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "azhaq ") && strings.Contains(l, " -") {
			starts++
		}
	}
	if starts < 6 {
		t.Errorf("the overview shows %d commands to start with, want 6", starts)
	}
	if n := strings.Count(out, "\n"); n > 36 {
		t.Errorf("the overview is %d lines: it should fit a screen", n)
	}
	for _, b := range newFlagTable().checkDoc("overview", "```\n"+docsOverview+"```") {
		t.Error(b)
	}
	for _, tp := range topics {
		if tp.file == "" {
			continue
		}
		if raw, err := docs.Files.ReadFile(tp.file); err != nil || len(raw) == 0 {
			t.Errorf("azhaq docs %s: %s is not embedded", tp.name, tp.file) // not printed: a pipe holds 64 KB
		}
	}
}

// The examples the help registry gives are command lines too.
func TestHelpExamplesUseRealFlags(t *testing.T) {
	ft := newFlagTable()
	n := 0
	for _, c := range buildManifest().Commands {
		for _, ex := range c.Examples {
			n++
			for _, b := range ft.checkCommandLine(ex) {
				t.Errorf("help %s: %s", c.Name, b)
			}
		}
	}
	if n < 40 {
		t.Errorf("only %d help examples checked", n)
	}
}
