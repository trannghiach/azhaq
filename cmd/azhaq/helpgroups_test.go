package main

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
)

// The table names real flags: every group and hidden entry is a flag of its
// command, every flag of a command is shown in one group or hidden for one
// reason, and no flag is both or twice.
func TestHelpTableHoldsEveryFlagOnce(t *testing.T) {
	reason := regexp.MustCompile(`^(compat:[a-z]+|alias|accepted|rare)$`)
	for name := range helpSpecs {
		if _, ok := lookup(name); !ok {
			t.Errorf("the help table has an entry for %q, which is no command", name)
		}
	}
	for _, c := range commands {
		fs := flagsOf(c.name)
		if fs == nil || len(flagNames(fs)) == 0 {
			continue
		}
		spec, ok := specOf(c.name)
		if !ok {
			t.Errorf("%s has flags and no entry in the help table (helpgroups.go)", c.name)
			continue
		}
		real := map[string]bool{}
		for _, n := range flagNames(fs) {
			real[n] = true
		}
		where := map[string]string{}
		for _, g := range spec.groups {
			for _, n := range g.flags {
				if !real[n] {
					t.Errorf("%s: group %q names -%s, which is no flag of %s", c.name, g.title, n, c.name)
				}
				if prev, dup := where[n]; dup {
					t.Errorf("%s: -%s is in %q and in %q", c.name, n, prev, g.title)
				}
				where[n] = g.title
			}
		}
		for n, why := range spec.hidden {
			if !real[n] {
				t.Errorf("%s: hides -%s, which is no flag of %s", c.name, n, c.name)
			}
			if !reason.MatchString(why) {
				t.Errorf("%s: -%s is hidden for %q, not compat:TOOL, alias, accepted or rare", c.name, n, why)
			}
			if g, shown := where[n]; shown {
				t.Errorf("%s: -%s is in group %q and hidden", c.name, n, g)
			}
			where[n] = "hidden"
		}
		for n := range real {
			if _, ok := where[n]; !ok {
				t.Errorf("%s: -%s is neither in a group nor hidden", c.name, n)
			}
		}
	}
	// plan takes run's table, so it must take run's flags.
	run, plan := map[string]bool{}, map[string]bool{}
	for _, n := range flagNames(flagsOf("run")) {
		run[n] = true
	}
	for _, n := range flagNames(flagsOf("plan")) {
		plan[n] = true
		if !run[n] {
			t.Errorf("plan has -%s, which run lacks, and the table of plan is run's", n)
		}
	}
	for n := range run {
		if !plan[n] {
			t.Errorf("run has -%s, which plan lacks", n)
		}
	}
}

// helpLines are the flag names printed one to a row, as "  -name".
func helpFlagRows(out string) map[string]bool {
	rows := map[string]bool{}
	for _, l := range strings.Split(out, "\n") {
		if rest, ok := strings.CutPrefix(l, "  -"); ok {
			rows[strings.Fields(rest)[0]] = true
		}
	}
	return rows
}

// -h shows the flags of azhaq's own under task headings and none of the
// names kept for httpx's command lines, and ends with the -h all line.
func TestProbeHelpShowsOwnFlagsOnly(t *testing.T) {
	out, _, code := cli(t, "probe", "-h")
	if code != exitOK {
		t.Fatalf("probe -h: exit %d", code)
	}
	rows := helpFlagRows(out)
	spec, _ := specOf("probe")
	for n, why := range spec.hidden {
		if rows[n] {
			t.Errorf("probe -h lists -%s (%s)", n, why)
		}
	}
	for _, want := range []string{"\nTargets and input:\n", "\nScope and safety:\n", "\nPace and limits:\n", "\nOutput:\n", "  -deny-path ", "  -u "} {
		if !strings.Contains(out, want) {
			t.Errorf("probe -h lacks %q", want)
		}
	}
	// httpx's flags people use stay shown, with the matchers and fields; no other one does.
	for _, used := range []string{"sc", "title", "td", "ip", "mc", "fc", "fr", "irr", "tls-grab"} {
		if !rows[used] {
			t.Errorf("probe -h leaves out httpx's -%s, which people use", used)
		}
	}
	for _, rare := range []string{"cdn", "favicon", "asn", "wc", "rt", "csv", "extract-regex"} {
		if rows[rare] {
			t.Errorf("probe -h lists httpx-only -%s", rare)
		}
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	last := lines[len(lines)-1]
	if want := len(spec.hidden); !strings.HasPrefix(last, itoa(want)+" more flags (httpx's names, aliases, accepted only): ") || !strings.HasSuffix(last, "azhaq probe -h all") {
		t.Errorf("probe -h ends with %q, want the -h all line for %d flags", last, want)
	}
	if n := len(lines); n > 100 {
		t.Errorf("probe -h is %d lines, want a short page", n)
	}
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// -h all holds every flag of every command, the shown ones under their
// headings and the others under theirs, and an alias says what it stands for.
func TestHelpAllHoldsEveryFlag(t *testing.T) {
	for _, c := range commands {
		fs := flagsOf(c.name)
		if fs == nil || len(flagNames(fs)) == 0 {
			continue
		}
		if c.name == "run" || c.name == "plan" {
			continue // checked below, with the larger pages
		}
		out, _, code := cli(t, c.name, "-h", "all")
		if code != exitOK {
			t.Fatalf("%s -h all: exit %d", c.name, code)
		}
		rows := helpFlagRows(out)
		for _, n := range flagNames(fs) {
			if !rows[n] {
				t.Errorf("%s -h all lacks -%s", c.name, n)
			}
		}
		if strings.Contains(out, "-h all\n") {
			t.Errorf("%s -h all still points at -h all", c.name)
		}
	}
	for _, name := range []string{"run", "plan"} {
		out, _, code := cli(t, name, "-h", "all")
		rows := helpFlagRows(out)
		if code != exitOK {
			t.Fatalf("%s -h all: exit %d", name, code)
		}
		for _, n := range flagNames(flagsOf(name)) {
			if !rows[n] {
				t.Errorf("%s -h all lacks -%s", name, n)
			}
		}
		for _, want := range []string{"\nRarely needed:\n", "  -dirs-ext ", "  -port-rate ", "  -shot-size ", "  -urls-from "} {
			if !strings.Contains(out, want) {
				t.Errorf("%s -h all lacks %q", name, want)
			}
		}
		short, _, _ := cli(t, name, "-h")
		if strings.Contains(short, "  -dirs-ext ") || !regexp.MustCompile(` more flags \([a-z ,]*rarely used\): azhaq `+name+` -h all`).MatchString(short) {
			t.Errorf("%s -h leaves its hidden families in, or says no more: %.300s", name, short)
		}
	}
	out, _, _ := cli(t, "probe", "-h", "all")
	for _, want := range []string{"\nFlags familiar from httpx:\n", "\nOther names:\n", "\nAccepted for httpx command lines:\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("probe -h all lacks the heading %q", want)
		}
	}
	if !regexp.MustCompile(`(?m)^  -bp INT +same as -body-preview$`).MatchString(out) {
		t.Errorf("probe -h all does not say -bp is the same as -body-preview")
	}
	// The other ways to ask the same page.
	help, _, _ := cli(t, "help", "probe")
	hAll, _, _ := cli(t, "help", "probe", "all")
	for _, args := range [][]string{{"probe", "-help", "all"}, {"probe", "--help", "all"}, {"help", "all", "probe"}} {
		got, _, _ := cli(t, args...)
		if got != hAll {
			t.Errorf("azhaq %s differs from azhaq help probe all", strings.Join(args, " "))
		}
	}
	short, _, _ := cli(t, "probe", "-h")
	if help != short {
		t.Error("azhaq help probe differs from azhaq probe -h")
	}
	if hAll == short || !strings.Contains(hAll, "  -cdn ") {
		t.Error("help probe all is not the long page")
	}
}

// The command list leaves out new, worker and bench and says where the rest
// is; they still run and keep their pages.
func TestCommandListLeavesOutHiddenCommands(t *testing.T) {
	for _, args := range [][]string{{"help"}, {"-h"}, {"--help"}} {
		out, _, code := cli(t, args...)
		if code != exitOK {
			t.Fatalf("azhaq %v: exit %d", args, code)
		}
		for _, name := range []string{"new", "worker", "bench"} {
			if strings.Contains(out, "\n  "+name+" ") {
				t.Errorf("azhaq %v lists %s", args, name)
			}
		}
		for _, name := range []string{"run", "probe", "query", "roles"} {
			if !strings.Contains(out, "\n  "+name+" ") {
				t.Errorf("azhaq %v leaves out %s", args, name)
			}
		}
		if !strings.HasSuffix(out, "\nmore commands: azhaq help all\n") {
			t.Errorf("azhaq %v does not end with the line about azhaq help all: %q", args, out[max(0, len(out)-80):])
		}
	}
	all, _, _ := cli(t, "help", "all")
	for _, c := range commands {
		if !strings.Contains(all, "\n  "+c.name+" ") {
			t.Errorf("azhaq help all leaves out %s", c.name)
		}
	}
	if strings.Contains(all, "more commands:") {
		t.Error("azhaq help all points at itself")
	}
	for _, name := range []string{"new", "worker", "bench"} {
		if out, _, code := cli(t, name, "-h"); code != exitOK || !strings.HasPrefix(out, "azhaq "+name+": ") {
			t.Errorf("%s -h: exit %d, %.80q", name, code, out)
		}
		if out, _, code := cli(t, "help", name); code != exitOK || !strings.HasPrefix(out, "azhaq "+name+": ") {
			t.Errorf("help %s: exit %d, %.80q", name, code, out)
		}
	}
	if _, errOut, _ := cli(t, "new"); strings.Contains(errOut, "unknown command") {
		t.Errorf("new no longer runs: %q", errOut)
	}
}

// help -json lists every flag and command, and marks what -h leaves out.
func TestHelpJSONMarksHiddenFlagsAndCommands(t *testing.T) {
	raw, err := json.Marshal(buildManifest())
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Commands []struct {
			Name   string `json:"name"`
			Hidden bool   `json:"hidden"`
			Why    string `json:"why"`
			Flags  []struct {
				Name   string `json:"name"`
				Hidden bool   `json:"hidden"`
				Why    string `json:"why"`
			} `json:"flags"`
		} `json:"commands"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	hiddenCmd := map[string]bool{}
	flags := map[string]map[string][2]string{}
	for _, c := range m.Commands {
		if c.Hidden {
			hiddenCmd[c.Name] = true
			if c.Why == "" {
				t.Errorf("command %s is hidden and says no why", c.Name)
			}
		} else if c.Why != "" {
			t.Errorf("command %s says why and is not hidden", c.Name)
		}
		flags[c.Name] = map[string][2]string{}
		for _, f := range c.Flags {
			hidden := ""
			if f.Hidden {
				hidden = "yes"
				if f.Why == "" {
					t.Errorf("%s -%s is hidden and says no why", c.Name, f.Name)
				}
			}
			flags[c.Name][f.Name] = [2]string{hidden, f.Why}
		}
	}
	for _, name := range []string{"new", "worker", "bench"} {
		if !hiddenCmd[name] {
			t.Errorf("help -json does not mark %s hidden", name)
		}
	}
	if len(hiddenCmd) != 3 {
		t.Errorf("hidden commands %v, want new, worker and bench", hiddenCmd)
	}
	for _, c := range []struct{ cmd, flag, hidden, why string }{
		{"probe", "sc", "", ""},
		{"probe", "cdn", "yes", "compat:httpx"},
		{"probe", "status-code", "yes", "alias"},
		{"probe", "u", "", ""},
		{"probe", "deny-path", "", ""},
		{"run", "dirs-ext", "yes", "rare"},
		{"plan", "dirs-ext", "yes", "rare"},
		{"run", "allow", "", ""},
		{"fuzz", "mc", "", ""},
		{"fuzz", "ic", "yes", "compat:ffuf"},
		{"dns", "a", "", ""},
		{"crawl", "nc", "yes", "accepted"},
	} {
		got, ok := flags[c.cmd][c.flag]
		if !ok {
			t.Errorf("help -json: %s has no -%s", c.cmd, c.flag)
			continue
		}
		if got != [2]string{c.hidden, c.why} {
			t.Errorf("help -json: %s -%s is %v, want hidden=%q why=%q", c.cmd, c.flag, got, c.hidden, c.why)
		}
	}
}

// A mistyped flag's error names the closest flags of the command, the ones
// -h leaves out too.
func TestMistypedFlagSuggestsClosestName(t *testing.T) {
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"probe", "-proxyy", "x"}, "did you mean -proxy?"},
		{[]string{"probe", "-deny-pat", "x"}, "-deny-path"},
		{[]string{"probe", "-status-cod"}, "-status-code"}, // hidden: httpx's name
		{[]string{"run", "-dirs-extt"}, "-dirs-ext"},       // hidden: a rare one
		{[]string{"fuzz", "-recursio"}, "-recursion"},
		{[]string{"crawl", "-rate-limitt"}, "-rate-limit"},
	} {
		_, errOut, code := cli(t, c.args...)
		if code != exitUsage || !strings.Contains(errOut, "flag provided but not defined") || !strings.Contains(errOut, c.want) {
			t.Errorf("azhaq %s: exit %d, stderr %q, want it to say %q", strings.Join(c.args, " "), code, errOut, c.want)
		}
	}
	// A flag far from every name gets no guess, and a one-letter one only
	// its other case.
	for _, args := range [][]string{{"probe", "-zzzzzzzz"}, {"probe", "-q"}} {
		_, errOut, _ := cli(t, args...)
		if strings.Contains(errOut, "did you mean") {
			t.Errorf("azhaq %s guessed: %q", strings.Join(args, " "), errOut)
		}
	}
	if got := flagNear("H", []string{"h", "x"}); len(got) != 1 || got[0] != "-h" {
		t.Errorf("a one-letter flag in the other case: %v", got)
	}
}
