package main

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
)

// Reasons a flag is hidden (the keys of helpSpec.hidden; compat is
// "compat:TOOL").
const (
	whyAlias    = "alias"
	whyAccepted = "accepted"
	whyRare     = "rare"
)

// parsedSpec is a helpSpec with its name lists split.
type parsedSpec struct {
	groups []parsedGroup
	hidden map[string]string // flag -> reason
	tool   string            // the reference tool the compat flags are named for
}

type parsedGroup struct {
	title string
	flags []string
}

var specCache sync.Map // command name -> *parsedSpec

// specOf is the help table entry of a command; plan takes run's.
func specOf(name string) (*parsedSpec, bool) {
	if name == "plan" {
		name = "run"
	}
	if v, ok := specCache.Load(name); ok {
		return v.(*parsedSpec), true
	}
	raw, ok := helpSpecs[name]
	if !ok {
		return nil, false
	}
	ps := &parsedSpec{hidden: map[string]string{}}
	for _, g := range raw.groups {
		ps.groups = append(ps.groups, parsedGroup{g.title, strings.Fields(g.flags)})
	}
	for why, names := range raw.hidden {
		for _, n := range strings.Fields(names) {
			ps.hidden[n] = why
		}
		if tool, ok := strings.CutPrefix(why, "compat:"); ok && (ps.tool == "" || tool < ps.tool) {
			ps.tool = tool
		}
	}
	specCache.Store(name, ps)
	return ps, true
}

// markHidden sets Hidden and Why on the flags a command's table hides.
func markHidden(name string, infos []flagInfo) []flagInfo {
	spec, ok := specOf(name)
	if !ok {
		return infos
	}
	for i := range infos {
		if why, hidden := spec.hidden[infos[i].Name]; hidden {
			infos[i].Hidden, infos[i].Why = true, why
		}
	}
	return infos
}

// commandFlags is a command's flags as help -json lists them, the hidden
// ones marked.
func commandFlags(name string) []flagInfo {
	return markHidden(name, flagInfos(flagsOf(name)))
}

// A helpShown is a heading and the flags under it; a helpHidden is a kind
// of hidden flags (why is the reason they share) with its heading.
type helpShown struct {
	title string
	flags []flagInfo
}

type helpHidden struct {
	why   string
	title string
	flags []flagInfo
}

type helpLayout struct {
	shown  []helpShown
	hidden []helpHidden
}

// hiddenTitle is the heading of the hidden flags that share a reason.
func hiddenTitle(why, tool string) string {
	switch {
	case strings.HasPrefix(why, "compat:"):
		return "Flags familiar from " + strings.TrimPrefix(why, "compat:")
	case why == whyAlias:
		return "Other names"
	case why == whyAccepted:
		if tool != "" {
			return "Accepted for " + tool + " command lines"
		}
		return "Accepted, with no effect"
	default:
		return "Rarely needed"
	}
}

func whyRank(why string) int {
	switch {
	case strings.HasPrefix(why, "compat:"):
		return 0
	case why == whyAlias:
		return 1
	case why == whyAccepted:
		return 2
	}
	return 3
}

// layoutFlags sorts a command's flags into its table's groups and hidden
// kinds. A flag the table does not name is shown last, so none is lost.
func layoutFlags(name string, infos []flagInfo) helpLayout {
	spec, ok := specOf(name)
	if !ok {
		return helpLayout{shown: []helpShown{{flags: infos}}}
	}
	byName := map[string]flagInfo{}
	for _, f := range infos {
		byName[f.Name] = f
	}
	var l helpLayout
	placed := map[string]bool{}
	for _, g := range spec.groups {
		sg := helpShown{title: g.title}
		for _, n := range g.flags {
			if f, ok := byName[n]; ok {
				sg.flags = append(sg.flags, f)
				placed[n] = true
			}
		}
		if len(sg.flags) > 0 {
			l.shown = append(l.shown, sg)
		}
	}
	byWhy := map[string][]flagInfo{}
	var rest []flagInfo
	for _, f := range infos { // infos are in name order
		switch why, hidden := spec.hidden[f.Name]; {
		case hidden:
			byWhy[why] = append(byWhy[why], f)
		case !placed[f.Name]:
			rest = append(rest, f)
		}
	}
	if len(rest) > 0 {
		l.shown = append(l.shown, helpShown{title: "Other", flags: rest})
	}
	var whys []string
	for why := range byWhy {
		whys = append(whys, why)
	}
	sort.Slice(whys, func(i, j int) bool {
		if a, b := whyRank(whys[i]), whyRank(whys[j]); a != b {
			return a < b
		}
		return whys[i] < whys[j]
	})
	for _, why := range whys {
		l.hidden = append(l.hidden, helpHidden{why: why, title: hiddenTitle(why, spec.tool), flags: byWhy[why]})
	}
	return l
}

// hiddenCount is how many flags -h leaves for -h all.
func (l helpLayout) hiddenCount() int {
	n := 0
	for _, h := range l.hidden {
		n += len(h.flags)
	}
	return n
}

// moreSummary says what the hidden flags are: "httpx's names, aliases,
// rarely used".
func (l helpLayout) moreSummary() string {
	var parts []string
	for _, h := range l.hidden {
		switch {
		case strings.HasPrefix(h.why, "compat:"):
			parts = append(parts, strings.TrimPrefix(h.why, "compat:")+"'s names")
		case h.why == whyAlias:
			parts = append(parts, "aliases")
		case h.why == whyAccepted:
			parts = append(parts, "accepted only")
		default:
			parts = append(parts, "rarely used")
		}
	}
	return strings.Join(parts, ", ")
}

// aliasTarget is the flag an alias stands for: one with the same help text
// that is not itself an alias (a shown one first), or "".
func aliasTarget(f flagInfo, l helpLayout) string {
	if rest, ok := strings.CutPrefix(f.Usage, "same as -"); ok && rest != "" {
		return ""
	}
	try := func(flags []flagInfo) string {
		for _, o := range flags {
			if o.Name != f.Name && o.Usage == f.Usage && o.Type == f.Type {
				return o.Name
			}
		}
		return ""
	}
	for _, s := range l.shown {
		if n := try(s.flags); n != "" {
			return n
		}
	}
	for _, h := range l.hidden {
		if h.why != whyAlias {
			if n := try(h.flags); n != "" {
				return n
			}
		}
	}
	return ""
}

// flagCol is the left column of a flag's row: -name, and its type unless
// it is a bool.
func flagCol(f flagInfo) string {
	col := "-" + f.Name
	if f.Type != "bool" {
		col += " " + strings.ToUpper(f.Type)
	}
	return col
}

// flagText is a flag's help text with its repeatable mark and default.
func flagText(f flagInfo) string {
	line := f.Usage
	if f.Repeatable && !strings.Contains(line, "repeatable") {
		line += " (repeatable)"
	}
	if f.Default != "" {
		line += fmt.Sprintf(" (default %s)", f.Default)
	}
	return line
}

// printFlags is the flags part of azhaq NAME -h (all: -h all).
func printFlags(w io.Writer, name string, infos []flagInfo, all bool) {
	if len(infos) == 0 {
		return
	}
	l := layoutFlags(name, infos)
	width := 0
	for _, s := range l.shown {
		for _, f := range s.flags {
			width = max(width, len(flagCol(f)))
		}
	}
	if all {
		for _, h := range l.hidden {
			for _, f := range h.flags {
				width = max(width, len(flagCol(f)))
			}
		}
	}
	row := func(f flagInfo, line string) { fmt.Fprintf(w, "  %-*s  %s\n", width, flagCol(f), line) }
	for _, s := range l.shown {
		title := s.title
		if title == "" {
			title = "flags"
		}
		fmt.Fprintf(w, "\n%s:\n", title)
		for _, f := range s.flags {
			row(f, flagText(f))
		}
	}
	if !all {
		if n := l.hiddenCount(); n > 0 {
			noun := "flags"
			if n == 1 {
				noun = "flag"
			}
			fmt.Fprintf(w, "\n%d more %s (%s): azhaq %s -h all\n", n, noun, l.moreSummary(), name)
		}
		return
	}
	for _, h := range l.hidden {
		fmt.Fprintf(w, "\n%s:\n", h.title)
		for _, f := range h.flags {
			line := flagText(f)
			if h.why == whyAlias {
				if t := aliasTarget(f, l); t != "" {
					line = "same as -" + t
				}
			}
			row(f, line)
		}
	}
}

// helpAll says whether the arguments ask -h all (or -help all, --help all).
func helpAll(args []string) bool {
	for i, a := range args {
		switch a {
		case "-h", "-help", "--help":
			return i+1 < len(args) && args[i+1] == "all"
		}
	}
	return false
}

// flagNear names the flags closest to a mistyped one, hidden ones too.
func flagNear(name string, names []string) []string {
	limit := 2
	switch {
	case len(name) == 1:
		limit = 0 // a one-letter name is near only in its other case
	case len(name) <= 4:
		limit = 1
	}
	type cand struct {
		name  string
		score int
	}
	var cs []cand
	lower := strings.ToLower(name)
	for _, n := range names {
		ln := strings.ToLower(n)
		d := levenshtein(lower, ln)
		if len(name) == 1 && n == name {
			continue
		}
		if len(name) >= 3 && strings.HasPrefix(ln, lower) {
			d = min(d, 1)
		}
		if d <= limit {
			cs = append(cs, cand{n, d})
		}
	}
	sort.Slice(cs, func(i, j int) bool {
		if cs[i].score != cs[j].score {
			return cs[i].score < cs[j].score
		}
		if len(cs[i].name) != len(cs[j].name) {
			return len(cs[i].name) < len(cs[j].name)
		}
		return cs[i].name < cs[j].name
	})
	var out []string
	for i, c := range cs {
		if i == 3 {
			break
		}
		out = append(out, "-"+c.name)
	}
	return out
}

// withFlagHint adds the closest flag names to the "flag provided but not
// defined" error of the flag package.
func withFlagHint(err error, names []string) error {
	bad, ok := strings.CutPrefix(err.Error(), "flag provided but not defined: -")
	if !ok {
		return err
	}
	near := flagNear(bad, names)
	switch len(near) {
	case 0:
		return err
	case 1:
		return fmt.Errorf("%w; did you mean %s?", err, near[0])
	}
	return fmt.Errorf("%w; did you mean %s or %s?", err, strings.Join(near[:len(near)-1], ", "), near[len(near)-1])
}
