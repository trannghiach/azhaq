package main

import (
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"

	"github.com/trannghiach/azhaq/engine"
	"github.com/trannghiach/azhaq/internal/fuzz"
	"github.com/trannghiach/azhaq/store"
	"github.com/trannghiach/azhaq/types"
)

// A hint is a "next:" line for a person at a terminal: a command that
// follows from what this run measured, with the measurement as its reason.
// Hints are not in the JSON summary, and none is printed with -silent,
// -json or -jsonl, nor when stderr is not a terminal unless -v is given.

// maxHints is how many hint lines a summary holds.
const maxHints = 2

// hintTerminal says whether stderr is a terminal; a test replaces it.
var hintTerminal = stderrIsTerminal

// hint adds a suggestion, "COMMAND   (why)", once.
func (r *report) hint(line string) {
	if line != "" && !slices.Contains(r.hints, line) {
		r.hints = append(r.hints, line)
	}
}

// lateHint adds a suggestion that is made last, after the others, and only
// when there is room: f returns "" for none. It runs when the summary is
// printed and the hints are shown, so it may record that it was shown.
func (r *report) lateHint(f func() string) { r.late = append(r.late, f) }

// hintsShown says whether this summary carries hints.
func (r *report) hintsShown() bool {
	return !r.hintsOff && os.Getenv("AZHAQ_NO_HINTS") == "" && (r.hintsVrb || hintTerminal())
}

// shownHints is the hints to print, at most maxHints, the late ones last.
func (r *report) shownHints() []string {
	if !r.hintsShown() {
		return nil
	}
	out := slices.Clone(r.hints)
	if len(out) > maxHints {
		out = out[:maxHints]
	}
	for _, f := range r.late {
		if len(out) >= maxHints {
			break
		}
		if h := f(); h != "" && !slices.Contains(out, h) {
			out = append(out, h)
		}
	}
	r.late = nil
	return out
}

// runTargetOf is the one target of a run's arguments as run's own flag,
// "-domain example.com" or "-url https://example.com/", or "" when the
// arguments name none, several, or a bare host (its scheme would be a guess).
func runTargetOf(args []string) string {
	var domains, urls []string
	var list string
	for i := 0; i < len(args); i++ {
		name, val, hasVal := strings.Cut(strings.TrimLeft(args[i], "-"), "=")
		if !strings.HasPrefix(args[i], "-") || !slices.Contains([]string{"domain", "url", "list"}, name) {
			continue
		}
		if !hasVal {
			if i+1 >= len(args) {
				break
			}
			i++
			val = args[i]
		}
		switch name {
		case "domain":
			domains = append(domains, val)
		case "url":
			urls = append(urls, val)
		default:
			list = val
		}
	}
	if list != "" {
		lines, err := loadLines(list)
		if err != nil || len(lines) != 1 || len(domains)+len(urls) > 0 || !strings.Contains(lines[0], "://") {
			return ""
		}
		urls = lines
	}
	switch {
	case len(domains) == 1 && len(urls) == 0:
		return "-domain " + domains[0]
	case len(urls) == 1 && len(domains) == 0:
		return "-url " + urls[0]
	}
	return ""
}

// runHint points a drop-in command's user to run, once for each workspace
// (recorded in it) so it does not nag; without -db there is no workspace to
// record it in.
func runHint(st *store.Store, db, target string) string {
	const key = "hint:run"
	line := "azhaq run " + target
	if db != "" {
		if st.GetMeta(key) != "" {
			return ""
		}
		_ = st.SetMeta(key, "shown")
		line += " -db " + db
	}
	return line + "   (one command: names, services, crawl, files and a ranked map, in one workspace)"
}

// signedIn says whether a run was given a session: a sign-in, a cookie or
// an Authorization or Cookie header.
func signedIn(login string, cookies, headers []string) bool {
	if login != "" || len(cookies) > 0 {
		return true
	}
	return slices.ContainsFunc(headers, func(h string) bool {
		name, _, _ := strings.Cut(h, ":")
		name = strings.ToLower(strings.TrimSpace(name))
		return name == "authorization" || name == "cookie"
	})
}

func signedInKey(run string) string { return "signed-in:" + run }

// rolesHint is the command that tests what one account reaches of another's.
const rolesHint = "azhaq roles -role anon -role 'user=Authorization: Bearer …' -- RUN FLAGS   (the run was signed in: test what one account can reach of another's)"

// runHints are the hints that follow from what a run measured: a catch-all
// page its front page is a shell for, and a session with no roles test.
func runHints(rep *report, rows []engine.MapEntry, obs []types.StoredObservation, interact, signed bool) {
	browserSaid := slices.ContainsFunc(rep.Next, func(n string) bool { return strings.Contains(n, "-browser") })
	if ca := engine.CatchAllShell(rows, obs); ca.Origin != "" && !interact && !browserSaid {
		rep.hint(catchAllHint("azhaq run -url "+ca.Origin+"/ -browser -interact", ca))
	}
	if signed && rep.Counts["auth"] == 0 {
		rep.hint(rolesHint)
	}
}

func catchAllHint(cmd string, ca engine.CatchAll) string {
	return fmt.Sprintf("%s   (%s of %s answered with the page every unknown path gets; Chrome clicks find the routes only a click shows)", cmd, plural(ca.Routes, "URL"), ca.Origin)
}

// tokenField matches the name of a request field that carries an anti-forgery
// token: csrf_token, _token, authenticity_token, __RequestVerificationToken.
var tokenField = regexp.MustCompile(`(?i)(?:^|[?&{,\s"'])["']?([\w.-]*(?:csrf|xsrf|authenticity_token|requestverificationtoken|nonce)[\w.-]*|_token)["']?\s*[=:]\s*["']?[^&"'\s,}]`)

// tokenHint is the preflight command for a form that wants a token: the
// request sends a token field with a value fixed on the command line, and
// at least 10 answers came back with 80% of them 403 or 419. "" otherwise;
// that is all it measures, so a refusal for another reason is not claimed.
func tokenHint(t fuzz.Template, answered, refused int) string {
	if answered < 10 || refused*100 < answered*80 {
		return ""
	}
	var name string
	for _, part := range []string{t.URL, t.Data} {
		if m := tokenField.FindStringSubmatch(part); m != nil {
			name = m[1]
			break
		}
	}
	if name == "" {
		return ""
	}
	return fmt.Sprintf("azhaq fuzz … -preflight PAGE.req -preflight-var-auto TOKEN:%s   (the request sends %s with a fixed value and %d of %d answers were 403 or 419; the preflight reads a fresh one before each request, and TOKEN stands for it)", name, name, refused, answered)
}

// signedWorkspace says whether a run in the workspace was signed in.
func signedWorkspace(path string) bool {
	st, err := store.OpenExisting(path)
	if err != nil {
		return false
	}
	defer st.Close()
	runs, _ := st.Runs()
	return slices.ContainsFunc(runs, func(r store.Run) bool { return st.GetMeta(signedInKey(r.ID)) != "" })
}
