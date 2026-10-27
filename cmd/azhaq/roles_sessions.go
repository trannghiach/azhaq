package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/internal/normalize"
)

// sessionState is what the answers say of one signed-in role's session.
type sessionState struct {
	dead      bool
	gated     int    // endpoints the anonymous role was asked to sign in for
	gatedRead int    // of those, the ones this role read
	beyond    int    // endpoints the anonymous role is asked to sign in for that this role reads
	refusedAt string // a gated endpoint that refused it, to ask again for the reason
}

// sessionStates judges each signed-in role's session: dead when it is
// refused wherever a session matters (on every endpoint the anonymous
// role is refused and another signed-in role reads, or, when no
// signed-in role reads any of them, every endpoint the anonymous role is
// refused), or refused on every endpoint another role reads; and it reads
// no "/me" endpoint unlike the anonymous role. Tokens copied together
// expire together: with every session dead, none reads what the
// anonymous role is refused, and each is judged alone.
func sessionStates(roles []role, rows []roleRow) map[string]sessionState {
	anon, signed := "", 0
	for _, r := range roles {
		switch {
		case !r.anonymous():
			signed++
		case anon == "":
			anon = r.name
		}
	}
	// gate: the anonymous visitor was asked for a session (401, 403, a
	// sign-in page), not told the page is missing.
	gate := func(row roleRow, no map[string]bool) bool {
		b, ok := row.Answers[anon]
		return ok && anon != "" && no[anon] && (b.Status == 401 || b.Status == 403 || b.toLogin)
	}
	alone := signed == 1
	if !alone {
		alone = true
		for _, row := range rows {
			if !gate(row, refusing(row)) {
				continue
			}
			for _, r := range roles {
				if a, ok := row.Answers[r.name]; ok && !r.anonymous() && reads(a) {
					alone = false
				}
			}
		}
	}
	out := map[string]sessionState{}
	for _, x := range roles {
		if x.anonymous() {
			continue
		}
		var s sessionState
		others, othersLet, me := 0, 0, false
		for _, row := range rows {
			a, ok := row.Answers[x.name]
			if !ok {
				continue
			}
			no := refusing(row)
			otherSigned, otherAny := false, false
			for _, r := range roles {
				if b, ok := row.Answers[r.name]; ok && r.name != x.name && reads(b) {
					otherAny = true
					otherSigned = otherSigned || !r.anonymous()
				}
			}
			mine := reads(a)
			if mine && gate(row, no) {
				s.beyond++
			}
			if gate(row, no) && (otherSigned || alone) {
				s.gated++
				if mine {
					s.gatedRead++
				} else if s.refusedAt == "" && no[x.name] {
					s.refusedAt = row.URL
				}
			}
			if otherAny {
				others++
				if !no[x.name] {
					othersLet++
				}
			}
			if b, ok := row.Answers[anon]; mine && meLike(row.URL) && len(a.Keys) > 0 && (!ok || !reads(b) || b.Hash != a.Hash) {
				me = true // a JSON "/me" answer of its own
			}
		}
		s.dead = !me && (s.gated > 0 && s.gatedRead == 0 || others > 0 && othersLet == 0)
		out[x.name] = s
	}
	return out
}

// tokenExpiry is the earliest expiry ("exp") of the JSON Web Tokens the
// headers carry, in an Authorization header, a cookie or any other; zero
// when none says.
func tokenExpiry(h http.Header) time.Time {
	var first time.Time
	for _, vs := range h {
		for _, v := range vs {
			for _, t := range jwtValue.FindAllString(v, 4) {
				exp, ok := claims(t)["exp"].(float64)
				if !ok || exp <= 0 || exp > 1e11 {
					continue
				}
				at := time.Unix(int64(exp), 0)
				if first.IsZero() || at.Before(first) {
					first = at
				}
			}
		}
	}
	return first
}

// headerOf is a role's -role headers as a header.
func headerOf(lines []string) http.Header {
	h := http.Header{}
	for _, l := range lines {
		if k, v, ok := strings.Cut(l, ":"); ok {
			h.Add(strings.TrimSpace(k), strings.TrimSpace(v))
		}
	}
	return h
}

// ago says how long before now t was, to the minute.
func ago(now, t time.Time) string {
	d := now.Sub(t).Round(time.Minute)
	if d < time.Minute {
		return "under a minute"
	}
	return strings.TrimSuffix(d.String(), "0s")
}

// expiryNotes are said before any request: the tokens a role carries
// that have expired (stale; the end of the run says what came of them),
// or will expire within the quarter hour (soon).
func expiryNotes(roles []role, now time.Time) (stale, soon []string, expired map[string]time.Time) {
	expired = map[string]time.Time{}
	for _, r := range roles {
		exp := tokenExpiry(headerOf(r.headers))
		switch {
		case exp.IsZero():
		case !exp.After(now):
			expired[r.name] = exp
			stale = append(stale, fmt.Sprintf("role %s carries a token that expired %s ago (exp %s): sign in again and pass the new one, or let -role-cmd fetch one at run time",
				r.name, ago(now, exp), exp.UTC().Format(time.RFC3339)))
		case exp.Before(now.Add(15 * time.Minute)):
			soon = append(soon, fmt.Sprintf("role %s carries a token that expires in %s (exp %s): a longer run ends with a dead session",
				r.name, ago(exp, now), exp.UTC().Format(time.RFC3339)))
		}
	}
	return stale, soon, expired
}

// sessionNotes say which sessions look dead, with the site's own words
// when asking one gated endpoint again gets a reason, and which expired
// tokens the site still took. warn: a dead session, whose role's rows are
// a visitor's.
func sessionNotes(roles []role, rows []roleRow, expired map[string]time.Time, own map[string]bool) (notes []string, warn bool, asked int) {
	states := sessionStates(roles, rows)
	for _, r := range roles {
		s, ok := states[r.name]
		if !ok {
			continue
		}
		exp, wasExpired := expired[r.name]
		switch {
		case s.dead:
			warn = true
			why := ""
			if s.refusedAt != "" {
				asked++
				if said := refusalReason(r, s.refusedAt, own); said != "" {
					why = fmt.Sprintf(" (the site said %q)", said)
				}
			}
			tail := "its session looks expired or wrong"
			if wasExpired {
				tail = "its token expired at " + exp.UTC().Format(time.RFC3339)
			}
			notes = append(notes, fmt.Sprintf("role %s was refused wherever a session matters%s: %s; its rows show what a visitor gets", r.name, why, tail))
		case wasExpired && s.beyond > 0:
			notes = append(notes, fmt.Sprintf("role %s's token expired at %s, yet the site still let it read %s the anonymous role is refused: check that it verifies token expiry",
				r.name, exp.UTC().Format(time.RFC3339), plural(s.beyond, "endpoint")))
		case wasExpired:
			warn = true
			notes = append(notes, fmt.Sprintf("role %s's token expired at %s and nothing it was asked tells whether the site still takes it", r.name, exp.UTC().Format(time.RFC3339)))
		}
	}
	return notes, warn, asked
}

// deadRoles are the signed-in roles whose sessions look expired or wrong.
func deadRoles(roles []role, rows []roleRow) []string {
	states := sessionStates(roles, rows)
	var out []string
	for _, r := range roles {
		if states[r.name].dead {
			out = append(out, r.name)
		}
	}
	return out
}

// refusalReason asks u again in role r and gives the reason the refusal
// states: a JSON answer's message, an HTML page's title, or a short text
// answer, with anything shaped like a credential taken out.
func refusalReason(r role, u string, own map[string]bool) string {
	fetch.Reset()
	defer fetch.Reset()
	fetch.Allow = func(h string) bool { return own[normalize.Hostname(h)] }
	fetch.Extra = r.session.Clone()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	res, _, err := fetch.Do(ctx, fetch.Client(nil), u)
	if err != nil || res.Status >= 200 && res.Status < 300 {
		return ""
	}
	return reasonText(res.Body, contentType(res))
}

var (
	credentialish = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}(\.[A-Za-z0-9_-]*){0,2}|[A-Za-z0-9+/_-]{32,}={0,2}`)
	titleTag      = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
)

// reasonText is what a refusal says, at most 100 characters.
func reasonText(body []byte, ctype string) string {
	var said string
	var v any
	switch {
	case json.Unmarshal(body, &v) == nil:
		said = messageOf(v, 0)
	case strings.Contains(ctype, "html"):
		if m := titleTag.FindSubmatch(body); m != nil {
			said = string(m[1])
		}
	case len(body) <= 300:
		said = string(body)
	}
	said = credentialish.ReplaceAllString(said, "…")
	said = strings.Join(strings.FieldsFunc(said, func(r rune) bool { return unicode.IsSpace(r) || !unicode.IsPrint(r) }), " ")
	if r := []rune(said); len(r) > 100 {
		said = string(r[:100]) + "…"
	}
	return said
}

// messageOf finds a refusal's message in a JSON answer: {"message":…},
// {"error":{"message":…}}, {"errors":[{"detail":…}]}.
func messageOf(v any, depth int) string {
	if depth > 3 {
		return ""
	}
	switch t := v.(type) {
	case map[string]any:
		for _, k := range []string{"message", "msg", "detail", "error_description", "errormessage", "error", "reason", "title", "description", "status"} {
			for key, x := range t {
				if norm(key) != norm(k) {
					continue
				}
				if s, ok := x.(string); ok && strings.TrimSpace(s) != "" {
					return s
				}
				if s := messageOf(x, depth+1); s != "" {
					return s
				}
			}
		}
		for key, x := range t {
			if n := norm(key); n == "errors" || n == "data" {
				if s := messageOf(x, depth+1); s != "" {
					return s
				}
			}
		}
	case []any:
		if len(t) > 0 {
			return messageOf(t[0], depth+1)
		}
	}
	return ""
}
