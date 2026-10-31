package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/trannghiach/azhaq/internal/egress"
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
	// more: it read an endpoint the anonymous role did not, or was
	// forbidden (403) where the anonymous role was asked to sign in
	// (401): the site knew who it was.
	more bool
}

// sessionStates judges each signed-in role's session: dead when it is
// refused wherever a session matters (on every endpoint the anonymous
// role is refused and another signed-in role reads, or, when no
// signed-in role reads any of them, every endpoint the anonymous role is
// refused), or refused on every endpoint another role reads; and it reads
// no "/me" endpoint unlike the anonymous role. Tokens copied together
// expire together: with every session dead, none reads what the
// anonymous role is refused, and each is judged alone; then a role that
// got more than the anonymous role anywhere is alive (users refused an
// admin area).
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
			if b, ok := row.Answers[anon]; anon != "" && (mine && (!ok || !reads(b)) || ok && b.Status == 401 && a.Status == 403) {
				s.more = true
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
		refused := s.gated > 0 && s.gatedRead == 0 && (!alone || !s.more)
		s.dead = !me && (refused || others > 0 && othersLet == 0)
		out[x.name] = s
	}
	return out
}

// credentialName: a header or cookie that carries a credential by its
// name (X-Auth-Token, X-Api-Key, session, connect.sid, jwt); an analytics
// cookie (_ga_id) does not.
var credentialName = regexp.MustCompile(`(?i)token|jwt|auth|sess|sid|access|bearer|identity|api[-_]?key|apikey`)

// tokenExpiry is the earliest expiry ("exp") of the JSON Web Tokens the
// headers carry as a credential (in Authorization, or a header or cookie
// named for one), zero when none says; sole: every credential they carry
// is such a token, expired by then, so what the role reads, it reads on
// an expired token.
func tokenExpiry(h http.Header, now time.Time) (first time.Time, sole bool) {
	var exps []time.Time
	others := 0
	credential := func(v string) {
		t := jwtValue.FindString(v)
		exp, ok := claims(t)["exp"].(float64)
		if t == "" || !ok || exp <= 0 || exp > 1e11 {
			others++
			return
		}
		exps = append(exps, time.Unix(int64(exp), 0))
	}
	for k, vs := range h {
		for _, v := range vs {
			switch {
			case strings.EqualFold(k, "Cookie"):
				for _, c := range strings.Split(v, ";") {
					if name, val, ok := strings.Cut(strings.TrimSpace(c), "="); ok && credentialName.MatchString(name) {
						credential(val)
					}
				}
			case strings.EqualFold(k, "Authorization") || credentialName.MatchString(k):
				credential(v)
			}
		}
	}
	last := time.Time{}
	for _, at := range exps {
		if first.IsZero() || at.Before(first) {
			first = at
		}
		if at.After(last) {
			last = at
		}
	}
	return first, others == 0 && len(exps) > 0 && !last.After(now)
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
	switch {
	case d < time.Minute:
		return "under a minute"
	case d >= 48*time.Hour:
		return fmt.Sprintf("%d days", int(d/(24*time.Hour)))
	}
	return strings.TrimSuffix(d.String(), "0s")
}

// expiry is when a role's token expired, and whether it was the role's
// only credential.
type expiry struct {
	at   time.Time
	sole bool
}

// expiryNotes are said before any request: the tokens a role carries
// that have expired (stale; the end of the run says what came of them),
// or will expire within the quarter hour (soon).
func expiryNotes(roles []role, now time.Time) (stale, soon []string, expired map[string]expiry) {
	expired = map[string]expiry{}
	for _, r := range roles {
		exp, sole := tokenExpiry(headerOf(r.headers), now)
		switch {
		case exp.IsZero():
		case !exp.After(now):
			expired[r.name] = expiry{exp, sole}
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
func sessionNotes(roles []role, rows []roleRow, expired map[string]expiry, own map[string]bool) (notes []string, warn bool, asked int) {
	states := sessionStates(roles, rows)
	for _, r := range roles {
		s, ok := states[r.name]
		if !ok {
			continue
		}
		e, wasExpired := expired[r.name]
		exp := e.at
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
		case wasExpired && !e.sole:
			// Another credential may carry the session: the answers said
			// it is alive.
		case wasExpired && s.beyond > 0:
			notes = append(notes, fmt.Sprintf("role %s's token expired at %s, yet the site still let it read %s the anonymous role is refused: check that it verifies token expiry",
				r.name, exp.UTC().Format(time.RFC3339), plural(s.beyond, "endpoint")))
		case wasExpired:
			warn = true // its only credential expired, and nothing tells
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
	egress.SetScope(func(h string) bool { return own[normalize.Hostname(h)] })
	holdDeny()
	fetch.Extra = r.session.Clone()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	res, _, err := fetch.Do(ctx, fetch.Client(nil), u)
	if err != nil || res.Status >= 200 && res.Status < 300 {
		return ""
	}
	return hideSent(reasonText(res.Body, contentType(res)), r.session)
}

// hideSent takes out of text every value the role sent: its headers'
// values, each cookie's value, the credential after Bearer or Basic. A
// refusal may echo the session it refused.
func hideSent(text string, h http.Header) string {
	var sent []string
	for _, vs := range h {
		for _, v := range vs {
			sent = append(sent, v)
			for _, part := range strings.FieldsFunc(v, func(r rune) bool { return r == ';' || r == ' ' || r == ',' }) {
				if _, val, ok := strings.Cut(part, "="); ok {
					part = val
				}
				sent = append(sent, part)
			}
		}
	}
	// The longest first: a cookie's value inside the whole header.
	slices.SortFunc(sent, func(a, b string) int { return len(b) - len(a) })
	for _, v := range sent {
		if len(v) >= 6 {
			text = strings.ReplaceAll(text, v, "…")
		}
	}
	return text
}

var (
	credentialish = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}(\.[A-Za-z0-9_-]*){0,2}|[A-Za-z0-9+/_.%-]{16,}={0,2}`)
	titleTag      = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
)

// hideCredentials takes out what looks like a credential: a JSON Web
// Token, or a run of 16 characters or more mixing letters and digits (a
// session id, a key, base64): words are left.
func hideCredentials(s string) string {
	return credentialish.ReplaceAllStringFunc(s, func(m string) string {
		letter, digit := false, false
		for _, r := range m {
			letter = letter || unicode.IsLetter(r)
			digit = digit || unicode.IsDigit(r)
		}
		if strings.HasPrefix(m, "eyJ") || letter && digit {
			return "…"
		}
		return m
	})
}

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
	said = hideCredentials(said)
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
