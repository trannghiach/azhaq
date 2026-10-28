package main

import (
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

// Refusals answered as success: a "200 Access denied" page. Each origin's
// is learned from the anonymous role's answers on endpoints a signed-in
// role reads otherwise, and -refusal says what one looks like; such an
// answer counts as refused for every role.

// refusalPage is how an origin refuses with a 2xx answer.
type refusalPage struct {
	origin string
	status int
	hash   string   // the body's, when it does not change
	said   string   // its title and first heading, or its JSON message
	keys   []string // a JSON refusal's top-level fields
	urls   int      // the endpoints the anonymous role got it on
}

var (
	// refusalWords say on their own that the visitor may not see the page.
	refusalWords = regexp.MustCompile(`(?i)\b(access (is )?denied|permission denied|not authori[sz]ed|unauthori[sz]ed|forbidden|not allowed|no access|(login|authentication|authorization) required|please (log|sign) ?in|you must (be )?(log|sign)(ged)? ?in|session (has )?expired|insufficient (permissions|privileges|rights))\b`)
	// signInWords say it when the same page stands for several endpoints.
	signInWords = regexp.MustCompile(`(?i)\b(log ?in|sign ?in|log ?on)\b`)
)

// saidOf is what an answer says, from its kept body when it was not read.
func saidOf(a answer) string {
	if a.said != "" {
		return a.said
	}
	if b, ctype, _, ok := keptBodyOf(a.Hash); ok {
		title, said := sayOf(b, ctype)
		if said == "" {
			said = title
		}
		return said
	}
	return a.Title
}

func originOf(u string) string {
	p, err := url.Parse(u)
	if err != nil {
		return ""
	}
	return strings.ToLower(p.Scheme + "://" + p.Host)
}

// learnRefusals finds each origin's refusal pages: what the anonymous role
// got with a 2xx status on endpoints a signed-in role reads otherwise,
// when it says so (access denied, forbidden, …: one endpoint is enough),
// or asks to sign in on two endpoints or more.
func learnRefusals(roles []role, answers map[string]map[string]answer) []refusalPage {
	anon := ""
	for _, r := range roles {
		if r.anonymous() {
			anon = r.name
			break
		}
	}
	if anon == "" {
		return nil
	}
	groups := map[string]*refusalPage{}
	for _, u := range sortedKeys(mapKeys(answers[anon])) {
		a := answers[anon][u]
		if !reads(a) {
			continue
		}
		other := false
		for _, r := range roles {
			if b, ok := answers[r.name][u]; ok && !r.anonymous() && reads(b) && b.Hash != a.Hash {
				other = true
			}
		}
		said := saidOf(a)
		if !other || !refusalWords.MatchString(said) && !signInWords.MatchString(said) {
			continue
		}
		k := fmt.Sprintf("%s\x00%d\x00%s", originOf(u), a.Status, said)
		p := groups[k]
		if p == nil {
			p = &refusalPage{origin: originOf(u), status: a.Status, hash: a.Hash, said: said, keys: a.top}
			groups[k] = p
		} else if p.hash != a.Hash {
			p.hash = "" // it changes: told by what it says
		}
		p.urls++
	}
	var out []refusalPage
	for _, k := range sortedKeys(mapKeys(groups)) {
		if p := groups[k]; refusalWords.MatchString(p.said) || p.urls >= 2 {
			out = append(out, *p)
		}
	}
	return out
}

// matchesPage: a 2xx answer at u is one of its origin's refusal pages.
func matchesPage(u string, a answer, pages []refusalPage) bool {
	if !ok2xx(a.Status) || len(pages) == 0 {
		return false
	}
	o := originOf(u)
	for _, p := range pages {
		if p.origin != o || p.status != a.Status {
			continue
		}
		if p.hash != "" && a.Hash == p.hash {
			return true
		}
		if saidOf(a) == p.said && (len(p.keys) == 0 || slices.Equal(a.top, p.keys)) {
			return true
		}
	}
	return false
}

// markRefusals marks every 2xx answer that is its origin's refusal page,
// or whose body re matches, as refused. n: how many.
func markRefusals(answers map[string]map[string]answer, pages []refusalPage, re *regexp.Regexp) (byPage, byRE int) {
	for _, as := range answers {
		for u, a := range as {
			if !ok2xx(a.Status) || a.Error || a.Refusal {
				continue
			}
			switch {
			case matchesPage(u, a, pages):
				byPage++
			case re != nil && bodyMatches(a, re):
				byRE++
			default:
				continue
			}
			a.Refusal = true
			as[u] = a
		}
	}
	return byPage, byRE
}

// bodyMatches: re matches the answer's kept body, or, without one, what it
// says.
func bodyMatches(a answer, re *regexp.Regexp) bool {
	if b, _, _, ok := keptBodyOf(a.Hash); ok {
		return re.Match(b)
	}
	return re.MatchString(saidOf(a))
}

// refusalNotes say which pages count as refusals.
func refusalNotes(pages []refusalPage, byRE int, re *regexp.Regexp) []string {
	var out []string
	for _, p := range pages {
		out = append(out, fmt.Sprintf("%s refuses with a %d page saying %q (the anonymous role got it on %s a signed-in role reads otherwise): such an answer counts as refused for every role",
			p.origin, p.status, p.said, plural(p.urls, "endpoint")))
	}
	if re != nil {
		out = append(out, fmt.Sprintf("-refusal %s matched %s, counted as refused", re, plural(byRE, "2xx answer")))
	}
	return out
}
