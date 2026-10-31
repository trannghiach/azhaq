package hunt

import (
	"net/url"
	"strings"
)

// next is the command to run for a row, chosen by the signal that weighs
// most in it. db is the workspace path as the user gave it.
func (c *cand) next(db, best string) string {
	show := "azhaq show -db " + quote(db) + " " + quote(c.instance())
	switch {
	case best == "cross-role":
		u := c.roleURL
		if u == "" {
			u = c.key
		}
		if c.roleDir == "" {
			return show // the roles run's directory is not known: the row's own view
		}
		cmd := "azhaq roles show -dir " + quote(c.roleDir) + " " + quote(u)
		if c.roleM != "" {
			cmd += " -method " + c.roleM
		}
		return cmd
	case best == "object-id":
		return "azhaq roles -role anon -role 'user=Authorization: Bearer …' -- -url " + quote(c.originOrKey())
	case best == "input" && c.typ == "URL":
		return "azhaq params -u " + quote(c.instance()) + " -w WORDLIST"
	}
	return show
}

// originOrKey is the target an access-control run is pointed at.
func (c *cand) originOrKey() string {
	if c.origin != "" {
		return c.origin + "/"
	}
	if u, err := url.Parse(c.key); err == nil && u.Host != "" {
		return u.Scheme + "://" + u.Host + "/"
	}
	return c.key
}

// instance is a URL the route was seen at, for a command that asks it.
func (c *cand) instance() string {
	if len(c.instances) > 0 {
		return c.instances[0]
	}
	return c.key
}

// quote leaves a plain word alone and single-quotes anything a shell would
// split or expand.
func quote(s string) string {
	if s != "" && strings.IndexFunc(s, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("/:._-=+@%,", r))
	}) < 0 {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
