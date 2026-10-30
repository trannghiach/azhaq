// Package crawlscope decides which links a crawl follows: the field scope
// of katana's -fs (rdn, fqdn, dn or a host regex), its -cs and -cos URL
// regexes, and -ns. Without a configuration a link must be on the page's
// own origin, as every other command reads pages.
package crawlscope

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"

	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/internal/normalize"
	"github.com/trannghiach/azhaq/internal/webextract"
)

// Field "rdn-origin" is rdn for names, and for an address (a lab, a dev
// box) its own port only: crawl's default, so that a link to another dev
// port of the host is listed under -do instead of requested.
//
// Config is a crawl's scope. The field rules follow projectdiscovery/katana
// (MIT), pkg/utils/scope: rdn is the root domain and its subdomains, fqdn
// the root host only, dn any host naming the root's domain keyword, and
// anything else a regex on the host. An address is only itself.
type Config struct {
	Field string   // "", rdn, fqdn, dn, or a regex on the host
	In    []string // URL regexes: one must match
	Out   []string // URL regexes: none may match
	Any   bool     // no field scope (-ns); -allow, -deny and the URL regexes still hold
	Roots []string // start URLs: the hosts the field scope is read from

	field *regexp.Regexp
	in    []*regexp.Regexp
	out   []*regexp.Regexp
	roots []string
}

var cur atomic.Pointer[Config]

// Set installs the crawl's scope. An empty Field with no other rule leaves
// the same-origin default.
func Set(c Config) error {
	switch c.Field {
	case "", "origin", "rdn", "fqdn", "dn", "rdn-origin":
	default:
		re, err := regexp.Compile(c.Field)
		if err != nil {
			return fmt.Errorf("scope %q is not rdn, fqdn, dn or a regex: %v", c.Field, err)
		}
		c.field = re
	}
	for _, s := range c.In {
		re, err := regexp.Compile(s)
		if err != nil {
			return fmt.Errorf("-crawl-in %q: %v", s, err)
		}
		c.in = append(c.in, re)
	}
	for _, s := range c.Out {
		re, err := regexp.Compile(s)
		if err != nil {
			return fmt.Errorf("-crawl-out %q: %v", s, err)
		}
		c.out = append(c.out, re)
	}
	for _, r := range c.Roots {
		if u, err := url.Parse(r); err == nil && u.Hostname() != "" {
			c.roots = append(c.roots, strings.ToLower(u.Hostname()))
		}
	}
	cur.Store(&c)
	return nil
}

// Reset goes back to the same-origin default.
func Reset() { cur.Store(nil) }

// Wide says whether the crawl may leave a page's origin (so that the links
// it does not follow are worth saying).
func Wide() bool {
	c := cur.Load()
	return c != nil && (c.Field != "" && c.Field != "origin" || c.Any)
}

// Within says whether a crawl that reads page follows link.
func Within(page, link string) bool {
	c := cur.Load()
	if c == nil || (c.Field == "" || c.Field == "origin") && !c.Any {
		if !webextract.SameOrigin(page, link) {
			return false
		}
		return c == nil || c.urlOK(link)
	}
	lu, err := url.Parse(link)
	if err != nil || lu.Hostname() == "" {
		return false
	}
	if fetch.Allow != nil && !fetch.Allow(lu.Hostname()) {
		return false
	}
	if !c.Any && !c.hostOK(page, lu.Hostname()) {
		return false
	}
	if c.Field == "rdn-origin" && net.ParseIP(lu.Hostname()) != nil && !webextract.SameOrigin(page, link) {
		return false
	}
	return c.urlOK(link)
}

func (c *Config) urlOK(link string) bool {
	for _, re := range c.out {
		if re.MatchString(link) {
			return false
		}
	}
	if len(c.in) == 0 {
		return true
	}
	for _, re := range c.in {
		if re.MatchString(link) {
			return true
		}
	}
	return false
}

// hostOK reads the field scope from the root the page is in (the start
// URL whose scope holds the page's host), else from the page's own host.
func (c *Config) hostOK(page, host string) bool {
	pu, err := url.Parse(page)
	if err != nil {
		return false
	}
	ph := strings.ToLower(pu.Hostname())
	for _, r := range c.roots {
		if c.rootOK(r, ph) && c.rootOK(r, host) {
			return true
		}
	}
	if len(c.roots) > 0 {
		return false
	}
	return c.rootOK(ph, host)
}

func (c *Config) rootOK(root, host string) bool {
	host = strings.ToLower(host)
	if c.field != nil && c.field.MatchString(host) {
		return true
	}
	if net.ParseIP(host) != nil || c.Field == "fqdn" || c.field != nil {
		return host == root
	}
	rdn := normalize.RegistrableDomain(root)
	if rdn == "" {
		return host == root
	}
	switch c.Field {
	case "dn":
		kw, _, _ := strings.Cut(rdn, ".")
		return strings.Contains(host, kw)
	default: // rdn, rdn-origin
		return host == rdn || strings.HasSuffix(host, "."+rdn)
	}
}
