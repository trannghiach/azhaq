package normalize

import (
	"net"
	"net/url"
	"strings"

	"golang.org/x/net/publicsuffix"

	"github.com/trannghiach/azhaq/types"
)

func Seed(s types.Seed) types.Seed {
	out := types.Seed{Type: s.Type, Keys: make(map[string]string, len(s.Keys))}
	for k, v := range s.Keys {
		out.Keys[k] = v
	}
	switch s.Type {
	case types.TypeURL:
		if u, err := URL(s.Keys["url"]); err == nil {
			out.Keys["url"] = u
		}
	case types.TypeHostname:
		out.Keys["fqdn"] = Hostname(s.Keys["fqdn"])
	case types.TypeDomain:
		out.Keys["domain"] = Hostname(s.Keys["domain"])
	}
	return out
}

func URL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errEmpty
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	u.Fragment = ""
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	host, port, err := net.SplitHostPort(u.Host)
	if err == nil {
		if (u.Scheme == "http" && port == "80") || (u.Scheme == "https" && port == "443") {
			u.Host = host
		} else {
			u.Host = net.JoinHostPort(strings.ToLower(host), port)
		}
	}
	if u.Path == "" {
		u.Path = "/"
	}
	// Keep {param} placeholders readable in API templates.
	out := strings.NewReplacer("%7B", "{", "%7D", "}").Replace(u.String())
	return out, nil
}

func Hostname(h string) string {
	h = strings.TrimSpace(strings.ToLower(h))
	return strings.TrimSuffix(h, ".")
}

// sharedPlatforms are multi-tenant suffixes. Two tenants are not one site.
var sharedPlatforms = []string{
	"appspot.com", "web.app", "firebaseapp.com", "herokuapp.com",
	"azurewebsites.net", "cloudfront.net", "github.io", "gitlab.io",
	"netlify.app", "vercel.app", "pages.dev", "workers.dev",
	"ngrok.io", "trycloudflare.com", "s3.amazonaws.com",
	"blob.core.windows.net", "googleusercontent.com", "googleapis.com",
	"cloudfunctions.net", "run.app",
}

// SharedSuffix is the platform name if host is on a shared PaaS.
func SharedSuffix(host string) string {
	host = Hostname(host)
	for _, s := range sharedPlatforms {
		if host == s || strings.HasSuffix(host, "."+s) {
			return s
		}
	}
	return ""
}

// RegistrableDomain is eTLD+1, or empty for IPs and unknowns.
// Shared PaaS hosts stop at the tenant (a.appspot.com, not appspot.com).
func RegistrableDomain(host string) string {
	host = Hostname(host)
	if host == "" || net.ParseIP(host) != nil {
		return ""
	}
	if suf := SharedSuffix(host); suf != "" {
		if host == suf {
			return ""
		}
		rest := strings.TrimSuffix(host, "."+suf)
		if i := strings.LastIndex(rest, "."); i >= 0 {
			rest = rest[i+1:]
		}
		return rest + "." + suf
	}
	d, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return ""
	}
	return Hostname(d)
}

// SameSite is true when both names share a non-empty eTLD+1.
func SameSite(a, b string) bool {
	da, db := RegistrableDomain(a), RegistrableDomain(b)
	return da != "" && da == db
}

func HostFromURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	host := u.Hostname()
	return Hostname(host)
}

// SpecialUse is true for RFC 2606 / 6761 names that cannot exist on the
// public internet (.test, .localhost, .invalid, .example, .local).
func SpecialUse(host string) bool {
	h := Hostname(host)
	if h == "" || net.ParseIP(h) != nil {
		return false
	}
	labels := strings.Split(h, ".")
	switch labels[len(labels)-1] {
	case "test", "example", "invalid", "localhost", "local":
		return true
	default:
		return false
	}
}

type emptyError struct{}

func (emptyError) Error() string { return "empty" }

var errEmpty emptyError
