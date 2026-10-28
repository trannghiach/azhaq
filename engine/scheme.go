package engine

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"

	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/internal/neterr"
	"github.com/trannghiach/azhaq/internal/normalize"
	"github.com/trannghiach/azhaq/types"
)

// A run given https://host/ finds http://host/… URLs in archives and in
// links: most often the same site, mapped twice at twice the cost. One
// request to http://host/ decides. When it redirects to https on the same
// host, serves the same front page (and, behind a redirect, the same page
// at the end of it), or nothing listens on port 80, the http URLs are the
// https site's and are mapped as https. Otherwise
// http://host/ is a service of its own, and its URLs stay as they are.
// The other names of the target's domain (www., the apex) are asked the
// same way: a site that serves https on one serves it on the others.

// heldHint is a hint waiting for its host's answer.
type heldHint struct {
	seed  types.Seed
	depth int
}

// httpsGiven is where the run was given https on the default port: the
// hosts (host, or [v6]) and their registrable domains; and the hosts it
// was given over plain http, which are left as they are.
type httpsGiven struct {
	hosts, domains, plain map[string]bool
}

func givenHTTPS(seeds []types.Seed) httpsGiven {
	g := httpsGiven{hosts: map[string]bool{}, domains: map[string]bool{}, plain: map[string]bool{}}
	for _, raw := range seeds {
		s := normalize.Seed(raw)
		if s.Type != types.TypeURL {
			continue
		}
		u, err := url.Parse(s.Key())
		if err != nil {
			continue
		}
		switch {
		case u.Scheme == "http":
			g.plain[u.Host] = true
		case u.Scheme == "https" && u.Port() == "":
			g.hosts[u.Host] = true
			if d := normalize.RegistrableDomain(u.Hostname()); d != "" {
				g.domains[d] = true
			}
		}
	}
	return g
}

// covers: http URLs on host are asked about.
func (g httpsGiven) covers(host string) bool {
	if g.plain[host] {
		return false
	}
	if g.hosts[host] {
		return true
	}
	d := normalize.RegistrableDomain(strings.Trim(host, "[]"))
	return d != "" && g.domains[d]
}

// scheme gives an http://host/… hint on a host of the https target as its
// https URL, once http://host/ is known to be the same site. held: the
// question is out and the hint waits for its answer.
func (s *scheduler) scheme(seed types.Seed, depth int) (types.Seed, bool) {
	if seed.Type != types.TypeURL || s.b.Passive || len(s.secure.hosts) == 0 {
		return seed, false
	}
	u, err := url.Parse(seed.Key())
	if err != nil || u.Scheme != "http" || u.Port() != "" || !s.secure.covers(u.Host) {
		return seed, false
	}
	same, known := s.schemes[u.Host]
	if !known {
		if !s.asked[u.Host] {
			s.asked[u.Host] = true
			s.askScheme(u.Host)
		}
		s.waiting[u.Host] = append(s.waiting[u.Host], heldHint{seed, depth})
		return seed, true
	}
	if !same {
		return seed, false
	}
	u.Scheme = "https"
	keys := maps.Clone(seed.Keys)
	keys["url"] = u.String()
	return normalize.Seed(types.Seed{Type: seed.Type, Keys: keys}), false
}

// askScheme asks whether http://host/ is the https site, off the loop:
// the answer comes back as a finished item, once the URLs found so far
// are moved over.
func (s *scheduler) askScheme(host string) {
	s.inflight++
	client := fetch.Client(s.e.Client)
	ctx := s.ctx
	go func() {
		same := sameSite(ctx, client, host)
		if same {
			s.e.secureHost(host)
		}
		s.results <- finished{scheme: host, same: same}
	}()
}

// schemeAnswered records the answer for a host and adds the hints that
// waited for it.
func (s *scheduler) schemeAnswered(host string, same bool) {
	s.inflight--
	s.schemes[host] = same
	held := s.waiting[host]
	delete(s.waiting, host)
	for _, h := range held {
		s.add(h.seed, h.depth, true)
	}
}

// schemeKind is the observation, on the host, that its http URLs are the
// https site's.
const schemeKind = "scheme"

// secureHost records that http://host/ is the https site. URLs found on
// it from now on are kept as https; those found before get their https
// URL, found where they were; and the map leaves out the http ones that
// were not requested (BuildMap).
func (e *Engine) secureHost(host string) {
	e.secured.Store(host, true)
	if e.Store == nil {
		return
	}
	now := time.Now().UTC()
	name := strings.Trim(host, "[]")
	typ := types.TypeHostname
	if ip := net.ParseIP(name); ip != nil {
		typ, name = types.TypeIPAddress, ip.String()
	}
	if ent, err := e.Store.UpsertEntity(typ, name, now); err == nil {
		payload, _ := json.Marshal(map[string]string{"http": "http://" + host + "/", "https": "https://" + host + "/"})
		_, _ = e.Store.AddObservation(ent.ID, types.Observation{Collector: "azhaq-http", Source: "run", Kind: schemeKind, Payload: payload, ObservedAt: now})
	}
	obs, err := e.Store.Observations()
	if err != nil {
		return
	}
	for _, o := range obs {
		if o.Kind != "url" {
			continue
		}
		if u, err := normalize.URL(payloadURL(o)); err == nil && e.onHTTPS(u) != u {
			e.linkFoundURL(types.Entity{ID: o.EntityID}, o.Observation, now)
		}
	}
}

// onHTTPS is raw on https when its host's http URLs are the https site's.
func (e *Engine) onHTTPS(raw string) string {
	if !strings.HasPrefix(raw, "http://") {
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Port() != "" {
		return raw
	}
	if _, ok := e.secured.Load(u.Host); !ok {
		return raw
	}
	u.Scheme = "https"
	if n, err := normalize.URL(u.String()); err == nil {
		return n
	}
	return raw
}

// securedHosts are the hosts a run found to serve its https site over
// http too: their http URLs that were not requested are not rows.
func securedHosts(obs []types.StoredObservation) map[string]bool {
	out := map[string]bool{}
	for _, o := range obs {
		if o.Kind != schemeKind {
			continue
		}
		var p struct {
			HTTP string `json:"http"`
		}
		if json.Unmarshal(o.Payload, &p) == nil {
			if u, err := url.Parse(p.HTTP); err == nil && u.Host != "" {
				out[u.Host] = true
			}
		}
	}
	return out
}

// foldedHTTP: an http URL on such a host, found and not requested.
func foldedHTTP(key, coverage string, secured map[string]bool) bool {
	if coverage != "hint" || len(secured) == 0 || !strings.HasPrefix(key, "http://") {
		return false
	}
	u, err := url.Parse(key)
	return err == nil && u.Port() == "" && secured[u.Host]
}

// sameSite asks http://host/ once. A redirect to https on the same host,
// the https front page again, or nothing listening on port 80 make its
// URLs the https site's. A request not sent (the budget, the scope)
// decides nothing, and the URLs stay as they are; so does an answer that
// is slow or not HTTP: something listens there, maybe a service of its
// own.
func sameSite(ctx context.Context, c *http.Client, host string) bool {
	plain, _, err := fetch.Do(ctx, c, "http://"+host+"/")
	if err != nil && dialTimeout(err) && ctx.Err() == nil {
		// One connect timed out may be the network; two are a port that
		// drops them. The first error is cached under the other key.
		plain, _, err = fetch.Do(ctx, c, "http://"+host)
	}
	if err != nil {
		return ctx.Err() == nil && nothingListens(err)
	}
	redirect := plain.Status >= 300 && plain.Status < 400
	if redirect && toHTTPS(plain, host) {
		return true
	}
	secure, _, err := fetch.Do(ctx, c, "https://"+host+"/")
	if err != nil || !fetch.SamePage(plain, secure) {
		return false
	}
	if redirect {
		// Both send the visitor to /login: two applications do too, each
		// to its own. The pages the chains end on decide.
		return fetch.SamePage(landing(plain), landing(secure))
	}
	return true
}

// toHTTPS: a hop of the chain sends to https on the same host, on the
// default port.
func toHTTPS(res fetch.Result, host string) bool {
	h, err := url.Parse("http://" + host + "/")
	if err != nil {
		return false
	}
	for _, hop := range res.Hops {
		from, err := url.Parse(hop.URL)
		if err != nil || hop.Location == "" {
			continue
		}
		if next, err := from.Parse(hop.Location); err == nil && next.Scheme == "https" &&
			strings.EqualFold(next.Hostname(), h.Hostname()) && (next.Port() == "" || next.Port() == "443") {
			return true
		}
	}
	return false
}

// landing is the answer at the end of res's redirect chain.
func landing(res fetch.Result) fetch.Result {
	status := res.Status
	if n := len(res.Hops); n > 0 {
		status = res.Hops[n-1].Status
	}
	return fetch.Result{RequestURL: res.URL, Status: status, URL: res.URL, Header: res.FinalHeader, Body: res.Body}
}

// nothingListens: no connection was made. The port refused it, no route
// leads there, the name has no address, or the connects timed out (a
// filter that drops them). A timeout once connected, a reset or an answer
// that is not HTTP come from something that listens.
func nothingListens(err error) bool {
	if errors.Is(err, neterr.ErrBudget) || errors.Is(err, neterr.ErrOutOfScope) || errors.Is(err, neterr.ErrEndsSession) {
		return false
	}
	if neterr.UnknownHost(err) || dialTimeout(err) || errors.Is(err, neterr.ErrOriginDown) {
		return true
	}
	for _, no := range []error{syscall.ECONNREFUSED, syscall.EHOSTUNREACH, syscall.ENETUNREACH, syscall.EHOSTDOWN} {
		if errors.Is(err, no) {
			return true
		}
	}
	return false
}

// dialTimeout: the connect timed out, not the wait for an answer.
func dialTimeout(err error) bool {
	var op *net.OpError
	return errors.As(err, &op) && op.Op == "dial" && op.Timeout()
}
