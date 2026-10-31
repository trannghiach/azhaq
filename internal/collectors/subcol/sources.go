package subcol

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/alienvault"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/anubis"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/bevigil"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/bufferover"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/builtwith"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/c99"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/censys"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/chinaz"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/commoncrawl"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/crtname"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/digitalyama"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/digitorus"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/dnsdb"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/dnsdumpster"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/dnsrepo"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/domainsproject"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/driftnet"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/fofa"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/fullhunt"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/github"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/gitlab"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/hackertarget"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/hudsonrock"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/intelx"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/leakix"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/merklemap"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/netlas"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/onyphe"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/profundis"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/pugrecon"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/quake"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/rapiddns"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/reconcloud"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/reconeer"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/redhuntlabs"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/riddler"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/robtex"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/rsecloud"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/scanmalware"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/securitytrails"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/shodan"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/shodanct"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/sitedossier"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/subdomaincenter"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/submd"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/thc"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/threatbook"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/threatcrowd"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/threatminer"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/urlscan"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/virustotal"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/waybackarchive"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/whoisxmlapi"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/windvane"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/zoomeyeapi"
)

// keyNeed says whether a source works without an API key.
type keyNeed int

const (
	noKey keyNeed = iota
	optionalKey
	requiredKey
)

// source is one passive subdomain source.
type source struct {
	name    string
	need    keyNeed
	deflt   bool    // part of the default set
	perSec  float64 // request rate; 0 is unlimited
	verify  bool    // a name only it gave is kept when it resolves
	sampler bool    // asked again by sampled(): it keeps its own time
	recurse bool    // handles subdomains of a subdomain (-recursive)
	collect func(ctx context.Context, domain string, keys []string, s *subscraping.Session) ([]string, error)
}

// pd adapts a subfinder source. A new instance is made per call because
// the instances keep keys and statistics.
func pd(newSource func() subscraping.Source, perSec float64) source {
	s := newSource()
	need := noKey
	switch s.KeyRequirement() {
	case subscraping.OptionalKey:
		need = optionalKey
	case subscraping.RequiredKey:
		need = requiredKey
	}
	return source{
		name:    s.Name(),
		need:    need,
		deflt:   s.IsDefault(),
		perSec:  perSec,
		recurse: s.HasRecursiveSupport(),
		collect: func(ctx context.Context, domain string, keys []string, sess *subscraping.Session) ([]string, error) {
			src := newSource()
			if len(keys) > 0 {
				src.AddApiKeys(keys)
			}
			ctx = context.WithValue(ctx, subscraping.CtxSourceArg, src.Name())
			var names, errs []string
			for r := range src.Run(ctx, domain, sess) {
				switch r.Type {
				case subscraping.Subdomain:
					names = append(names, r.Value)
				case subscraping.Error:
					if r.Error != nil && len(errs) < 3 {
						errs = append(errs, r.Error.Error())
					}
				}
			}
			why := answeredWithError(ctx)
			switch {
			case why != "" && len(names) == 0:
				// The server's words, not the decoder's complaint about them;
				// an error page has no names: not an honest zero.
				return nil, errors.New(why)
			case len(errs) > 0:
				return names, errors.New(strings.Join(errs, "; "))
			case why != "":
				addNote(ctx, why)
			}
			return names, nil
		},
	}
}

// Rates follow subfinder's defaults (requests per second).
const perMinute = 1.0 / 60

func allSources() []source {
	return []source{
		pd(func() subscraping.Source { return &alienvault.Source{} }, 0),
		pd(func() subscraping.Source { return &anubis.Source{} }, 0),
		pd(func() subscraping.Source { return &bevigil.Source{} }, 0),
		pd(func() subscraping.Source { return &bufferover.Source{} }, 0),
		pd(func() subscraping.Source { return &builtwith.Source{} }, 0),
		pd(func() subscraping.Source { return &c99.Source{} }, 0),
		pd(func() subscraping.Source { return &censys.Source{} }, 0),
		pd(func() subscraping.Source { return &chinaz.Source{} }, 0),
		pd(func() subscraping.Source { return &commoncrawl.Source{} }, 0),
		pd(func() subscraping.Source { return &crtname.Source{} }, 0),
		pd(func() subscraping.Source { return &digitalyama.Source{} }, 0),
		off(pd(func() subscraping.Source { return &digitorus.Source{} }, 0)),
		pd(func() subscraping.Source { return &dnsdb.Source{} }, 0),
		pd(func() subscraping.Source { return &dnsdumpster.Source{} }, 0),
		pd(func() subscraping.Source { return &dnsrepo.Source{} }, 0),
		pd(func() subscraping.Source { return &domainsproject.Source{} }, 0),
		pd(func() subscraping.Source { return &driftnet.Source{} }, 0),
		pd(func() subscraping.Source { return &fofa.Source{} }, 0),
		pd(func() subscraping.Source { return &fullhunt.Source{} }, 60*perMinute),
		pd(func() subscraping.Source { return &github.Source{} }, 83*perMinute),
		pd(func() subscraping.Source { return &gitlab.Source{} }, 0),
		pd(func() subscraping.Source { return &hackertarget.Source{} }, 2),
		on(pd(func() subscraping.Source { return &hudsonrock.Source{} }, 5)),
		pd(func() subscraping.Source { return &intelx.Source{} }, 0),
		pd(func() subscraping.Source { return &leakix.Source{} }, 0),
		pd(func() subscraping.Source { return &merklemap.Source{} }, 0),
		pd(func() subscraping.Source { return &netlas.Source{} }, 1),
		pd(func() subscraping.Source { return &onyphe.Source{} }, 0),
		pd(func() subscraping.Source { return &profundis.Source{} }, 0),
		pd(func() subscraping.Source { return &pugrecon.Source{} }, 10),
		pd(func() subscraping.Source { return &quake.Source{} }, 0),
		on(pd(func() subscraping.Source { return &rapiddns.Source{} }, 0)),
		off(pd(func() subscraping.Source { return &reconcloud.Source{} }, 0)),
		keyed(pd(func() subscraping.Source { return &reconeer.Source{} }, 0)),
		pd(func() subscraping.Source { return &redhuntlabs.Source{} }, 0),
		off(pd(func() subscraping.Source { return &riddler.Source{} }, 0)),
		pd(func() subscraping.Source { return &robtex.Source{} }, 0),
		pd(func() subscraping.Source { return &rsecloud.Source{} }, 0),
		pd(func() subscraping.Source { return &scanmalware.Source{} }, 0),
		pd(func() subscraping.Source { return &securitytrails.Source{} }, 2),
		pd(func() subscraping.Source { return &shodan.Source{} }, 1),
		pd(func() subscraping.Source { return &shodanct.Source{} }, 0),
		pd(func() subscraping.Source { return &sitedossier.Source{} }, 8*perMinute),
		sampled(verified(pd(func() subscraping.Source { return &subdomaincenter.Source{} }, 0))),
		off(pd(func() subscraping.Source { return &submd.Source{} }, 0)),
		on(pd(func() subscraping.Source { return &thc.Source{} }, 0)),
		pd(func() subscraping.Source { return &threatbook.Source{} }, 0),
		pd(func() subscraping.Source { return &threatcrowd.Source{} }, 0),
		off(pd(func() subscraping.Source { return &threatminer.Source{} }, 0)),
		pd(func() subscraping.Source { return &urlscan.Source{} }, 1),
		pd(func() subscraping.Source { return &virustotal.Source{} }, 4*perMinute),
		pd(func() subscraping.Source { return &waybackarchive.Source{} }, 15*perMinute),
		pd(func() subscraping.Source { return &whoisxmlapi.Source{} }, 50),
		pd(func() subscraping.Source { return &windvane.Source{} }, 0),
		pd(func() subscraping.Source { return &zoomeyeapi.Source{} }, 0),
		certspotterSource(),
		chaosSource(),
		crtshSource(),
		historySource(),
	}
}

// off takes a source out of the default set: it was dead or refused
// every request when last checked (2026-10-26), and a run that always
// reports the same failures teaches its reader to ignore failures.
// -sources NAME or -all-sources still runs it.
func off(s source) source {
	s.deflt = false
	return s
}

// on puts a keyless source that answers into the default set, although
// subfinder leaves it out of its own (checked 2026-10-27: rapiddns, thc
// and hudsonrock answered for tesla.com with names the others lacked).
func on(s source) source {
	s.deflt = true
	return s
}

// verified marks a source that pads its answer with made-up names:
// subdomain.center answers about 500 names per call, nearly all random
// and different each time, with the odd real one among them (2026-10-27).
// A name only such a source gave is kept when it resolves (not to a
// wildcard).
func verified(s source) source {
	s.verify = true
	return s
}

// sampled asks a keyless source again while its answers keep adding names
// that resolve: subdomain.center answers a different random 500 per call
// (2026-10-29: five calls gave 2135 tesla.com names, 49 live hosts one call
// missed). Each round's new names are resolved before the next round is
// asked (the checker in ctx); it stops when a round adds no new live name.
// Without resolvers it stops when under a tenth of a round is new. The
// source's bound (-source-timeout) is for asking: a request may take that
// long and the asking half of it in all; resolving is paced by -dns-rate.
func sampled(s source) source {
	collect := s.collect
	s.sampler = true
	s.collect = func(ctx context.Context, domain string, keys []string, sess *subscraping.Session) ([]string, error) {
		if len(keys) > 0 {
			return collect(ctx, domain, keys, sess) // a key pages the whole set
		}
		timeout := DefaultSourceTimeout
		if sess != nil && sess.Timeout > 0 {
			timeout = time.Duration(sess.Timeout) * time.Second
		}
		chk, _ := ctx.Value(checkerKey{}).(*checker)
		start := time.Now()
		var asking time.Duration
		var names []string
		seen := map[string]bool{}
		for call := 0; call < sampleRounds; call++ {
			countCall(ctx)
			fctx, cancel := context.WithTimeout(ctx, timeout)
			t0 := time.Now()
			got, err := collect(fctx, domain, nil, sess)
			cancel()
			asking += time.Since(t0)
			recordRound(ctx, got)
			var fresh []string
			for _, n := range got {
				if !seen[n] {
					seen[n] = true
					names = append(names, n)
					fresh = append(fresh, n)
				}
			}
			keepPartial(ctx, names)
			st := roundStat{Got: len(got), New: len(fresh)}
			switch {
			case err != nil && (len(names) == 0 || ctx.Err() != nil):
				return names, err
			case err != nil:
				return names, nil // later rounds were refused: the row says so
			case len(fresh) == 0:
				return names, nil // saturated
			case chk == nil:
				// Nothing to check them against: a second sample would only
				// add more guesses.
				return names, nil
			}
			t1 := time.Now()
			asked := chk.asked
			st.Live = chk.check(cleaned(fresh, domain))
			st.Asked = chk.asked - asked
			st.Seconds = round(time.Since(t1).Seconds())
			recordStat(ctx, st)
			switch {
			case st.Live == 0:
				return names, nil // this round found nothing new that resolves
			case !chk.room():
				return names, nil // the guesses have cost what the real names did
			case !chk.paced && time.Since(start) >= sampleBudget, asking >= timeout/2, ctx.Err() != nil:
				return names, nil
			}
		}
		return names, nil
	}
	return s
}

// roundStat is one round of a sampled source, for its row: the names it
// gave, how many were new, how many of those were looked up and how many
// resolved and no other source had.
type roundStat struct {
	Got     int     `json:"names"`
	New     int     `json:"new"`
	Asked   int     `json:"looked_up"`
	Live    int     `json:"new_live"`
	Seconds float64 `json:"check_seconds"`
}

func recordStat(ctx context.Context, st roundStat) {
	if l, ok := ctx.Value(roundsKey{}).(*roundLog); ok {
		l.mu.Lock()
		l.stats = append(l.stats, st)
		l.mu.Unlock()
	}
}

type partialKey struct{}

// partialNames keeps what a sampled source has gathered, for Run to use
// when it stops waiting before the source returns.
type partialNames struct {
	mu    sync.Mutex
	names []string
}

func (p *partialNames) snapshot() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.names...)
}

func keepPartial(ctx context.Context, names []string) {
	if p, ok := ctx.Value(partialKey{}).(*partialNames); ok {
		p.mu.Lock()
		p.names = append(p.names[:0], names...)
		p.mu.Unlock()
	}
}

type callsKey struct{}

// countCall adds one to the calls Run counts for the source (its row's
// "calls", shown by subs -v).
func countCall(ctx context.Context) {
	if n, ok := ctx.Value(callsKey{}).(*atomic.Int32); ok {
		n.Add(1)
	}
}

var (
	sampleRounds = 12
	// sampleBudget bounds the sampling when DNS is not paced: a round is a
	// request and its lookups, a few seconds.
	sampleBudget = 20 * time.Second
)

// keyed marks a source that has started to require a key.
func keyed(s source) source {
	s.need = requiredKey
	return s
}

// crtshSource asks crt.sh's JSON endpoint. subfinder's version tries the
// public Postgres server first (usually full) and then a URL crt.sh no
// longer serves; /json answers, though with the odd 502, so it is asked
// again a few times.
func crtshSource() source {
	return source{
		name:    "crtsh",
		need:    noKey,
		deflt:   true,
		recurse: true,
		collect: func(ctx context.Context, domain string, _ []string, sess *subscraping.Session) ([]string, error) {
			u := "https://crt.sh/json?q=" + url.QueryEscape(domain)
			var rows []struct {
				CommonName string `json:"common_name"`
				NameValue  string `json:"name_value"`
			}
			var err error
			start := time.Now()
			for attempt, wait := 0, time.Second; attempt < 4; attempt, wait = attempt+1, wait*2 {
				if err = getJSON(ctx, sess, "crtsh", u, nil, &rows); err == nil || !retry(err) {
					break
				}
				// crt.sh is often down for a while: a few quick retries, not a
				// minute of them, since every other source waits for this one.
				if time.Since(start)+wait > crtshRetryBudget {
					break
				}
				select {
				case <-ctx.Done():
					return nil, err
				case <-time.After(wait):
				}
			}
			if err != nil {
				return nil, err
			}
			var names []string
			for _, r := range rows {
				names = append(names, r.CommonName)
				names = append(names, strings.Split(r.NameValue, "\n")...)
			}
			return names, nil
		},
	}
}

// crtshRetryBudget is how long crt.sh may take, retries included, before
// its failure is taken as the answer.
const crtshRetryBudget = 12 * time.Second

// retry: crt.sh's gateway errors and dropped connections pass (a 429 is
// waited out in the transport).
func retry(err error) bool {
	s := err.Error()
	for _, code := range []string{" 500", " 502", " 503", " 504"} {
		if strings.HasSuffix(s, code) {
			return true
		}
	}
	return strings.Contains(s, "EOF") || strings.Contains(s, "connection reset") || strings.Contains(s, "unexpected end of JSON")
}

// certspotterSource asks Cert Spotter. Unlike subfinder's version it also
// works without a key, at the free tier's rate, where it reads the first
// page only (100 issuances) and says so; with a key it pages with
// after=<last id> until a page is empty, as subfinder does.
func certspotterSource() source {
	return source{
		name:    "certspotter",
		need:    optionalKey,
		deflt:   true,
		recurse: true,
		collect: func(ctx context.Context, domain string, keys []string, sess *subscraping.Session) ([]string, error) {
			base := "https://api.certspotter.com/v1/issuances?domain=" + url.QueryEscape(domain) + "&include_subdomains=true&expand=dns_names"
			headers := map[string]string{}
			key := subscraping.PickRandom(keys, "certspotter")
			if key != "" {
				headers["Authorization"] = "Bearer " + key
			}
			var names []string
			after := ""
			for page := 0; page < certspotterMaxPages; page++ {
				u := base
				if after != "" {
					u += "&after=" + url.QueryEscape(after)
				}
				var rows []struct {
					ID       string   `json:"id"`
					DNSNames []string `json:"dns_names"`
				}
				if err := getJSON(ctx, sess, "certspotter", u, headers, &rows); err != nil {
					if len(names) > 0 {
						addNote(ctx, fmt.Sprintf("stopped after page %d: %v; the names of the pages before it are kept", page+1, err))
						return names, nil
					}
					return nil, err
				}
				for _, r := range rows {
					names = append(names, r.DNSNames...)
				}
				if len(rows) == 0 || rows[len(rows)-1].ID == "" {
					return names, nil
				}
				if key == "" {
					if len(rows) >= certspotterPage {
						addNote(ctx, "first page only (without a key it is not paged): more issuances exist; a Cert Spotter key in the provider file pages them all")
					}
					return names, nil
				}
				after = rows[len(rows)-1].ID
			}
			addNote(ctx, fmt.Sprintf("stopped at %d pages; more issuances exist", certspotterMaxPages))
			return names, nil
		},
	}
}

const (
	certspotterPage     = 100 // issuances per page
	certspotterMaxPages = 1000
)

type noteKey struct{}

// rowNote is what a source says about its own answer, for its row.
type rowNote struct {
	mu   sync.Mutex
	text string
}

func (n *rowNote) get() string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.text
}

// addNote tells the run something about the source's answer: it is partial,
// and why. It is shown with the source's row and in the summary.
func addNote(ctx context.Context, text string) {
	if n, ok := ctx.Value(noteKey{}).(*rowNote); ok {
		n.mu.Lock()
		if n.text != "" {
			n.text += "; "
		}
		n.text += text
		n.mu.Unlock()
	}
}

// chaosSource asks ProjectDiscovery's Chaos dataset. It is written here
// because subfinder's version pulls in a large client library.
func chaosSource() source {
	return source{
		name:  "chaos",
		need:  requiredKey,
		deflt: true,
		collect: func(ctx context.Context, domain string, keys []string, sess *subscraping.Session) ([]string, error) {
			var body struct {
				Subdomains []string `json:"subdomains"`
			}
			u := "https://dns.projectdiscovery.io/dns/" + url.PathEscape(domain) + "/subdomains"
			if err := getJSON(ctx, sess, "chaos", u, map[string]string{"Authorization": subscraping.PickRandom(keys, "chaos")}, &body); err != nil {
				return nil, err
			}
			names := make([]string, 0, len(body.Subdomains))
			for _, s := range body.Subdomains {
				names = append(names, strings.TrimSuffix(s, ".")+"."+domain)
			}
			return names, nil
		},
	}
}

func getJSON(ctx context.Context, sess *subscraping.Session, name, u string, headers map[string]string, into any) error {
	ctx = context.WithValue(ctx, subscraping.CtxSourceArg, name)
	resp, err := sess.Get(ctx, u, "", headers)
	if err != nil {
		sess.DiscardHTTPResponse(resp)
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s %d", resp.Request.URL.Host, resp.StatusCode)
	}
	err = json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(into)
	if err != nil {
		if why := answeredWithError(ctx); why != "" {
			return errors.New(why) // the server's words, not a decoder's
		}
	}
	return err
}
