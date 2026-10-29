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
		name:   s.Name(),
		need:   need,
		deflt:  s.IsDefault(),
		perSec: perSec,
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
			if len(errs) > 0 {
				return names, errors.New(strings.Join(errs, "; "))
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

// sampled asks a keyless source again while its answers keep adding names:
// subdomain.center answers a different random 500 per call (2026-10-29: five
// calls gave 2135 tesla.com names, 49 live hosts one call missed). Rounds use
// half the source's bound, leaving the rest for the DNS check.
func sampled(s source) source {
	collect := s.collect
	s.collect = func(ctx context.Context, domain string, keys []string, sess *subscraping.Session) ([]string, error) {
		if len(keys) > 0 {
			return collect(ctx, domain, keys, sess) // a key pages the whole set
		}
		stop := time.Now().Add(sampleBudget)
		if dl, ok := ctx.Deadline(); ok {
			stop = time.Now().Add(time.Until(dl) / 2)
		}
		var names []string
		seen := map[string]bool{}
		for round := 0; round < sampleRounds; round++ {
			got, err := collect(ctx, domain, nil, sess)
			fresh := 0
			for _, n := range got {
				if !seen[n] {
					seen[n] = true
					names = append(names, n)
					fresh++
				}
			}
			switch {
			case err == nil && fresh*10 >= len(got) && fresh > 0:
			case err != nil && strings.Contains(err.Error(), "status code 429") && time.Until(stop) > samplePause:
				select {
				case <-ctx.Done():
					return names, ctx.Err()
				case <-time.After(samplePause):
				}
			case err != nil && (round == 0 || ctx.Err() != nil):
				return names, err
			default:
				return names, nil // saturated, or later rounds refused
			}
			if time.Now().After(stop) {
				break
			}
		}
		return names, nil
	}
	return s
}

var (
	sampleRounds = 12
	sampleBudget = 30 * time.Second
	samplePause  = 12 * time.Second
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
		name:  "crtsh",
		need:  noKey,
		deflt: true,
		collect: func(ctx context.Context, domain string, _ []string, sess *subscraping.Session) ([]string, error) {
			u := "https://crt.sh/json?q=" + url.QueryEscape(domain)
			var rows []struct {
				CommonName string `json:"common_name"`
				NameValue  string `json:"name_value"`
			}
			var err error
			for attempt, wait := 0, 2*time.Second; attempt < 4; attempt, wait = attempt+1, wait*2 {
				if err = getJSON(ctx, sess, "crtsh", u, nil, &rows); err == nil || !retry(err) {
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

// retry: crt.sh's gateway errors and dropped connections pass.
func retry(err error) bool {
	s := err.Error()
	for _, code := range []string{" 429", " 500", " 502", " 503", " 504"} {
		if strings.HasSuffix(s, code) {
			return true
		}
	}
	return strings.Contains(s, "EOF") || strings.Contains(s, "connection reset") || strings.Contains(s, "unexpected end of JSON")
}

// certspotterSource asks Cert Spotter. Unlike subfinder's version it also
// works without a key, at the free tier's rate.
func certspotterSource() source {
	return source{
		name:  "certspotter",
		need:  optionalKey,
		deflt: true,
		collect: func(ctx context.Context, domain string, keys []string, sess *subscraping.Session) ([]string, error) {
			u := "https://api.certspotter.com/v1/issuances?domain=" + url.QueryEscape(domain) + "&include_subdomains=true&expand=dns_names"
			headers := map[string]string{}
			if k := subscraping.PickRandom(keys, "certspotter"); k != "" {
				headers["Authorization"] = "Bearer " + k
			}
			var rows []struct {
				DNSNames []string `json:"dns_names"`
			}
			if err := getJSON(ctx, sess, "certspotter", u, headers, &rows); err != nil {
				return nil, err
			}
			var names []string
			for _, r := range rows {
				names = append(names, r.DNSNames...)
			}
			return names, nil
		},
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
	return json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(into)
}
