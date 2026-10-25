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
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/crtsh"
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
		pd(func() subscraping.Source { return &crtsh.Source{} }, 0),
		pd(func() subscraping.Source { return &digitalyama.Source{} }, 0),
		pd(func() subscraping.Source { return &digitorus.Source{} }, 0),
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
		pd(func() subscraping.Source { return &hudsonrock.Source{} }, 5),
		pd(func() subscraping.Source { return &intelx.Source{} }, 0),
		pd(func() subscraping.Source { return &leakix.Source{} }, 0),
		pd(func() subscraping.Source { return &merklemap.Source{} }, 0),
		pd(func() subscraping.Source { return &netlas.Source{} }, 1),
		pd(func() subscraping.Source { return &onyphe.Source{} }, 0),
		pd(func() subscraping.Source { return &profundis.Source{} }, 0),
		pd(func() subscraping.Source { return &pugrecon.Source{} }, 10),
		pd(func() subscraping.Source { return &quake.Source{} }, 0),
		pd(func() subscraping.Source { return &rapiddns.Source{} }, 0),
		pd(func() subscraping.Source { return &reconcloud.Source{} }, 0),
		pd(func() subscraping.Source { return &reconeer.Source{} }, 0),
		pd(func() subscraping.Source { return &redhuntlabs.Source{} }, 0),
		pd(func() subscraping.Source { return &riddler.Source{} }, 0),
		pd(func() subscraping.Source { return &robtex.Source{} }, 0),
		pd(func() subscraping.Source { return &rsecloud.Source{} }, 0),
		pd(func() subscraping.Source { return &scanmalware.Source{} }, 0),
		pd(func() subscraping.Source { return &securitytrails.Source{} }, 2),
		pd(func() subscraping.Source { return &shodan.Source{} }, 1),
		pd(func() subscraping.Source { return &shodanct.Source{} }, 0),
		pd(func() subscraping.Source { return &sitedossier.Source{} }, 8*perMinute),
		pd(func() subscraping.Source { return &subdomaincenter.Source{} }, 0),
		pd(func() subscraping.Source { return &submd.Source{} }, 0),
		pd(func() subscraping.Source { return &thc.Source{} }, 0),
		pd(func() subscraping.Source { return &threatbook.Source{} }, 0),
		pd(func() subscraping.Source { return &threatcrowd.Source{} }, 0),
		pd(func() subscraping.Source { return &threatminer.Source{} }, 0),
		pd(func() subscraping.Source { return &urlscan.Source{} }, 1),
		pd(func() subscraping.Source { return &virustotal.Source{} }, 4*perMinute),
		pd(func() subscraping.Source { return &waybackarchive.Source{} }, 15*perMinute),
		pd(func() subscraping.Source { return &whoisxmlapi.Source{} }, 50),
		pd(func() subscraping.Source { return &windvane.Source{} }, 0),
		pd(func() subscraping.Source { return &zoomeyeapi.Source{} }, 0),
		certspotterSource(),
		chaosSource(),
	}
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
