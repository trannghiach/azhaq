// Package collectors registers Azhaq's built-in collectors in a catalog.
package collectors

import (
	"context"
	"net/http"

	"github.com/trannghiach/azhaq/catalog"
	"github.com/trannghiach/azhaq/internal/browser"
	"github.com/trannghiach/azhaq/internal/collectors/apicol"
	"github.com/trannghiach/azhaq/internal/collectors/asncol"
	"github.com/trannghiach/azhaq/internal/collectors/brutecol"
	"github.com/trannghiach/azhaq/internal/collectors/cloudcol"
	"github.com/trannghiach/azhaq/internal/collectors/crawlcol"
	"github.com/trannghiach/azhaq/internal/collectors/dirscol"
	"github.com/trannghiach/azhaq/internal/collectors/dnscol"
	"github.com/trannghiach/azhaq/internal/collectors/gqlcol"
	"github.com/trannghiach/azhaq/internal/collectors/httpcol"
	"github.com/trannghiach/azhaq/internal/collectors/jscol"
	"github.com/trannghiach/azhaq/internal/collectors/paramcol"
	"github.com/trannghiach/azhaq/internal/collectors/pathscol"
	"github.com/trannghiach/azhaq/internal/collectors/portcol"
	"github.com/trannghiach/azhaq/internal/collectors/rdapcol"
	"github.com/trannghiach/azhaq/internal/collectors/rendercol"
	"github.com/trannghiach/azhaq/internal/collectors/searchcol"
	"github.com/trannghiach/azhaq/internal/collectors/shotcol"
	"github.com/trannghiach/azhaq/internal/collectors/subcol"
	"github.com/trannghiach/azhaq/internal/collectors/tlscol"
	"github.com/trannghiach/azhaq/internal/collectors/urlcol"
	"github.com/trannghiach/azhaq/internal/dnsr"
	"github.com/trannghiach/azhaq/internal/fetch"
)

// Options configure the built-in collectors for one run.
type Options struct {
	Client      *http.Client // target requests; nil for the shared default
	Paths       []string     // extra wordlist entries for azhaq-paths
	DNS         *dnsr.Pool   // resolver pool; nil for the default resolvers
	Subdomains  subcol.Options
	BruteWords  []string // wordlist for azhaq-dns-brute (runs only with -dns-brute)
	URLs        urlcol.Options
	WebPorts    []int            // ports azhaq-http tries on each hostname; nil for 443 then 80
	NoTech      bool             // skip technology fingerprints
	Probe       bool             // azhaq-http answers like httpx: no catch-all check
	NoFavicon   bool             // azhaq-http does not hash favicons
	Ports       []int            // azhaq-ports: ports to scan (runs only with -ports)
	UDPPorts    []int            // azhaq-ports: UDP ports to ask (with -ports-udp)
	PortRate    float64          // azhaq-ports: connection attempts per second
	PortConfig  portcol.Config   // azhaq-ports: timeouts, retries, order and the rest
	Dirs        dirscol.Options  // azhaq-dirs: wordlist sweep (runs only with -dirs)
	Params      paramcol.Options // azhaq-params: parameter names (runs only with -params)
	MaxIPs      int              // azhaq-prefix: addresses expanded from prefixes for the run
	Shots       string           // azhaq-shots: screenshot directory (runs only when set)
	ShotHTML    bool             // azhaq-shots: keep each rendered page beside its picture
	WebScheme   string           // "http" or "https": the only scheme tried on a name or an address
	Browser     *browser.Browser // the run's Chrome, started on first use
	Render      bool             // azhaq-render: load pages in Chrome (-browser)
	NoMapGuess  bool             // azhaq-js does not ask for main.js.map next to a bundle that names no map
	FillForms   bool             // azhaq-crawl asks the action of GET forms with neutral values
	PathClimb   bool             // azhaq-crawl lists the parent directories of its links
	SubmitForms bool             // azhaq-crawl submits POST forms (changes data)
	KnownFiles  string           // azhaq-paths: ask only robots.txt and sitemaps (all, robotstxt, sitemapxml)
}

func RegisterAll(cat *catalog.Catalog, client *http.Client) {
	Register(cat, Options{Client: client})
}

func Register(cat *catalog.Catalog, o Options) {
	client := o.Client
	hc := httpcol.New(client)
	hc.Ports = o.WebPorts
	hc.Only = o.WebScheme
	hc.NoTech = o.NoTech
	hc.Probe = o.Probe
	hc.NoFavicon = o.NoFavicon
	cat.MustRegister(hc)
	cc := crawlcol.New(client)
	cc.FillForms, cc.SubmitForms, cc.Climb = o.FillForms, o.SubmitForms, o.PathClimb
	cat.MustRegister(cc)
	jc := jscol.New(client)
	jc.NoMapGuess = o.NoMapGuess
	cat.MustRegister(jc)
	apicol.Register(cat, client)
	cat.MustRegister(gqlcol.New(client))
	cat.MustRegister(gqlcol.NewSchema(client))
	if o.KnownFiles != "" {
		cat.MustRegister(&pathscol.Collector{Client: client, Wordlist: pathscol.KnownFiles(o.KnownFiles), Known: true})
	} else if len(o.Paths) > 0 {
		list := append(append([]string{}, pathscol.DefaultWordlist...), o.Paths...)
		cat.MustRegister(&pathscol.Collector{Client: client, Wordlist: list})
	} else {
		pathscol.Register(cat, client)
	}
	pool := o.DNS
	if pool == nil {
		pool = dnsr.New(dnsr.Options{})
	}
	dnsc := dnscol.New(pool)
	cat.MustRegister(dnsc)
	cat.MustRegister(&brutecol.Brute{Pool: pool, Wild: dnsc.Wild, Words: o.BruteWords})
	cat.MustRegister(&brutecol.Permute{Pool: pool, Wild: dnsc.Wild})
	pc := portcol.New(pool, o.Ports, o.PortRate)
	pc.UDPPorts = o.UDPPorts
	pc.Apply(o.PortConfig)
	cat.MustRegister(pc)
	cat.MustRegister(dirscol.New(client, o.Dirs))
	cat.MustRegister(paramcol.New(client, o.Params))
	cat.MustRegister(asncol.NewASN(nil))
	cat.MustRegister(searchcol.New(o.Subdomains.Keys))
	cat.MustRegister(&shotcol.Collector{Dir: o.Shots, Browser: o.Browser, Only: o.WebScheme, Ports: o.WebPorts, NoTech: o.NoTech, HTML: o.ShotHTML})
	render := &rendercol.Collector{}
	if o.Render {
		render.Browser = o.Browser
	}
	cat.MustRegister(render)
	// A scan of the ports of a prefix asks its addresses itself, and the
	// ones that answer go on; without one, the prefix is expanded.
	cat.MustRegister(&asncol.Prefix{MaxIPs: o.MaxIPs, Scanned: len(o.Ports)+len(o.UDPPorts) > 0})
	cat.MustRegister(&asncol.PTR{Pool: pool})
	tlscol.Register(cat)
	sub := o.Subdomains
	sub.Verify = func(ctx context.Context, apex string, names []string) (live []string, unchecked int) {
		var ask []string
		for _, n := range names {
			if fetch.Allow == nil || fetch.Allow(n) { // outside the scope: not even resolved
				ask = append(ask, n)
			}
		}
		// Mostly made-up names: one resolver's NXDOMAIN is enough, as in brute.
		for _, a := range pool.ResolveMany(dnsr.Bulk(ctx), ask, 128) {
			switch {
			case a.Status == dnsr.StatusFailed || ctx.Err() != nil:
				unchecked++
			case a.Live() && !dnsc.Wild.Match(ctx, a.Name, apex, a):
				live = append(live, a.Name)
			}
		}
		return live, unchecked
	}
	subcol.Register(cat, sub)
	cat.MustRegister(urlcol.New(o.URLs))
	rdapcol.Register(cat, client)
	cloudcol.Register(cat)
}
