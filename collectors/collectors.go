// Package collectors registers Azhaq's built-in collectors in a catalog.
package collectors

import (
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
)

// Options configure the built-in collectors for one run.
type Options struct {
	Client     *http.Client // target requests; nil for the shared default
	Paths      []string     // extra wordlist entries for azhaq-paths
	DNS        *dnsr.Pool   // resolver pool; nil for the default resolvers
	Subdomains subcol.Options
	BruteWords []string // wordlist for azhaq-dns-brute (runs only with -dns-brute)
	URLs       urlcol.Options
	WebPorts   []int            // ports azhaq-http tries on each hostname; nil for 443 then 80
	NoTech     bool             // skip technology fingerprints
	Probe      bool             // azhaq-http answers like httpx: no catch-all check
	NoFavicon  bool             // azhaq-http does not hash favicons
	Ports      []int            // azhaq-ports: ports to scan (runs only with -ports)
	PortRate   float64          // azhaq-ports: connection attempts per second
	Dirs       dirscol.Options  // azhaq-dirs: wordlist sweep (runs only with -dirs)
	Params     paramcol.Options // azhaq-params: parameter names (runs only with -params)
	MaxIPs     int              // azhaq-prefix: addresses expanded from prefixes for the run
	Shots      string           // azhaq-shots: screenshot directory (runs only when set)
	Browser    *browser.Browser // the run's Chrome, started on first use
	Render     bool             // azhaq-render: load pages in Chrome (-browser)
}

func RegisterAll(cat *catalog.Catalog, client *http.Client) {
	Register(cat, Options{Client: client})
}

func Register(cat *catalog.Catalog, o Options) {
	client := o.Client
	hc := httpcol.New(client)
	hc.Ports = o.WebPorts
	hc.NoTech = o.NoTech
	hc.Probe = o.Probe
	hc.NoFavicon = o.NoFavicon
	cat.MustRegister(hc)
	crawlcol.Register(cat, client)
	jscol.Register(cat, client)
	apicol.Register(cat, client)
	cat.MustRegister(gqlcol.New(client))
	cat.MustRegister(gqlcol.NewSchema(client))
	if len(o.Paths) > 0 {
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
	cat.MustRegister(portcol.New(pool, o.Ports, o.PortRate))
	cat.MustRegister(dirscol.New(client, o.Dirs))
	cat.MustRegister(paramcol.New(client, o.Params))
	cat.MustRegister(asncol.NewASN(nil))
	cat.MustRegister(searchcol.New(o.Subdomains.Keys))
	cat.MustRegister(&shotcol.Collector{Dir: o.Shots, Browser: o.Browser})
	render := &rendercol.Collector{}
	if o.Render {
		render.Browser = o.Browser
	}
	cat.MustRegister(render)
	cat.MustRegister(&asncol.Prefix{MaxIPs: o.MaxIPs})
	cat.MustRegister(&asncol.PTR{Pool: pool})
	tlscol.Register(cat)
	subcol.Register(cat, o.Subdomains)
	cat.MustRegister(urlcol.New(o.URLs))
	rdapcol.Register(cat, client)
	cloudcol.Register(cat)
}
