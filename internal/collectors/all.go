package collectors

import (
	"net/http"

	"github.com/trannghiach/azhaq/internal/catalog"
	"github.com/trannghiach/azhaq/internal/collectors/apicol"
	"github.com/trannghiach/azhaq/internal/collectors/brutecol"
	"github.com/trannghiach/azhaq/internal/collectors/cdxcol"
	"github.com/trannghiach/azhaq/internal/collectors/cloudcol"
	"github.com/trannghiach/azhaq/internal/collectors/crawlcol"
	"github.com/trannghiach/azhaq/internal/collectors/dnscol"
	"github.com/trannghiach/azhaq/internal/collectors/httpcol"
	"github.com/trannghiach/azhaq/internal/collectors/jscol"
	"github.com/trannghiach/azhaq/internal/collectors/pathscol"
	"github.com/trannghiach/azhaq/internal/collectors/rdapcol"
	"github.com/trannghiach/azhaq/internal/collectors/subcol"
	"github.com/trannghiach/azhaq/internal/collectors/tlscol"
	"github.com/trannghiach/azhaq/internal/dnsr"
)

// Options configure the built-in collectors for one run.
type Options struct {
	Client     *http.Client // target requests; nil for the shared default
	Paths      []string     // extra wordlist entries for azhaq-paths
	DNS        *dnsr.Pool   // resolver pool; nil for the default resolvers
	Subdomains subcol.Options
	BruteWords []string // wordlist for azhaq-dns-brute (runs only with -dns-brute)
	WebPorts   []int    // ports azhaq-http tries on each hostname; nil for 443 then 80
}

func RegisterAll(cat *catalog.Catalog, client *http.Client) {
	Register(cat, Options{Client: client})
}

func Register(cat *catalog.Catalog, o Options) {
	client := o.Client
	hc := httpcol.New(client)
	hc.Ports = o.WebPorts
	cat.MustRegister(hc)
	crawlcol.Register(cat, client)
	jscol.Register(cat, client)
	apicol.Register(cat, client)
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
	tlscol.Register(cat)
	subcol.Register(cat, o.Subdomains)
	cdxcol.Register(cat, client)
	rdapcol.Register(cat, client)
	cloudcol.Register(cat)
}
