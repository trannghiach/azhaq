package collectors

import (
	"net/http"

	"github.com/trannghiach/azhaq/internal/catalog"
	"github.com/trannghiach/azhaq/internal/collectors/apicol"
	"github.com/trannghiach/azhaq/internal/collectors/cdxcol"
	"github.com/trannghiach/azhaq/internal/collectors/cloudcol"
	"github.com/trannghiach/azhaq/internal/collectors/crawlcol"
	"github.com/trannghiach/azhaq/internal/collectors/ctcol"
	"github.com/trannghiach/azhaq/internal/collectors/dnscol"
	"github.com/trannghiach/azhaq/internal/collectors/httpcol"
	"github.com/trannghiach/azhaq/internal/collectors/jscol"
	"github.com/trannghiach/azhaq/internal/collectors/pathscol"
	"github.com/trannghiach/azhaq/internal/collectors/rdapcol"
	"github.com/trannghiach/azhaq/internal/collectors/tlscol"
)

func RegisterAll(cat *catalog.Catalog, client *http.Client) {
	RegisterAllWith(cat, client, nil)
}

func RegisterAllWith(cat *catalog.Catalog, client *http.Client, paths []string) {
	httpcol.Register(cat, client)
	crawlcol.Register(cat, client)
	jscol.Register(cat, client)
	apicol.Register(cat, client)
	if len(paths) > 0 {
		list := append(append([]string{}, pathscol.DefaultWordlist...), paths...)
		cat.MustRegister(&pathscol.Collector{Client: client, Wordlist: list})
	} else {
		pathscol.Register(cat, client)
	}
	dnscol.Register(cat)
	tlscol.Register(cat)
	ctcol.Register(cat, client)
	cdxcol.Register(cat, client)
	rdapcol.Register(cat, client)
	cloudcol.Register(cat)
}
