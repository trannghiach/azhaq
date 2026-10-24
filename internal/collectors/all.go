package collectors

import (
	"net/http"

	"azhaq/internal/catalog"
	"azhaq/internal/collectors/cdxcol"
	"azhaq/internal/collectors/cloudcol"
	"azhaq/internal/collectors/crawlcol"
	"azhaq/internal/collectors/ctcol"
	"azhaq/internal/collectors/dnscol"
	"azhaq/internal/collectors/httpcol"
	"azhaq/internal/collectors/jscol"
	"azhaq/internal/collectors/pathscol"
	"azhaq/internal/collectors/rdapcol"
	"azhaq/internal/collectors/tlscol"
)

func RegisterAll(cat *catalog.Catalog, client *http.Client) {
	RegisterAllWith(cat, client, nil)
}

func RegisterAllWith(cat *catalog.Catalog, client *http.Client, paths []string) {
	httpcol.Register(cat, client)
	crawlcol.Register(cat, client)
	jscol.Register(cat, client)
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
