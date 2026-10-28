package webextract

import (
	"net/url"
	"slices"
	"testing"
)

func TestReadManifest(t *testing.T) {
	vite := `{"index.html":{"file":"assets/index-4f1a.js","src":"index.html","isEntry":true,"imports":["_vendor-9c.js"]},
"_vendor-9c.js":{"file":"assets/vendor-9c.js"},"src/pages/Admin.vue":{"file":"assets/Admin-77.js","src":"src/pages/Admin.vue","isDynamicEntry":true},
"src/style.css":{"file":"assets/style-1.css","src":"src/style.css"}}`
	m, ok := ReadManifest([]byte(vite))
	if !ok || m.Kind != "vite" || len(m.Scripts) != 3 || !slices.Contains(m.Sources, "src/pages/Admin.vue") {
		t.Fatalf("vite %+v %v", m, ok)
	}
	cra := `{"files":{"main.js":"/static/js/main.8e2b.js","main.js.map":"/static/js/main.8e2b.js.map","static/js/787.1c.chunk.js":"/static/js/787.1c.chunk.js","index.html":"/index.html"},"entrypoints":["static/js/main.8e2b.js"]}`
	m, ok = ReadManifest([]byte(cra))
	if !ok || m.Kind != "cra" || len(m.Scripts) != 2 || len(m.Maps) != 1 {
		t.Fatalf("cra %+v %v", m, ok)
	}
	ngsw := `{"configVersion":1,"index":"/index.html","assetGroups":[{"name":"app","urls":["/main.5a.js","/polyfills.2b.js","/styles.css"]}],"dataGroups":[]}`
	m, ok = ReadManifest([]byte(ngsw))
	if !ok || m.Kind != "ngsw" || !slices.Equal(m.Scripts, []string{"/main.5a.js", "/polyfills.2b.js"}) {
		t.Fatalf("ngsw %+v %v", m, ok)
	}
	latest := `{"id":"3f9a0c1e-2b","timestamp":1730000000000}`
	m, ok = ReadManifest([]byte(latest))
	if !ok || m.Kind != "nuxt" || m.BuildID != "3f9a0c1e-2b" {
		t.Fatalf("nuxt latest %+v %v", m, ok)
	}
	meta := `{"id":"3f9a0c1e-2b","timestamp":1,"matcher":{"static":{"/admin/reports":{}},"wildcard":{"/blog/**":{}},"dynamic":{}},"prerendered":["/","/pricing"]}`
	m, ok = ReadManifest([]byte(meta))
	if !ok || m.Kind != "nuxt" || !slices.Contains(m.Pages, "/admin/reports") || !slices.Contains(m.Pages, "/blog") || !slices.Contains(m.Pages, "/pricing") {
		t.Fatalf("nuxt meta %+v %v", m, ok)
	}
	for _, doc := range []string{
		`{"name":"Shop","short_name":"Shop","icons":[{"src":"/icon.png","sizes":"192x192"}],"start_url":"/"}`, // a web app manifest
		`{"status":"ok"}`, `[1,2]`, `<!doctype html><title>shell</title>`,
	} {
		if m, ok := ReadManifest([]byte(doc)); ok {
			t.Errorf("%s read as %+v", doc, m)
		}
	}
}

func TestPageManifests(t *testing.T) {
	page, _ := url.Parse("https://shop.test/")
	next := []byte(`<script src="/_next/static/chunks/main-1111.js" defer></script>` +
		`<script id="__NEXT_DATA__" type="application/json">{"props":{},"page":"/","buildId":"abc123"}</script>`)
	got := PageManifests(next, page, []string{"https://shop.test/_next/static/chunks/main-1111.js"})
	if !slices.Equal(got, []string{"https://shop.test/_next/static/abc123/_buildManifest.js", "https://shop.test/_next/static/abc123/_ssgManifest.js"}) {
		t.Errorf("next %v", got)
	}
	// Named by the page: only its companion is added.
	got = PageManifests(nil, page, []string{"https://shop.test/_next/static/abc123/_buildManifest.js"})
	if !slices.Equal(got, []string{"https://shop.test/_next/static/abc123/_ssgManifest.js"}) {
		t.Errorf("next named %v", got)
	}
	got = PageManifests(nil, page, []string{"https://shop.test/static/js/main.8e2b9c1d.js"})
	if !slices.Equal(got, []string{"https://shop.test/asset-manifest.json"}) {
		t.Errorf("cra %v", got)
	}
	nuxt := []byte(`<script>window.__NUXT__={config:{app:{baseURL:"/",buildId:"3f9a0c1e-2b",buildAssetsDir:"/_nuxt/"}}}</script><script src="/_nuxt/entry.js"></script>`)
	got = PageManifests(nuxt, page, nil)
	if !slices.Equal(got, []string{"https://shop.test/_nuxt/builds/meta/3f9a0c1e-2b.json"}) {
		t.Errorf("nuxt %v", got)
	}
	if got := PageManifests([]byte(`<script src="/app.js"></script>`), page, []string{"https://shop.test/app.js"}); len(got) != 0 {
		t.Errorf("plain page %v", got)
	}
}

func TestScriptManifests(t *testing.T) {
	page, _ := url.Parse("https://shop.test/")
	js, _ := url.Parse("https://shop.test/assets/index-4f1a.js")
	got := ScriptManifests(`const __vite__mapDeps=(i,m=__vite__mapDeps,d=(m.f||(m.f=["assets/Admin-77.js"])))=>i.map(i=>d[i]);`, js, page)
	if !slices.Equal(got, []string{"https://shop.test/.vite/manifest.json", "https://shop.test/manifest.json"}) {
		t.Errorf("vite %v", got)
	}
	ng, _ := url.Parse("https://shop.test/main.5a.js")
	got = ScriptManifests(`Gw.register("ngsw-worker.js",{enabled:!0,registrationStrategy:"registerWhenStable:30000"})`, ng, page)
	if !slices.Equal(got, []string{"https://shop.test/ngsw.json"}) {
		t.Errorf("ngsw %v", got)
	}
	if got := ScriptManifests(`fetch("/api/x")`, ng, page); len(got) != 0 {
		t.Errorf("plain %v", got)
	}
	if !NextInternal("/_app") || NextInternal("/admin") {
		t.Error("NextInternal")
	}
}

// Next.js: the pages a build manifest lists, dynamic ones as templates,
// and its chunks from the asset root.
func TestNextBuildManifest(t *testing.T) {
	bm := `self.__BUILD_MANIFEST=function(s){return{__rewrites:{afterFiles:[],beforeFiles:[],fallback:[]},"/":[s,"static/chunks/pages/index-1a2b.js"],` +
		`"/account/settings":["static/chunks/pages/account/settings-77aa.js"],"/admin/users/[userId]":["static/chunks/pages/admin/users/[userId]-9f8e.js"],` +
		`"/docs/[...slug]":["static/chunks/pages/docs/[...slug]-31.js"],sortedPages:["/","/_app","/_error","/account/settings","/admin/users/[userId]","/docs/[...slug]"]}}("static/chunks/1-abc.js"),self.__BUILD_MANIFEST_CB&&self.__BUILD_MANIFEST_CB();` +
		`var tmpl="static/chunks/[name].[contenthash].js";`
	u, _ := url.Parse("https://shop.test/_next/static/abc123/_buildManifest.js")
	paths := JSURLs(bm, u)
	for _, want := range []string{"https://shop.test/account/settings", "https://shop.test/admin/users/{userId}", "https://shop.test/docs/{slug}", "https://shop.test/_app"} {
		if !slices.Contains(paths, want) {
			t.Errorf("missing %s in %v", want, paths)
		}
	}
	chunks := ScriptRefs(bm, u)
	for _, want := range []string{"https://shop.test/_next/static/chunks/pages/admin/users/[userId]-9f8e.js", "https://shop.test/_next/static/chunks/1-abc.js"} {
		if !slices.Contains(chunks, want) {
			t.Errorf("missing chunk %s in %v", want, chunks)
		}
	}
	for _, c := range chunks {
		if c == "https://shop.test/_next/static/chunks/[name].[contenthash].js" {
			t.Errorf("a name template is no chunk")
		}
	}
	if got := JSURLs(`var re="/[a-z]";`, u); len(got) != 0 {
		t.Errorf("a character class is no route: %v", got)
	}
}
