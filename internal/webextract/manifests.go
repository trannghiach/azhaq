package webextract

import (
	"encoding/json"
	"net/url"
	"regexp"
	"strings"
)

// Manifest is what a build manifest lists: the app's scripts and source
// maps, the files they were built from, and its pages. Paths are as
// written, relative to where the manifest sits.
type Manifest struct {
	Kind    string // vite, cra, ngsw, nuxt
	Scripts []string
	Maps    []string
	Sources []string
	Pages   []string
	BuildID string // Nuxt's builds/latest.json: the build whose meta to read
}

// ReadManifest reads the manifests bundlers leave next to an app: Vite's
// (.vite/manifest.json), Create React App's asset-manifest.json,
// Angular's service worker ngsw.json, Nuxt's builds/latest.json and
// builds/meta/<id>.json. ok is false for anything else, a web app
// manifest (manifest.json with icons) or a page included.
func ReadManifest(body []byte) (Manifest, bool) {
	var doc map[string]json.RawMessage
	if json.Unmarshal(body, &doc) != nil || len(doc) == 0 {
		return Manifest{}, false
	}
	var m Manifest
	switch {
	case doc["files"] != nil:
		var files map[string]string
		if json.Unmarshal(doc["files"], &files) != nil {
			return Manifest{}, false
		}
		m.Kind = "cra"
		for _, f := range files {
			switch {
			case strings.HasSuffix(f, ".js"):
				m.Scripts = append(m.Scripts, f)
			case strings.HasSuffix(f, ".js.map"):
				m.Maps = append(m.Maps, f)
			}
		}
	case doc["assetGroups"] != nil:
		var groups []struct {
			URLs []string `json:"urls"`
		}
		if json.Unmarshal(doc["assetGroups"], &groups) != nil {
			return Manifest{}, false
		}
		m.Kind = "ngsw"
		for _, g := range groups {
			for _, u := range g.URLs {
				if strings.HasSuffix(u, ".js") {
					m.Scripts = append(m.Scripts, u)
				}
			}
		}
	case doc["prerendered"] != nil || doc["matcher"] != nil:
		m.Kind = "nuxt"
		var pre []string
		_ = json.Unmarshal(doc["prerendered"], &pre)
		m.Pages = append(m.Pages, pre...)
		var matcher map[string]map[string]json.RawMessage
		_ = json.Unmarshal(doc["matcher"], &matcher)
		for _, k := range []string{"static", "wildcard"} {
			for p := range matcher[k] {
				m.Pages = append(m.Pages, strings.TrimSuffix(strings.TrimSuffix(p, "/**"), "/*"))
			}
		}
	case doc["id"] != nil && doc["timestamp"] != nil && len(doc) <= 4:
		m.Kind = "nuxt"
		_ = json.Unmarshal(doc["id"], &m.BuildID)
		if !buildID.MatchString(m.BuildID) {
			return Manifest{}, false
		}
	default:
		// Vite: every entry a chunk, {"file": "assets/x-1a2b.js", "src": …}.
		for _, raw := range doc {
			var c struct {
				File string `json:"file"`
				Src  string `json:"src"`
			}
			if json.Unmarshal(raw, &c) != nil || c.File == "" {
				return Manifest{}, false
			}
			if strings.HasSuffix(c.File, ".js") || strings.HasSuffix(c.File, ".mjs") {
				m.Scripts = append(m.Scripts, c.File)
			}
			if c.Src != "" && len(m.Sources) < 200 {
				m.Sources = append(m.Sources, c.Src)
			}
		}
		m.Kind = "vite"
	}
	var pages []string
	for _, p := range m.Pages {
		if strings.HasPrefix(p, "/") && !strings.ContainsAny(p, " *") {
			pages = append(pages, p)
		}
	}
	m.Pages = pages
	return m, true
}

var (
	buildID     = regexp.MustCompile(`^[\w-]{1,64}$`)
	nextBuildID = regexp.MustCompile(`"buildId"\s*:\s*"([\w-]{1,64})"`)
	nuxtBuildID = regexp.MustCompile(`\bbuildId\s*:\s*"([\w-]{1,64})"|"buildId"\s*:\s*"([\w-]{1,64})"`)
	nuxtAssets  = regexp.MustCompile(`\bbuildAssetsDir\s*:\s*"(/[\w./-]{0,64}/)"`)
	craMain     = regexp.MustCompile(`^(.*/)static/js/(?:main|bundle)\.[0-9a-f]{8,}\.js$`)
)

// PageManifests lists the build manifests a page's framework leaves at
// known places, for the frameworks the page shows: Next.js's
// _buildManifest.js and _ssgManifest.js (the pages it routes), Nuxt's
// build meta (its prerendered pages and route rules), Create React App's
// asset-manifest.json (every chunk and map). srcs are the page's scripts.
func PageManifests(body []byte, page *url.URL, srcs []string) []string {
	if page == nil {
		return nil
	}
	var out []string
	add := func(ref string) {
		if u, err := page.Parse(ref); err == nil {
			for _, x := range out {
				if x == u.String() {
					return
				}
			}
			out = append(out, u.String())
		}
	}
	next := ""
	for _, src := range srcs {
		u, err := url.Parse(src)
		if err != nil {
			continue
		}
		if i := strings.Index(u.Path, "/_next/static/"); i >= 0 && next == "" {
			next = u.Scheme + "://" + u.Host + u.Path[:i+len("/_next/")]
		}
		if strings.HasSuffix(u.Path, "/_buildManifest.js") {
			// The pages a static export prerenders are in the other one.
			add(strings.TrimSuffix(src, "_buildManifest.js") + "_ssgManifest.js")
			next = "-"
		}
		if m := craMain.FindStringSubmatch(u.Path); m != nil {
			add(u.Scheme + "://" + u.Host + m[1] + "asset-manifest.json")
		}
	}
	if next != "" && next != "-" {
		if m := nextBuildID.FindSubmatch(body); m != nil {
			add(next + "static/" + string(m[1]) + "/_buildManifest.js")
			add(next + "static/" + string(m[1]) + "/_ssgManifest.js")
		}
	}
	if dir := nuxtDir(body); dir != "" {
		if m := nuxtBuildID.FindSubmatch(body); m != nil {
			add(dir + "builds/meta/" + string(m[1]) + string(m[2]) + ".json")
		} else {
			add(dir + "builds/latest.json")
		}
	}
	return out
}

// nuxtDir is where a Nuxt 3 page keeps its build, or "".
func nuxtDir(body []byte) string {
	if m := nuxtAssets.FindSubmatch(body); m != nil {
		return string(m[1])
	}
	if strings.Contains(string(body), `src="/_nuxt/`) || strings.Contains(string(body), `href="/_nuxt/`) {
		if strings.Contains(string(body), "__NUXT__") || strings.Contains(string(body), "__NUXT_DATA__") {
			return "/_nuxt/"
		}
	}
	return ""
}

// NuxtMeta is the build meta Nuxt's builds/latest.json at latest points to.
func NuxtMeta(latest, id string) string {
	return strings.TrimSuffix(latest, "latest.json") + "meta/" + id + ".json"
}

// ScriptManifests lists the build manifests a script shows: Vite's next
// to its assets (the module preload helper is Vite's), Angular's
// ngsw.json where it registers ngsw-worker.js. page resolves what the
// app names relative to itself.
func ScriptManifests(script string, scriptURL, page *url.URL) []string {
	var out []string
	if scriptURL != nil && (strings.Contains(script, "__vite__mapDeps") || strings.Contains(script, `supports("modulepreload")`) || strings.Contains(script, "supports(`modulepreload`)")) {
		dir := scriptURL.Path[:strings.LastIndex(scriptURL.Path, "/")+1]
		dir = strings.TrimSuffix(dir, "assets/")
		root := scriptURL.Scheme + "://" + scriptURL.Host + dir
		out = append(out, root+".vite/manifest.json", root+"manifest.json")
	}
	if page != nil && strings.Contains(script, "ngsw-worker.js") {
		if u, err := page.Parse("ngsw.json"); err == nil {
			out = append(out, u.String())
		}
	}
	return out
}

// nextInternal are the pages Next.js lists for itself.
var nextInternal = map[string]bool{"/_app": true, "/_error": true, "/_document": true, "/_middleware": true}

// NextInternal says whether p is one of Next.js's own pages (/_app,
// /_error), which a build manifest lists and nobody visits.
func NextInternal(p string) bool { return nextInternal[p] }
