package main

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/trannghiach/azhaq/engine"
	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/internal/normalize"
	"github.com/trannghiach/azhaq/internal/webextract"
	"github.com/trannghiach/azhaq/types"
)

// cmdCrawl is katana: the URLs of an application, visited or found in its
// pages, scripts and API descriptions.
func cmdCrawl(args []string) error {
	fs := newFlags("crawl")
	var c common
	c.register(fs)
	var urls stringsFlag
	fs.Var(&urls, "u", "start URL (repeatable, or comma-separated)")
	list := onceString(fs, "l", "file of start URLs (- for stdin)")
	given := inherit(fs, append([]string{"depth", "max-items", "parallel", "host-parallel", "delay", "paths", "browser", "browser-writes",
		"login", "login-user", "login-pass", "per-template", "proxy", "retry", "backoff", "cookie-jar", "host-rate", "max-host-requests", "request-timeout", "max-response-size", "submit-forms", "path-climb", "no-map-guess", "interact", "interact-clicks", "resolvers", "no-follow",
		"kf=known-files", "fs=crawl-scope", "ns=crawl-any-host", "c=host-parallel", "p=parallel", "rl=rate", "ct=timeout", "dr=no-follow", "r=resolvers"},
		targetFlags...)...)
	var inScope, outScope stringsFlag
	fs.Var(&inScope, "cs", "follow only URLs that match this regex (repeatable)")
	fs.Var(&outScope, "cos", "never follow URLs that match this regex (repeatable)")
	rlm := fs.Int("rlm", 0, "requests per minute over all hosts (katana's -rlm)")
	hrl := fs.Int("hrl", 0, "requests per second to each host (katana's -hrl)")
	hrlm := fs.Int("hrlm", 0, "requests per minute to each host (katana's -hrlm)")
	mdp := fs.Int("mdp", 0, "requests one host may be sent, then its work is left for resume (katana's -mdp)")
	mrs := fs.Int("mrs", 0, "bytes read of a page (katana's -mrs; default 2 MiB, scripts and JSON 16 MiB)")
	rd := fs.Int("rd", 0, "seconds to wait before each request (katana's -rd)")
	iqp := fs.Bool("iqp", false, "ask one URL of each path whatever its query values (katana's -iqp; the others are listed)")
	pc := fs.Bool("pc", false, "same as -path-climb (katana's -pc)")
	fs.String("s", "", "accepted for katana's command lines; azhaq orders its work by worth within a host, not by -s depth-first or breadth-first")
	storeResp := fs.Bool("sr", false, "also write each answer kept in the workspace to the -srd directory, DIR/HOST/SHA1.txt, with an index.txt (katana's -sr)")
	storeRespDir := fs.String("srd", "katana_response", "directory for -sr")
	omitBody := fs.Bool("ob", false, "with -sr: write the status line and headers only")
	listFields := fs.Bool("lof", false, "list the fields -f, -sf and -ot take, and the fields of -jsonl lines, and exit")
	excludeFields := fs.String("eof", "", "leave these fields out of -json and -jsonl lines, comma-separated (request.tag, response.forms, tech, …)")
	noFill := fs.Bool("no-form-fill", false, "do not ask the action of GET forms with neutral values")
	d := fs.Int("d", -1, "katana's -d: link levels below the start URL to visit (3 by default); -depth N is -d N-1")
	assets := fs.Bool("assets", false, "also list images, fonts and media, and the source maps and build manifests azhaq reads (scripts and stylesheets are listed by default, as katana lists them)")
	noShell := fs.Bool("no-catchall", false, "leave out URLs that answer with the page every unknown path gets (client-side routes of a single-page app)")
	sweep := fs.Bool("sweep", false, "also ask each web service for the 32 built-in paths (robots.txt, sitemaps, API descriptions, .git/HEAD, admin, …) and for the source map next to each script, as run does; crawl asks only what a crawler does")
	showOut := fs.Bool("do", false, "also list the URLs found and left out of the crawl's scope (never requested)")
	showRejected := fs.Bool("rejected", false, "also list the strings read from scripts and pages and kept out of the URLs, each with its reason (text: string, a tab, the reason; -json: one object each)")
	jsonl := fs.Bool("jsonl", false, "katana's JSON lines: {timestamp, request{method, endpoint, tag, attribute, source}, response{status_code, technologies, forms, content_length}, error}")
	fs.BoolVar(jsonl, "j", false, "same as -jsonl")
	fieldList := fs.String("f", "", "print these fields of each URL instead of the URL, comma-separated: "+strings.Join(crawlFieldNames, ",")+" (katana's -f)")
	storeFields := fs.String("sf", "", "also write these fields, one file each, to the -sfd directory: katana_field/SCHEME_HOST_FIELD.txt")
	storeDir := fs.String("sfd", "katana_field", "directory for -sf")
	tmpl := fs.String("ot", "", "print each URL through this template, {{url}} or any field name in braces ({{rdn}} {{path}} …)")
	extMatch := fs.String("em", "", "list only URLs with these extensions, comma-separated (none: URLs without one)")
	extFilter := fs.String("ef", "", "leave out URLs with these extensions, comma-separated, besides the default list (images, fonts, archives, media, .pdf, .txt, .map, …)")
	noDefExt := fs.Bool("ndef", false, "do not leave out the default extensions")
	matchRe := fs.String("mr", "", "list only URLs that match this regex (regex of the printed URL; the crawl itself is not limited)")
	filterRe := fs.String("fr", "", "leave out URLs that match this regex (printed URLs only)")
	for _, name := range []string{"jc", "jsl", "fx", "td", "nc", "duc", "kb"} {
		fs.Bool(name, false, "accepted for katana's command lines; azhaq always reads scripts, forms and technologies")
	}
	for _, a := range args {
		if a == "--" {
			break
		}
		if name, _, _ := strings.Cut(strings.TrimLeft(a, "-"), "="); name == "fill-forms" && strings.HasPrefix(a, "-") {
			return usagef("crawl has no -fill-forms: it asks GET forms by default; -no-form-fill turns that off")
		}
	}
	if err := parse(fs, args); err != nil {
		return err
	}
	if *listFields {
		fmt.Println(strings.Join(crawlFieldNames, "\n"))
		fmt.Println("-jsonl: timestamp request.method request.endpoint request.tag request.attribute request.source response.status_code response.technologies response.forms response.content_length error")
		return nil
	}
	outOpts, err := crawlOutOpts(*jsonl, *fieldList, *storeFields, *storeDir, *tmpl, *extMatch, *extFilter, *noDefExt, *matchRe, *filterRe, *showRejected)
	if err != nil {
		return err
	}
	if *jsonl {
		c.json = true
	}
	if *d >= 0 {
		given = withDepth(fs, given, *d+1)
	}
	var more []string
	for _, u := range urls {
		for _, part := range strings.Split(u, ",") {
			if part = strings.TrimSpace(part); part != "" {
				more = append(more, part)
			}
		}
	}
	targets, err := inputs(more, *list)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return usagef("give -u URL, -l FILE or URLs on stdin")
	}
	for i, t := range targets {
		targets[i] = crawlTarget(t)
	}
	path, rm, err := tempList(targets)
	if err != nil {
		return err
	}
	defer rm()
	rep := newReport("crawl")
	rep.what = "URLs"
	// The application only: no subdomain, archive or certificate fan-out.
	run := []string{"-list", path, "-skip", "azhaq-subdomains,azhaq-urls,azhaq-rdap,azhaq-tls", "-no-favicon", "-backoff", "-retry=1", "-cookie-jar"}
	if !*noFill {
		run = append(run, "-fill-forms")
	}
	if *pc {
		run = append(run, "-path-climb")
	}
	if *rlm > 0 {
		run = append(run, fmt.Sprintf("-rate=%g", float64(*rlm)/60))
	}
	if *hrl > 0 {
		run = append(run, fmt.Sprintf("-host-rate=%d", *hrl))
	} else if *hrlm > 0 {
		run = append(run, fmt.Sprintf("-host-rate=%g", float64(*hrlm)/60))
	}
	if *mdp > 0 {
		run = append(run, fmt.Sprintf("-max-host-requests=%d", *mdp))
	}
	if *mrs > 0 {
		run = append(run, fmt.Sprintf("-max-response-size=%d", *mrs))
	}
	if *rd > 0 {
		run = append(run, fmt.Sprintf("-delay=%ds", *rd))
	}
	explicit := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { explicit[f.Name] = true })
	if !explicit["fs"] {
		run = append(run, "-crawl-scope=rdn-origin")
	}
	if !*sweep {
		run = append(run, "-no-map-guess")
	}
	if !*sweep && !explicit["kf"] && !explicit["paths"] {
		run = append(run, "-no-paths")
	}
	// A crawler asks every page it finds: no template fold and no item cap
	// unless -per-template or -max-items says so.
	if *iqp {
		run = append(run, "-per-template=1")
	} else if !explicit["per-template"] {
		run = append(run, "-per-template=1000000")
	}
	if !explicit["max-items"] {
		run = append(run, "-max-items=1000000")
	}
	run = append(run, crawlRegexArgs(inScope, "-crawl-in")...)
	run = append(run, crawlRegexArgs(outScope, "-crawl-out")...)
	var answers *answerStore
	if *storeResp {
		if answers, err = newAnswerStore(*storeRespDir, *omitBody); err != nil {
			return err
		}
	}
	if answers != nil {
		answerTap = answers.tap
		defer func() { answerTap = nil }()
	}
	st, done, err := runPreset(&c, append(run, given()...), rep, nil)
	if err != nil {
		return err
	}
	defer done()
	ents, _ := st.Entities()
	obs, _ := st.Observations()
	edges, _ := st.Edges()
	seeds, _ := st.LoadSeeds()
	leftover, _ := st.LoadLeftover()
	rows := engine.BuildMap(ents, engine.ScopeSeeds(seeds, ents, edges), obs, leftover, false)
	outOpts.exclude = splitList(*excludeFields)
	outOpts.assets = *assets
	out, err := newCrawlOutput(&c, outOpts)
	if err != nil {
		return err
	}
	facts, rejected, offsite := crawlFacts(obs)
	counts := map[string]int{}
	var otherMethod, scriptsOnly int
	var kinds crawlKinds
	for _, r := range rows {
		if r.Entity.Type != types.TypeURL || (*noShell && r.Coverage == "catchall") || r.Scope != "target" {
			continue
		}
		kinds.add(r)
		if outOpts.hidden(r) {
			continue
		}
		if !c.json && !outOpts.jsonl && strings.Contains(r.Entity.Key, "{") {
			continue // a route with a parameter (/api/Cards/{id}) is no URL to request; -json lists it
		}
		if !c.json && !outOpts.jsonl && (r.Role == "client-route" || r.Role == "websocket") {
			continue // a view the app draws, a socket: no page a GET gets; -json lists them
		}
		if !out.keep(r.Entity.Key) {
			continue
		}
		counts[r.Coverage]++
		switch {
		case len(r.Methods) > 0 && !slices.Contains(r.Methods, "GET"):
			otherMethod++
		case r.Coverage == "hint" && len(r.Methods) == 0 && strings.HasSuffix(r.Proof, engine.ProofScriptsOnly):
			scriptsOnly++
		}
		out.write(r, facts[r.Entity.Key])
	}
	if *showOut {
		for _, o := range offsite {
			if out.keep(o.url) {
				out.writeOut(o)
			}
		}
	}
	if *showRejected {
		for _, x := range rejected {
			out.writeRejected(x)
		}
	}
	if answers != nil {
		if err := answers.close(); err != nil {
			return err
		}
		rep.Notes = append(rep.Notes, fmt.Sprintf("%d answers written to %s", answers.n, *storeRespDir))
	}
	if err := out.close(); err != nil {
		return err
	}
	rep.Results, rep.Counts = out.w.count(), counts
	kinds.put(counts, len(rejected))
	if otherMethod > 0 {
		rep.Notes = append(rep.Notes, fmt.Sprintf("%d listed URLs are routes scripts call with a method other than GET, so a GET may answer 404 or 405 (-json has methods; -ot '{{method}} {{url}}' prints them)", otherMethod))
	}
	if scriptsOnly > 0 {
		rep.Notes = append(rep.Notes, fmt.Sprintf("%d listed URLs are named only in scripts, with no call to say how they are used, and a GET answers 404 (-json has proof)", scriptsOnly))
	}
	if n := len(rejected); n > 0 {
		rep.Notes = append(rep.Notes, fmt.Sprintf("%d strings read from scripts and pages were kept out of the URLs, with the reason each (not requested; -rejected lists them)", n))
	}
	if n := len(offsite); n > 0 && !*showOut {
		rep.Notes = append(rep.Notes, fmt.Sprintf("%d links found outside the crawl's scope were not followed (-do lists them)", n))
	}
	if ca := engine.CatchAllShell(rows, obs); ca.Origin != "" && !hasFlag(args, "interact") {
		rep.hint(catchAllHint("azhaq crawl -u "+ca.Origin+"/ -browser -interact", ca))
	}
	return rep.finish(c.json, c.silent)
}

// crawlKinds sorts every URL row of the crawl's scope into what it is, so a
// reader compares like with like (katana's records are the requested ones):
// requested + not requested + templates is every row, and assets are a
// count of their own.
type crawlKinds struct{ requested, answered, notRequested, templates, assets int }

func (k *crawlKinds) add(r engine.MapEntry) {
	switch r.Role {
	case "asset", "sourcemap", "manifest":
		k.assets++
	}
	answered := r.Status > 0 || r.Coverage == "visited" || r.Coverage == "gone" || r.Coverage == "catchall"
	switch {
	case strings.Contains(r.Entity.Key, "{"):
		k.templates++ // a route with a placeholder is never requested as written
	case answered || r.Coverage == "error":
		k.requested++
		if answered {
			k.answered++
		}
	default:
		k.notRequested++
	}
}

// put adds the kinds to the summary's counts, and the strings kept out of
// the URLs.
func (k *crawlKinds) put(c map[string]int, rejected int) {
	for name, n := range map[string]int{"requested": k.requested, "answered": k.answered, "not requested": k.notRequested,
		"templates": k.templates, "assets": k.assets, "rejected strings": rejected} {
		if n > 0 {
			c[name] = n
		}
	}
}

// crawlFact is what the run's observations say about a URL beyond its map
// row: how a link was found and the page that held it, and the page's
// own technologies and size.
type crawlFact struct {
	tag, attr, source string
	tech              []string
	length            int
}

type outLink struct{ url, source, tag, attr string }

type rejectedStr struct{ str, reason, url, source, via string }

func crawlFacts(obs []types.StoredObservation) (map[string]crawlFact, []rejectedStr, []outLink) {
	facts := map[string]crawlFact{}
	var rej []rejectedStr
	var off []outLink
	rejSeen, offSeen := map[string]bool{}, map[string]bool{}
	for _, o := range obs {
		var p struct {
			URL       string   `json:"url"`
			Via       string   `json:"via"`
			Tag       string   `json:"tag"`
			Attribute string   `json:"attribute"`
			Tech      []string `json:"tech"`
			Length    int      `json:"length"`
			String    string   `json:"string"`
			Reason    string   `json:"reason"`
		}
		if json.Unmarshal(o.Payload, &p) != nil {
			continue
		}
		switch o.Kind {
		case "rejected":
			if k := p.String + "\x00" + p.Reason + "\x00" + p.URL; !rejSeen[k] {
				rejSeen[k] = true
				rej = append(rej, rejectedStr{p.String, p.Reason, p.URL, o.Source, p.Via})
			}
		case "offsite":
			if u, err := normalize.URL(p.URL); err == nil && !offSeen[u] {
				offSeen[u] = true
				off = append(off, outLink{u, o.Source, p.Tag, p.Attribute})
			}
		case "url", "application":
			u, err := normalize.URL(p.URL)
			if err != nil {
				continue
			}
			f := facts[u]
			if o.Kind == "application" {
				if len(f.tech) == 0 {
					f.tech = p.Tech
				}
				if f.length == 0 {
					f.length = p.Length
				}
			} else if f.source == "" {
				f.source, f.tag, f.attr = o.Source, p.Tag, p.Attribute
				if f.tag == "" {
					f.tag = strings.TrimPrefix(p.Via, "js-")
				}
			}
			facts[u] = f
		}
	}
	sort.Slice(rej, func(i, j int) bool { return rej[i].str < rej[j].str })
	sort.Slice(off, func(i, j int) bool { return off[i].url < off[j].url })
	return facts, rej, off
}

func crawlRegexArgs(vals []string, flagName string) []string {
	var out []string
	for _, v := range vals {
		out = append(out, flagName+"="+v)
	}
	return out
}

// withDepth replaces -depth in the flags passed to run.
func withDepth(fs *flag.FlagSet, given func() []string, depth int) func() []string {
	return func() []string {
		var out []string
		for _, a := range given() {
			if strings.HasPrefix(a, "-depth=") {
				continue
			}
			out = append(out, a)
		}
		return append(out, "-depth="+strconv.Itoa(depth))
	}
}

// crawlTarget is a start URL as given: a bare host or host:port is asked
// over http for :80 and :8080, over https otherwise, as katana does.
func crawlTarget(t string) string {
	if strings.Contains(t, "://") {
		return t
	}
	host := t
	if h, _, ok := strings.Cut(t, "/"); ok {
		host = h
	}
	scheme := "https"
	if strings.HasSuffix(host, ":80") || strings.HasSuffix(host, ":8080") {
		scheme = "http"
	}
	if !strings.Contains(t, "/") {
		t += "/"
	}
	return scheme + "://" + t
}

// crawlFieldNames are katana's output fields (pkg/output/fields.go, MIT),
// all read off the URL, and azhaq's own method: the methods the row is
// called with, one line each (GET for a page no script calls another way).
var crawlFieldNames = []string{"url", "path", "fqdn", "rdn", "rurl", "qurl", "qpath", "file", "ufile", "key", "value", "kv", "dir", "udir", "method"}

// defaultDenyExt are the extensions katana leaves out by default.
var defaultDenyExt = strings.Fields(".3g2 .3gp .7z .apk .arj .avi .axd .bmp .csv .deb .dll .doc .drv .eot .exe .flv .gif .gifv .gz .h264 .ico .iso .jar .jpeg .jpg .lock .m4a .m4v .map .mkv .mov .mp3 .mp4 .mpeg .mpg .msi .ogg .ogm .ogv .otf .pdf .pkg .png .ppt .psd .rar .rm .rpm .svg .swf .sys .tar.gz .tar .tif .tiff .ttf .txt .vob .wav .webm .webp .wmv .woff .woff2 .xcf .xls .xlsx .zip")

type crawlOpts struct {
	jsonl, rejected, showAssets, assets bool
	fields, store                       []string
	dir, tmpl                           string
	match, deny, defDeny                map[string]bool
	hasMatch, method                    bool
	mr, fr                              *regexp.Regexp
	exclude                             []string
}

// hidden: a row the crawl does not list unless -assets, -em or -ndef asks. Scripts and
// stylesheets are listed, found or fetched, as katana lists them; what is left out is what
// the default extension list leaves out (images, fonts, media) and the source maps and
// build manifests azhaq guesses at, which no page names.
func (o crawlOpts) hidden(r engine.MapEntry) bool {
	if o.showAssets || o.assets {
		return false
	}
	switch r.Role {
	case "sourcemap", "manifest":
		return true
	case "asset":
		return o.defDeny[urlExt(r.Entity.Key)]
	}
	return false
}

func urlExt(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(path.Ext(u.Path))
}

// assetExt: an extension -assets brings back to the list, an image, font or media file
// (a source map is not one: no page loads it).
func assetExt(ext string) bool {
	return ext != ".map" && webextract.ClassifyURL("http://h/x"+ext) == "asset"
}

func crawlOutOpts(jsonl bool, fields, store, dir, tmpl, em, ef string, ndef bool, mr, fr string, rejected bool) (crawlOpts, error) {
	o := crawlOpts{jsonl: jsonl, rejected: rejected, dir: dir, tmpl: tmpl, match: map[string]bool{}, deny: map[string]bool{}, defDeny: map[string]bool{}}
	for _, kind := range []struct {
		name string
		list string
		dst  *[]string
	}{{"-f", fields, &o.fields}, {"-sf", store, &o.store}} {
		for _, f := range splitList(kind.list) {
			if !slices.Contains(crawlFieldNames, f) {
				return o, usagef("%s: no field %q (fields: %s)", kind.name, f, strings.Join(crawlFieldNames, ", "))
			}
			*kind.dst = append(*kind.dst, f)
		}
	}
	if tmpl != "" {
		for _, m := range crawlTagRe.FindAllStringSubmatch(tmpl, -1) {
			if !slices.Contains(crawlFieldNames, m[1]) {
				return o, usagef("-ot: no field %q (fields: %s)", m[1], strings.Join(crawlFieldNames, ", "))
			}
			o.method = o.method || m[1] == "method"
		}
	}
	o.method = o.method || slices.Contains(o.fields, "method") || slices.Contains(o.store, "method")
	ext := func(e string) string {
		e = strings.ToLower(strings.TrimSpace(e))
		if e == "none" {
			return ""
		}
		return "." + strings.TrimPrefix(e, ".")
	}
	for _, e := range splitList(em) {
		o.match[ext(e)], o.hasMatch, o.showAssets = true, true, true
	}
	if !ndef {
		for _, e := range defaultDenyExt {
			o.defDeny[e] = true
		}
	} else {
		o.showAssets = true
	}
	for _, e := range splitList(ef) {
		o.deny[ext(e)] = true
	}
	var err error
	if mr != "" {
		if o.mr, err = regexp.Compile(mr); err != nil {
			return o, usagef("-mr: %v", err)
		}
	}
	if fr != "" {
		if o.fr, err = regexp.Compile(fr); err != nil {
			return o, usagef("-fr: %v", err)
		}
	}
	return o, nil
}

var crawlTagRe = regexp.MustCompile(`\{\{\s*([a-z]+)\s*\}\}`)

// crawlOutput prints a crawl's rows as the command's flags say.
type crawlOutput struct {
	o     crawlOpts
	w     *writer
	json  bool
	files map[string]*os.File
}

func newCrawlOutput(c *common, o crawlOpts) (*crawlOutput, error) {
	w, err := newWriter(c)
	if err != nil {
		return nil, err
	}
	return &crawlOutput{o: o, w: w, json: c.json, files: map[string]*os.File{}}, nil
}

// keep applies -em, -ef, -mr and -fr to a URL as katana's output does:
// they limit what is printed, not the crawl.
func (c *crawlOutput) keep(raw string) bool {
	o := c.o
	if _, err := url.Parse(raw); err != nil {
		return true
	}
	ext := urlExt(raw)
	switch {
	case o.hasMatch:
		if !o.match[ext] {
			return false
		}
	case o.deny[ext], o.defDeny[ext] && !(c.json && !o.jsonl) && !(o.assets && assetExt(ext)):
		// -json lists the map's rows as they are: the default list is for the lines a crawler prints.
		return false
	}
	if o.mr != nil && !o.mr.MatchString(raw) {
		return false
	}
	if o.fr != nil && o.fr.MatchString(raw) {
		return false
	}
	return true
}

// urlFields are katana's fields of a URL (pkg/output/fields.go, MIT).
func urlFields(raw string) map[string][]string {
	out := map[string][]string{}
	u, err := url.Parse(raw)
	if err != nil {
		return out
	}
	set := func(k, v string) { out[k] = append(out[k], v) }
	host := u.Hostname()
	set("url", raw)
	if rdn := normalize.RegistrableDomain(host); rdn != "" {
		set("rdn", rdn)
	}
	if u.Path != "" {
		set("path", u.Path)
	}
	set("fqdn", host)
	set("rurl", u.Scheme+"://"+u.Host)
	q := u.Query()
	if len(q) > 0 {
		set("qpath", u.Path+"?"+q.Encode())
		set("qurl", raw)
		keys := make([]string, 0, len(q))
		for k := range q {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			set("key", k)
			for _, v := range q[k] {
				set("value", v)
				set("kv", k+"="+v)
			}
		}
	}
	if u.Path != "" && u.Path != "/" {
		if b := path.Base(u.Path); strings.Contains(b, ".") {
			set("file", b)
			set("ufile", u.String())
		}
		if strings.Contains(u.Path[1:], "/") {
			dir := u.Path[:strings.LastIndex(u.Path[1:], "/")+2]
			set("dir", dir)
			set("udir", u.Scheme+"://"+u.Host+dir)
		}
	}
	return out
}

// drop removes the fields -eof names from a line: "tech", or a path into
// an object ("request.tag").
func (c *crawlOutput) drop(row map[string]any) map[string]any {
	for _, name := range c.o.exclude {
		cur := row
		parts := strings.Split(name, ".")
		for i, p := range parts {
			if i == len(parts)-1 {
				delete(cur, p)
				break
			}
			next, ok := cur[p].(map[string]any)
			if !ok {
				break
			}
			cur = next
		}
	}
	return row
}

func (c *crawlOutput) write(r engine.MapEntry, f crawlFact) {
	key := r.Entity.Key
	if len(c.o.store) > 0 {
		c.store(key, rowMethods(r))
	}
	switch {
	case c.o.jsonl:
		c.jsonl(r, f)
	case c.json:
		row := mapRowJSON(r)
		row["url"] = key
		delete(row, "key")
		delete(row, "type")
		if len(f.tech) > 0 {
			row["tech"] = f.tech
		}
		c.w.obj(c.drop(row))
	case c.o.tmpl != "" || len(c.o.fields) > 0:
		// A row with several methods is one set of lines for each, as -jsonl has a line each.
		methods := []string{""}
		if c.o.method {
			methods = rowMethods(r)
		}
		for _, m := range methods {
			fields := urlFields(key)
			fields["method"] = []string{m}
			if c.o.tmpl != "" {
				c.w.line(crawlTagRe.ReplaceAllStringFunc(c.o.tmpl, func(t string) string {
					return strings.Join(fields[crawlTagRe.FindStringSubmatch(t)[1]], "\n")
				}))
				continue
			}
			for _, name := range c.o.fields {
				for _, v := range fields[name] {
					c.w.line(v)
				}
			}
		}
	default:
		c.w.line(key)
	}
}

// jsonl is one line in katana's shape. A URL that was found and not asked
// has no response.
func (c *crawlOutput) jsonl(r engine.MapEntry, f crawlFact) {
	req := map[string]any{"method": "GET", "endpoint": r.Entity.Key}
	if f.tag != "" {
		req["tag"] = f.tag
	}
	if f.attr != "" {
		req["attribute"] = f.attr
	}
	if f.source != "" {
		req["source"] = f.source
	}
	line := map[string]any{"request": req}
	if !r.Entity.FirstSeen.IsZero() {
		line["timestamp"] = r.Entity.FirstSeen.UTC().Format(time.RFC3339Nano)
	}
	resp := map[string]any{}
	if r.Status != 0 {
		resp["status_code"] = r.Status
	}
	if len(f.tech) > 0 {
		resp["technologies"] = f.tech
	}
	if f.length > 0 {
		resp["content_length"] = f.length
	}
	var forms []map[string]any
	for _, mf := range r.Forms {
		form := map[string]any{"method": mf.Method, "action": mf.Action}
		if mf.Enctype != "" {
			form["enctype"] = mf.Enctype
		}
		if len(mf.Fields) > 0 {
			form["parameters"] = mf.Fields
		}
		forms = append(forms, form)
	}
	if len(forms) > 0 {
		resp["forms"] = forms
	}
	if len(resp) > 0 {
		line["response"] = resp
	}
	if r.Coverage == "error" {
		line["error"] = "no answer"
	}
	c.w.obj(c.drop(line))
	for _, m := range r.Methods {
		if m == "GET" {
			continue
		}
		req2 := map[string]any{}
		for k, v := range req {
			req2[k] = v
		}
		req2["method"] = m
		c.w.obj(c.drop(map[string]any{"timestamp": line["timestamp"], "request": req2}))
	}
}

func (c *crawlOutput) writeOut(o outLink) {
	if c.o.jsonl || c.json {
		c.w.obj(map[string]any{"url": o.url, "coverage": "out-of-scope", "source": o.source, "tag": o.tag, "attribute": o.attr})
		return
	}
	c.w.line(o.url)
}

func (c *crawlOutput) writeRejected(x rejectedStr) {
	if c.o.jsonl || c.json {
		row := map[string]any{"rejected": x.str, "reason": x.reason, "source": x.source, "via": x.via}
		if x.url != "" {
			row["url"] = x.url
		}
		c.w.obj(row)
		return
	}
	c.w.line(x.str + "\t" + x.reason)
}

// rowMethods are the methods a row is listed with: those scripts and
// descriptions call it with, GET for a page nothing calls another way.
func rowMethods(r engine.MapEntry) []string {
	if len(r.Methods) == 0 {
		return []string{"GET"}
	}
	return r.Methods
}

// store appends the fields of a URL to the -sf files.
func (c *crawlOutput) store(raw string, methods []string) {
	u, err := url.Parse(raw)
	if err != nil {
		return
	}
	_ = os.MkdirAll(c.o.dir, 0o755)
	fields := urlFields(raw)
	fields["method"] = methods
	for _, name := range c.o.store {
		for _, v := range fields[name] {
			file := filepath.Join(c.o.dir, fmt.Sprintf("%s_%s_%s.txt", u.Scheme, u.Hostname(), name))
			f := c.files[file]
			if f == nil {
				if f, err = os.OpenFile(file, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); err != nil {
					return
				}
				c.files[file] = f
			}
			fmt.Fprintln(f, v)
		}
	}
}

func (c *crawlOutput) close() error {
	for _, f := range c.files {
		f.Close()
	}
	return c.w.close()
}

// answerTap is what a crawl -sr does with each answer; mapTarget hands it to fetch.
var answerTap func(string, fetch.Result)

// answerStore writes the answers a crawl gets to DIR/HOST/SHA1.txt with an
// index (katana's -sr layout), as they come.
type answerStore struct {
	mu       sync.Mutex
	dir      string
	omitBody bool
	idx      *os.File
	n        int
	err      error
}

func newAnswerStore(dir string, omitBody bool) (*answerStore, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	idx, err := os.Create(filepath.Join(dir, "index.txt"))
	if err != nil {
		return nil, err
	}
	return &answerStore{dir: dir, omitBody: omitBody, idx: idx}, nil
}

func (a *answerStore) tap(raw string, res fetch.Result) {
	if res.Status == 0 {
		return
	}
	u, err := url.Parse(raw)
	if err != nil {
		return
	}
	sum := sha1.Sum([]byte(raw))
	name := hex.EncodeToString(sum[:]) + ".txt"
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n\nGET %s\n\n%s\n", raw, u.RequestURI(), res.StatusLine)
	keys := make([]string, 0, len(res.Header))
	for k := range res.Header {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "%s: %s\n", k, strings.Join(res.Header[k], ", "))
	}
	if !a.omitBody {
		b.WriteString("\n")
		b.Write(res.Body)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	hostDir := filepath.Join(a.dir, u.Hostname())
	if err := os.MkdirAll(hostDir, 0o755); err == nil {
		err = os.WriteFile(filepath.Join(hostDir, name), []byte(b.String()), 0o644)
		if err == nil {
			fmt.Fprintf(a.idx, "%s/%s %s (%d)\n", u.Hostname(), name, raw, res.Status)
			a.n++
			return
		}
		a.err = err
	} else {
		a.err = err
	}
}

func (a *answerStore) close() error {
	a.idx.Close()
	return a.err
}
