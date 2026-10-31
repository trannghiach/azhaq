package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/trannghiach/azhaq/internal/collectors/subcol"
	"github.com/trannghiach/azhaq/store"
	"github.com/trannghiach/azhaq/types"
)

// subsMode is what subs tells the run it starts.
var subsMode struct {
	NoCheck   bool // names only guessed are listed unverified, not looked up
	Recursive bool // only the sources that handle subdomains of subdomains
}

// subsOut writes the names subs prints: text, subfinder's host,[sources] and
// host,ip,source forms, or JSON; with -oD also a file per domain.
type subsOut struct {
	w        *writer
	cs, oI   bool
	dir      string
	perInput map[string]*bytes.Buffer
	live     bool
	cnameN   int // live names that are a CNAME with no address of their own
	// takeover is the candidates DNS found, by name: -json rows carry them.
	takeover map[string]takeoverRow
}

func (o *subsOut) put(input, name string, row map[string]any, ips, by []string) {
	if o.live && len(ips) == 0 {
		o.cnameN++
	}
	if t, ok := o.takeover[name]; ok && o.w.json {
		row["takeover"] = t.Finding
	}
	var line string
	switch {
	case o.w.json:
		raw, _ := json.Marshal(row)
		line = string(raw)
	case o.oI:
		ip := ""
		if len(ips) > 0 {
			ip = ips[0]
		}
		src := ""
		if len(by) > 0 {
			src = by[0]
		}
		line = name + "," + ip + "," + src
	case o.cs:
		line = name + ",[" + strings.Join(by, ",") + "]"
	default:
		line = name
	}
	if o.w.json {
		o.w.obj(row)
	} else {
		o.w.line(line)
	}
	if o.dir != "" {
		b := o.perInput[input]
		if b == nil {
			b = &bytes.Buffer{}
			o.perInput[input] = b
		}
		b.WriteString(line + "\n")
	}
}

// files writes the -oD files: one per domain, even when it has no names.
func (o *subsOut) files(domains []string, ext string) error {
	if o.dir == "" {
		return nil
	}
	if err := os.MkdirAll(o.dir, 0o755); err != nil {
		return err
	}
	for _, d := range domains {
		b := o.perInput[d]
		if b == nil {
			b = &bytes.Buffer{}
		}
		if err := os.WriteFile(filepath.Join(o.dir, d+ext), b.Bytes(), 0o644); err != nil {
			return err
		}
	}
	return nil
}

// printSources is -ls: the sources, with subfinder's marks (* needs a key,
// ~ takes one), or one JSON object each.
func printSources(asJSON bool) {
	list := subcol.Sources()
	for _, s := range list {
		switch {
		case asJSON:
			raw, _ := json.Marshal(s)
			fmt.Println(string(raw))
		case s.KeyRequirement == "required":
			fmt.Println(s.Name + " *")
		case s.KeyRequirement == "optional":
			fmt.Println(s.Name + " ~")
		default:
			fmt.Println(s.Name)
		}
	}
}

// cmdSubs is subfinder (and subfinder | dnsx with -live; with -w and
// -permute, puredns and alterx too).
func cmdSubs(args []string) error {
	fs := newFlags("subs")
	var c common
	c.register(fs)
	var domains stringsFlag
	fs.Var(&domains, "d", "domain (repeatable; a comma list, a URL or a name with a trailing dot is cleaned, as subfinder does)")
	list := fs.String("dL", "", "file of domains (- for stdin)")
	live := fs.Bool("live", false, "only names that resolve (wildcard answers left out); without it nothing is looked up and the guesses are listed unverified")
	nW := fs.Bool("nW", false, "same as -live (subfinder's name)")
	words := fs.String("w", "", "also resolve WORD.domain for each word in this file, like puredns bruteforce (active DNS; the names found are live)")
	permute := fs.Bool("permute", false, "also resolve variations of the names found (api → api-dev, api2, dev.api), like alterx | dnsx (active DNS)")
	oJ := fs.Bool("oJ", false, "same as -json (subfinder's name)")
	ls := fs.Bool("ls", false, "list the sources and exit: name, then * if a key is required and ~ if one improves the answer; with -json one object each (name, default, recursive, keyRequirement)")
	cs := fs.Bool("cs", false, "text output: host,[source,source] (subfinder -cs)")
	oI := fs.Bool("oI", false, "text output: host,ip,source, with -live (subfinder -oI); -json rows get an ip field")
	oD := fs.String("oD", "", "write one file per domain into this directory (NAME.txt, NAME.json with -json), as well as stdout")
	var match, filter, matchRe, filterRe stringsFlag
	fs.Var(&match, "m", "only names matching these (comma list or file; * matches anything), as subfinder -m")
	fs.Var(&filter, "f", "leave out names matching these (comma list or file), as subfinder -f")
	fs.Var(&matchRe, "match-regex", "only names matching this regular expression (repeatable)")
	fs.Var(&filterRe, "filter-regex", "leave out names matching this regular expression (repeatable)")
	_ = fs.Bool("ei", false, "accepted for subfinder's sake: an IP address given as a domain is always left out with a note")
	recursive := fs.Bool("recursive", false, "only sources that look for subdomains of subdomains, as subfinder -recursive (see -ls)")
	stats := fs.Bool("stats", false, "after the run, one note per source: requests, names, errors and seconds, as subfinder -stats")
	showVersion := fs.Bool("version", false, "print the version and exit")
	given := inherit(fs, "sources", "exclude-sources", "all-sources", "no-history", "source-timeout", "providers", "resolvers", "dns-rate", "timeout", "v", "fail-on-errors",
		"source-rate", "source-rates", "max-results", "max-time", "max-body", "proxy=source-proxy", "t=parallel")
	maxNames := fs.Int("max-names", 0, fmt.Sprintf("most names kept per domain, and looked up with -live (default %d)", subcol.DefaultMaxNames))
	if err := parse(fs, args); err != nil {
		return err
	}
	if *oJ {
		c.json = true
	}
	if *showVersion {
		fmt.Println("azhaq " + version)
		return nil
	}
	if *ls {
		printSources(c.json)
		return nil
	}
	if *oI && !(*live || *nW) {
		return usagef("-oI prints the address, so it needs -live (or -nW)")
	}
	*live = *live || *nW
	filt, err := compileSubsFilter(listOrFile(match), listOrFile(filter), matchRe, filterRe)
	if err != nil {
		return usagef("%v", err)
	}
	filtering := len(match)+len(filter)+len(matchRe)+len(filterRe) > 0
	raw, err := inputs(domains, *list)
	if err != nil {
		return err
	}
	ds, dnotes := subsDomains(raw)
	if len(raw) == 0 {
		return usagef("give -d DOMAIN, -dL FILE or domains on stdin")
	}
	if len(ds) == 0 {
		return usagef("no domain such as example.com in the input (%s)", strings.Join(dnotes, "; "))
	}
	rep := newReport("subs")
	rep.what = "names"
	rep.Notes = append(rep.Notes, dnotes...)
	keep := []string{"azhaq-subdomains"}
	active := *words != "" || *permute
	if *live || active {
		keep = append(keep, "azhaq-dns")
	}
	if *live {
		rep.what = "live names"
	}
	run := []string{"-passive"}
	if *words != "" {
		keep = append(keep, "azhaq-dns-brute")
		run = append(run, "-dns-brute", *words)
	}
	if *permute {
		keep = append(keep, "azhaq-permute")
		run = append(run, "-permute")
	}
	run = append(run, "-skip", skipAllBut(keep...))
	var apexes []string
	for _, d := range ds {
		apexes = append(apexes, d)
		run = append(run, "-domain", d)
		if active {
			// The domains given are the scope of the guesses.
			run = append(run, "-allow", d)
		}
	}
	if !*live && !active {
		// The names are known once the sources answer: no DNS to wait for.
		run = append(run, "-depth", "0")
	}
	extra := given()
	switch {
	case *maxNames > 0:
		extra = append(extra, "-max-names="+fmt.Sprint(*maxNames))
	case *live:
		// A big zone is not cut at the run's default of 20,000 names looked up.
		extra = append(extra, "-max-names="+fmt.Sprint(subcol.DefaultMaxNames))
	}
	subsMode.NoCheck, subsMode.Recursive = !*live && !active, *recursive
	// The output is opened before anything is sent: a bad -o is not found out
	// after the run. Without -live a domain's names are printed when its
	// sources have answered, as subfinder prints a domain when it ends.
	c.appendOut = true // subfinder's -o appends
	w, err := newWriter(&c)
	if err != nil {
		return err
	}
	out := &subsOut{w: w, cs: *cs, oI: *oI, dir: *oD, perInput: map[string]*bytes.Buffer{}, live: *live}
	var alive map[string]map[string]any
	seen := map[string]bool{}
	answered, ran, failedOff := 0, 0, 0
	verbose := hasFlag(extra, "v")
	private := map[string]bool{}
	collected := map[string]bool{} // every passive name, before the -live filter
	bySource := map[string]int{}   // how many each source returned
	var union, dropped, unverified, notChecked, filtered, dup, cut, didNot int
	health := newHealthTally(false)
	var procMu sync.Mutex
	processed := map[string]bool{}
	process := func(p map[string]any) {
		procMu.Lock()
		defer procMu.Unlock()
		input, _ := p["domain"].(string)
		if processed[input] {
			return
		}
		processed[input] = true
		foundBy, _ := p["found_by"].(map[string]any)
		srcs, _ := p["sources"].(map[string]any)
		health.add(input, srcs)
		union += intOf(p["from_sources"])
		dropped += intOf(p["dropped"])
		cut += intOf(p["names_cut"])
		unver := map[string]bool{}
		for _, n := range strs(p["unverified"]) {
			unver[n] = true
		}
		wild := map[string]bool{}
		for _, n := range strs(p["wildcard_certificate"]) {
			wild[n] = true
		}
		for name, v := range srcs {
			row, _ := v.(map[string]any)
			if strings.HasPrefix(fmt.Sprint(row["skipped"]), "not a public domain") && !private[input] {
				private[input] = true
				rep.Notes = append(rep.Notes, input+": not a public domain, so no third-party source was asked (its TLD has no registry); -w or the name history find its names")
			}
			if name == "history" {
				continue // a local file, not a source that was asked
			}
			if row["skipped"] == nil {
				ran++
				if row["error"] == nil {
					answered++
				} else if row["default"] == false {
					failedOff++ // -all-sources reaches for flaky ones: counted apart
				}
			}
			if n, _ := row["partial"].(string); n != "" {
				rep.Notes = append(rep.Notes, fmt.Sprintf("%s: %s gave a partial answer: %s", input, name, n))
			}
			if row["rate_limited"] == true {
				rep.Notes = append(rep.Notes, rateLimitNote(input, name, row))
			}
		}
		if verbose {
			rep.Notes = append(rep.Notes, sourceDetail(input, srcs))
		}
		if n := slowSource(input, srcs); n != "" {
			rep.Notes = append(rep.Notes, n)
		}
		if *stats {
			rep.Notes = append(rep.Notes, sourceStats(input, srcs)...)
		}
		if n := guessCheck(input, srcs); n != "" {
			rep.Notes = append(rep.Notes, n)
		}
		for _, by := range foundBy {
			for _, s := range strs(by) {
				bySource[s]++ // sources credited with a name Azhaq kept
			}
		}
		for _, name := range strs(p["names"]) {
			collected[name] = true
			switch {
			case seen[name]:
				dup++
				continue
			case !filt.keep(name):
				filtered++
				continue
			case alive != nil && alive[name] == nil:
				if unver[name] {
					notChecked++
				} else {
					didNot++
				}
				continue
			}
			seen[name] = true
			if unver[name] {
				unverified++
			}
			by := strs(foundBy[name])
			row := map[string]any{"host": name, "input": input}
			if len(by) > 0 {
				row["source"], row["sources"] = by[0], by
			}
			if unver[name] {
				row["unverified"] = true
			}
			if wild[name] {
				row["wildcard_certificate"] = true
			}
			var ips []string
			if alive != nil {
				liveFields(row, alive[name])
				ips = strs(alive[name]["ips"])
				if *oI && len(ips) > 0 {
					row["ip"] = ips[0]
				}
			}
			out.put(input, name, row, ips, by)
		}
	}
	var observe func(types.Entity, types.Observation)
	if !*live {
		observe = func(_ types.Entity, o types.Observation) {
			if o.Collector != "azhaq-subdomains" || o.Kind != "subdomains" {
				return
			}
			var p map[string]any
			if json.Unmarshal(o.Payload, &p) == nil {
				process(p)
			}
		}
	}
	st, done, err := runPreset(&c, append(run, extra...), rep, observe)
	subsMode.NoCheck, subsMode.Recursive = false, false
	if err != nil {
		w.close()
		return err
	}
	defer done()
	out.takeover = map[string]takeoverRow{}
	for _, t := range rep.Takeover {
		out.takeover[t.Host] = t
	}
	if *live {
		// A name with an address, or one that is a CNAME (dnsx -a -cname
		// lists those too, dangling or not): it exists in DNS.
		alive = liveNames(st)
		for name, p := range cnameNames(st) {
			if alive[name] == nil {
				alive[name] = p
			}
		}
	}
	for _, p := range payloads(st, "azhaq-subdomains") {
		process(p) // the ones not printed yet: every one with -live
	}
	// Names the guesses found. A dangling CNAME is found but not live: with
	// -live it shows as a takeover candidate, not as a name.
	guessed := 0
	for _, g := range []struct{ collector, source string }{{"azhaq-dns-brute", "dns-brute"}, {"azhaq-permute", "permute"}} {
		for _, p := range payloads(st, g.collector) {
			for _, name := range strs(p["names"]) {
				if seen[name] || (alive != nil && alive[name] == nil) || !filt.keep(name) {
					continue
				}
				seen[name] = true
				guessed++
				row := map[string]any{"host": name, "input": apexOf(name, apexes), "source": g.source, "sources": []string{g.source}}
				var ips []string
				if alive != nil {
					liveFields(row, alive[name])
					ips = strs(alive[name]["ips"])
					if *oI && len(ips) > 0 {
						row["ip"] = ips[0]
					}
				}
				out.put(apexOf(name, apexes), name, row, ips, []string{g.source})
			}
		}
	}
	// Live names under the domains that DNS met as another name's CNAME
	// target: no source gave them, but they are found and in scope.
	viaCNAME := 0
	if alive != nil {
		var extra []string
		for name := range alive {
			if !seen[name] && apexOf(name, apexes) != "" && filt.keep(name) {
				extra = append(extra, name)
			}
		}
		sort.Strings(extra)
		for _, name := range extra {
			seen[name] = true
			viaCNAME++
			row := map[string]any{"host": name, "input": apexOf(name, apexes), "source": "cname", "sources": []string{"cname"}}
			liveFields(row, alive[name])
			ips := strs(alive[name]["ips"])
			if *oI && len(ips) > 0 {
				row["ip"] = ips[0]
			}
			out.put(apexOf(name, apexes), name, row, ips, []string{"cname"})
		}
	}
	ext := ".txt"
	if c.json {
		ext = ".json"
	}
	if err := out.files(apexes, ext); err != nil {
		return err
	}
	if err := w.close(); err != nil {
		return err
	}
	rep.Results = w.count()
	rep.Sources = health.result()
	rep.failOnErrors = hasFlag(extra, "fail-on-errors")
	rep.Counts = map[string]int{"sources asked": ran, "sources answered": answered, "sources failed": ran - answered - failedOff, "off-by-default failed": failedOff}
	rep.Degraded = rep.Counts["sources failed"] > 0
	if active {
		rep.Counts["found by guessing"] = guessed
	}
	// The names add up: from sources, less what was dropped or left out,
	// plus what DNS and the guesses added, is what was printed.
	rep.Counts["from sources"] = union
	set := func(k string, n int) {
		if n > 0 {
			rep.Counts[k] = n
		}
	}
	set("did not resolve", dropped+didNot)
	if *live {
		// Show the live/dead split: a raw subdomain count is mostly names
		// that do not resolve (stale certificate logs, wildcard noise). The
		// live set is the one you can act on.
		rep.Counts["collected"] = len(collected)
		rep.Counts["resolved from sources"] = rep.Results - guessed - viaCNAME
		set("found as CNAME targets", viaCNAME)
	}
	set("CNAME only", out.cnameN)
	set("not checked", notChecked)
	set("unverified", unverified)
	set("left out by -m/-f", filtered)
	set("listed under another domain", dup)
	set("cut by -max-names", cut)
	if cut > 0 {
		rep.Notes = append(rep.Notes, fmt.Sprintf("%d names were cut at -max-names: raise it to keep them", cut))
		rep.warned = true
	}
	if unverified > 0 {
		rep.Notes = append(rep.Notes, fmt.Sprintf("%d names are listed unverified (-json: \"unverified\": true): they came from subdomain.center's guesses or the name history and no DNS lookup was made; -live checks them", unverified))
	}
	if notChecked > 0 {
		rep.Notes = append(rep.Notes, fmt.Sprintf("%d names could not be checked (the resolvers failed) and are left out; azhaq resume checks them", notChecked))
		rep.warned = true
	}
	if s := topSources(bySource, 8); s != "" {
		rep.Notes = append(rep.Notes, "sources: "+s)
	}
	if n := nameSum(rep.Counts, rep.Results, filtering); n != "" {
		rep.Notes = append(rep.Notes, n)
	}
	rep.Notes = append(rep.Notes, subsNotes(payloads(st, "azhaq-subdomains"), seen)...)
	if c.db != "" {
		rep.Next = append(rep.Next, "azhaq query -db "+c.db+" -type Hostname")
	}
	return rep.finish(c.json, c.silent)
}

// nameSum is the note that lets a reader check the counts: the names the
// sources gave, less what was dropped, plus what DNS added, are the names
// printed.
func nameSum(c map[string]int, results int, filtering bool) string {
	if c["from sources"] == 0 {
		return ""
	}
	parts := []string{fmt.Sprintf("%d from the sources", c["from sources"])}
	minus := func(k, label string) {
		if c[k] > 0 {
			parts = append(parts, fmt.Sprintf("− %d %s", c[k], label))
		}
	}
	minus("did not resolve", "did not resolve")
	minus("not checked", "not checked")
	minus("left out by -m/-f", "left out by -m/-f")
	minus("listed under another domain", "listed under another domain")
	minus("cut by -max-names", "cut by -max-names")
	if n := c["found as CNAME targets"]; n > 0 {
		parts = append(parts, fmt.Sprintf("+ %d found as CNAME targets", n))
	}
	if n := c["found by guessing"]; n > 0 {
		parts = append(parts, fmt.Sprintf("+ %d found by guessing", n))
	}
	return fmt.Sprintf("count: %s = %d printed", strings.Join(parts, " "), results)
}

// rateLimitNote says what a source's 429 answers cost.
func rateLimitNote(domain, source string, row map[string]any) string {
	n := intOf(row["retried_429"])
	switch {
	case row["gave_up_429"] == true && n == 0:
		return fmt.Sprintf("%s: %s answered 429 and asked for %v s (Retry-After), more than is waited for: its names are missing", domain, source, row["retry_after_seconds"])
	case row["gave_up_429"] == true:
		return fmt.Sprintf("%s: %s kept answering 429 after %d retries and %v s of waiting: its answer may be partial", domain, source, n, row["waited_seconds"])
	}
	return fmt.Sprintf("%s: %s answered 429; it was asked again %d times after %v s of waiting (Retry-After) and answered", domain, source, n, row["waited_seconds"])
}

// sourceStats is -stats: a note per source.
func sourceStats(domain string, srcs map[string]any) []string {
	var out []string
	for _, name := range slices.Sorted(maps.Keys(srcs)) {
		row, _ := srcs[name].(map[string]any)
		if row["skipped"] != nil || name == "history" {
			continue
		}
		errs := 0
		if row["error"] != nil {
			errs = 1
		}
		out = append(out, fmt.Sprintf("%s stats: %s requests %v, names %v, errors %d, seconds %v", domain, name, row["requests"], row["count"], errs, row["seconds"]))
	}
	return out
}

// topSources renders the n biggest sources as "crtname 32, rapiddns 20, …",
// so a thin result shows which sources answered and which were dark, and a
// raw count is read next to where it came from.
func topSources(by map[string]int, n int) string {
	type kv struct {
		s string
		n int
	}
	var all []kv
	for s, c := range by {
		if c > 0 {
			all = append(all, kv{s, c})
		}
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].n != all[j].n {
			return all[i].n > all[j].n
		}
		return all[i].s < all[j].s
	})
	var parts []string
	for i, x := range all {
		if i >= n {
			parts = append(parts, fmt.Sprintf("+%d more", len(all)-n))
			break
		}
		parts = append(parts, fmt.Sprintf("%s %d", x.s, x.n))
	}
	return strings.Join(parts, ", ")
}

// cnameNames maps each name azhaq-dns found as a CNAME with no address of
// its own, a wildcard zone's answers left out, to its payload.
func cnameNames(st *store.Store) map[string]map[string]any {
	out := map[string]map[string]any{}
	for _, p := range payloads(st, "azhaq-dns") {
		name, _ := p["fqdn"].(string)
		if name != "" && p["wildcard"] == nil && len(strs(p["cnames"])) > 0 && len(strs(p["ips"])) == 0 && out[name] == nil {
			out[name] = p
		}
	}
	return out
}

// liveFields is dnsFields for a name that may have no address: a CNAME
// that leads nowhere has no a.
func liveFields(row, p map[string]any) {
	dnsFields(row, p)
	if a, ok := row["a"].([]string); ok && len(a) == 0 {
		delete(row, "a")
	}
}
