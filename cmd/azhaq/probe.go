package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/trannghiach/azhaq/engine"
	"github.com/trannghiach/azhaq/internal/fingerprint"
	"github.com/trannghiach/azhaq/internal/normalize"
	"github.com/trannghiach/azhaq/internal/pagekind"
	"github.com/trannghiach/azhaq/store"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/trannghiach/azhaq/internal/collectors/httpcol"
	"github.com/trannghiach/azhaq/internal/probefilter"
)

// probeFlags are the flags of probe that httpx has and run does not: what
// to ask, what to print, what to keep.
type probeFlags struct {
	// input
	paths, ports, methods, body, rawFile, sni      string
	noFallback, noDecode, probeAllIPs, noStdin, vi bool
	exclude                                        string
	// redirects and requests
	follow, sameHost bool
	maxRedirects     int
	retries          int
	reqTimeout       time.Duration
	// display
	sc, cl, ct, location, title, td, server, ws, method, ip, cname, asn, cdn, rt, lc, wc bool
	tlsGrab, jarm, http2, pipeline, vhost, probe                                         bool
	hash, strip                                                                          string
	preview                                                                              int
	extractRe                                                                            stringsFlag
	extractPreset                                                                        string
	// matchers and filters
	mc, ml, mlc, mwc, mfc, ms, mcdn, mrt, mdc string
	fc, fl, flc, fwc, ffc, fs, fcdn, frt, fdc string
	mr, fe                                    stringsFlag
	fd                                        bool
	// output
	csv, md, irh, irr, irrb, includeChain, sr, ob, storeChain bool
	srd, oa, eof, csvo, im, cff                               string
	rstr, rsts                                                int
	debug, debugReq, debugResp, lof, ldp                      bool
	// products and kinds of page
	cpe, wp, kb, fep          bool
	tlsProbe, cspProbe, efqdn bool
	ss                        bool
	fpt                       string
	// requests
	proxy                      string
	rhsts, autoReferer, random bool
	maxhr                      int
	delay                      time.Duration
}

// register adds the flags to fs under httpx's names (long and short).
func (p *probeFlags) register(fs *flag.FlagSet) {
	str := func(v *string, usage string, names ...string) {
		for _, n := range names {
			fs.StringVar(v, n, "", usage)
		}
	}
	boolean := func(v *bool, usage string, names ...string) {
		for _, n := range names {
			fs.BoolVar(v, n, false, usage)
		}
	}
	str(&p.ports, "ports to probe on each name: 80,443,8000-8100, each led by http: or https: to ask one scheme only (http:80,https:443)", "p", "ports", "web-ports")
	str(&p.paths, "path or paths to ask of every target in place of its own: a list, comma-separated, or a file", "path")
	boolean(&p.noFallback, "ask an input without a scheme over both http and https and report each that answers", "nf", "no-fallback")
	boolean(&p.probeAllIPs, "send the request to every address of a name, one row each", "pa", "probe-all-ips")
	str(&p.exclude, "leave out: cdn (ports other than 80 and 443 of CDN addresses), private-ips, a port, an address or range, or a regex", "e", "exclude")
	str(&p.sni, "TLS server name to ask for, whatever the host", "sni", "sni-name")
	boolean(&p.noDecode, "hash and match the body as sent, not converted to UTF-8", "no-decode")
	str(&p.im, "input mode: burp reads the URLs of a Burp XML export given with -l", "im", "input-mode")
	boolean(&p.vi, "lines are vhost,ip: ask the ip with the vhost as Host", "vi", "vhost-input")
	str(&p.cff, "wappalyzer fingerprints (JSON) to add to the built-in ones", "cff", "custom-fingerprint-file")
	boolean(&p.noStdin, "do not read targets from stdin", "no-stdin")
	boolean(&p.follow, "follow redirects within the site (status, title and length are then the last answer's; the chain is in chain_status_codes)", "fr", "follow-redirects")
	boolean(&p.sameHost, "with -fr: follow redirects to the same host only", "fhr", "follow-host-redirects")
	fs.IntVar(&p.maxRedirects, "maxr", 10, "with -fr: redirects to follow")
	fs.IntVar(&p.maxRedirects, "max-redirects", 10, "with -fr: redirects to follow")
	fs.IntVar(&p.retries, "retries", 0, "times to send a request again when nothing answered (each counts as a request)")
	fs.DurationVar(&p.reqTimeout, "req-timeout", 0, "time one request may take (default 10 s to the first byte, 30 s in all); -timeout bounds the whole run")

	str(&p.methods, "also send these methods to every target (GET, POST, HEAD, …; all for the common ones): requests that can change data on the target", "x")
	str(&p.body, "body sent with the -x methods: it can change data on the target", "body")
	str(&p.rawFile, "send the request in this file (request line, headers, blank line, body) to every target: it can change data on the target", "rr", "request")

	boolean(&p.sc, "print the status code", "sc", "status-code")
	boolean(&p.cl, "print the content length", "cl", "content-length")
	boolean(&p.ct, "print the content type", "ct", "content-type")
	boolean(&p.location, "print the redirect location (and where a followed chain ended)", "location")
	boolean(&p.title, "print the page title", "title")
	boolean(&p.td, "print the technologies", "td", "tech-detect")
	boolean(&p.server, "print the Server header", "server", "web-server")
	boolean(&p.ws, "print websocket for a server that speaks it", "websocket")
	boolean(&p.method, "print the request method", "method")
	boolean(&p.ip, "print the address connected to", "ip")
	boolean(&p.cname, "print the first CNAME", "cname")
	boolean(&p.asn, "print and report the autonomous system of the address (RIPEstat)", "asn")
	boolean(&p.cdn, "print the CDN, WAF or cloud in front", "cdn")
	boolean(&p.rt, "print the response time", "rt", "response-time")
	boolean(&p.lc, "print the line count", "lc", "line-count")
	boolean(&p.wc, "print the word count", "wc", "word-count")
	boolean(&p.tlsGrab, "report the certificate and the TLS version of each answer", "tls-grab")
	boolean(&p.jarm, "report the JARM fingerprint of TLS servers (ten handshakes a server)", "jarm")
	boolean(&p.http2, "report whether the server speaks HTTP/2 (one more request each)", "http2")
	boolean(&p.pipeline, "report whether the server answers pipelined requests (ten requests each)", "pipeline")
	boolean(&p.vhost, "report a virtual host (one more request each)", "vhost")
	boolean(&p.probe, "print a row for every target: [SUCCESS], or [FAILED] when nothing answered", "probe")
	str(&p.hash, "report these body and header digests: md5,mmh3,simhash,sha1,sha256,sha512", "hash")
	fs.IntVar(&p.preview, "bp", 0, "print the first N characters of the body")
	fs.IntVar(&p.preview, "body-preview", 0, "print the first N characters of the body")
	str(&p.strip, "strip tags from the body preview: html or xml (the preview always has its tags stripped, as httpx)", "strip")
	fs.Var(&p.extractRe, "er", "print what this regex finds in the response (repeatable)")
	fs.Var(&p.extractRe, "extract-regex", "print what this regex finds in the response (repeatable)")
	str(&p.extractPreset, "print what a ready regex finds: url, ipv4, mail", "ep", "extract-preset")

	for _, m := range []struct {
		v     *string
		usage string
		names []string
	}{
		{&p.mc, "keep rows with these status codes (200,302, spans 200-299, classes 4xx)", []string{"mc", "match-code"}},
		{&p.fc, "drop rows with these status codes", []string{"fc", "filter-code"}},
		{&p.ml, "keep rows with these content lengths", []string{"ml", "match-length"}},
		{&p.fl, "drop rows with these content lengths", []string{"fl", "filter-length"}},
		{&p.mlc, "keep rows with these line counts", []string{"mlc", "match-line-count"}},
		{&p.flc, "drop rows with these line counts", []string{"flc", "filter-line-count"}},
		{&p.mwc, "keep rows with these word counts", []string{"mwc", "match-word-count"}},
		{&p.fwc, "drop rows with these word counts", []string{"fwc", "filter-word-count"}},
		{&p.mfc, "keep rows with these favicon hashes (implies the favicon request)", []string{"mfc", "match-favicon"}},
		{&p.ffc, "drop rows with these favicon hashes (implies the favicon request)", []string{"ffc", "filter-favicon"}},
		{&p.ms, "keep rows whose response (headers and body) holds one of these strings, comma-separated, any case", []string{"ms", "match-string"}},
		{&p.fs, "drop rows whose response holds one of these strings", []string{"fs", "filter-string"}},
		{&p.mcdn, "keep rows behind these CDN providers", []string{"mcdn", "match-cdn"}},
		{&p.fcdn, "drop rows behind these CDN providers", []string{"fcdn", "filter-cdn"}},
		{&p.mrt, "keep rows by response time: '< 1', '>= 500ms'", []string{"mrt", "match-response-time"}},
		{&p.frt, "drop rows by response time: '> 1'", []string{"frt", "filter-response-time"}},
		{&p.mdc, "keep rows for which this condition holds, over the -json fields: 'contains(body, \"admin\") && status_code == 200'", []string{"mdc", "match-condition"}},
		{&p.fdc, "drop rows for which this condition holds", []string{"fdc", "filter-condition"}},
	} {
		for _, n := range m.names {
			fs.StringVar(m.v, n, "", m.usage)
		}
	}
	fs.Var(&p.mr, "mr", "keep rows whose response matches every one of these regexes (repeatable)")
	fs.Var(&p.mr, "match-regex", "keep rows whose response matches every one of these regexes (repeatable)")
	fs.Var(&p.fe, "fe", "drop rows whose response matches one of these regexes (repeatable)")
	fs.Var(&p.fe, "filter-regex", "drop rows whose response matches one of these regexes (repeatable)")
	boolean(&p.fd, "drop rows that answer almost as one already printed (same status and a body within 3 bits of its simhash)", "fd", "filter-duplicates")

	boolean(&p.csv, "print CSV, as httpx", "csv")
	boolean(&p.md, "print a Markdown table", "md", "markdown")
	boolean(&p.irh, "add the response headers to -json rows (header, raw_header)", "irh", "include-response-header")
	boolean(&p.irr, "add the request and the response to -json rows (request, body, header, raw_header)", "irr", "include-response")
	boolean(&p.irrb, "like -irr, base64-encoded", "irrb", "include-response-base64")
	boolean(&p.includeChain, "add each hop of a followed redirect to -json rows (chain)", "include-chain")
	boolean(&p.sr, "store each response (request and response as sent) under -srd/response/HOST/SHA1.txt, with an index.txt", "sr", "store-response")
	boolean(&p.storeChain, "like -sr, with the redirect chain in the file", "store-chain")
	boolean(&p.ob, "with -sr: leave the body out of the stored file", "ob", "omit-body")
	str(&p.srd, "directory of -sr (default output)", "srd", "store-response-dir")
	str(&p.oa, "write the results to FILE (text), FILE.json, FILE.csv and FILE.md", "oa", "output-all")
	str(&p.eof, "leave these fields out of -json rows, comma-separated", "eof", "exclude-output-fields")
	for _, n := range []string{"rstr", "response-size-to-read"} {
		fs.IntVar(&p.rstr, n, 0, "most bytes read of a response (default 2 MiB of a page, 16 MiB of a script)")
	}
	for _, n := range []string{"rsts", "response-size-to-save"} {
		fs.IntVar(&p.rsts, n, 0, "with -sr: most bytes of a response stored (0: all that was read)")
	}
	str(&p.csvo, "CSV encoding: utf-8 writes a byte order mark first (implies -csv)", "csvo", "csv-output-encoding")
	boolean(&p.debug, "print each request and response to stderr", "debug")
	boolean(&p.debugReq, "print each request to stderr", "debug-req")
	boolean(&p.debugResp, "print each response to stderr", "debug-resp")
	boolean(&p.lof, "list the fields -json rows hold, and stop", "lof", "list-output-fields", "ldv", "list-dsl-variables")
	boolean(&p.ldp, "print URLs with their default port (:80, :443)", "ldp", "leave-default-ports")
	boolean(&p.ss, "save a screenshot of each web service's front page under -srd/screenshot (Chrome on the machine); rows are printed when the run ends, with screenshot_path; implies -sr", "ss", "screenshot")
	boolean(&p.tlsProbe, "probe the names of each certificate too (implies -tls-grab)", "tls-probe")
	boolean(&p.cspProbe, "probe the names of each Content-Security-Policy too", "csp-probe")
	boolean(&p.efqdn, "report the names a page and its policy name: csp, body_fqdn, body_domains", "efqdn", "extract-fqdn")
	boolean(&p.cpe, "report products by title, body and favicon, as CPE (add -favicon for the hash)", "cpe")
	boolean(&p.wp, "report WordPress plugins and themes", "wp", "wordpress")
	boolean(&p.kb, "report the kind of page (login, captcha, …) in knowledgebase; needs the dit model (see TROUBLESHOOTING)", "kb", "knowledge-base")
	str(&p.fpt, "drop rows of these page types, comma-separated (login,captcha,parked,error…); implies -kb", "fpt", "filter-page-type")
	boolean(&p.fep, "drop error pages (as -fpt error)", "fep", "filter-error-page")
	str(&p.proxy, "send every request through this proxy (http://, https:// or socks5://)", "proxy", "http-proxy")
	boolean(&p.rhsts, "with -fr: go to https when a redirect's answer sent Strict-Transport-Security", "rhsts", "respect-hsts")
	boolean(&p.autoReferer, "send each request's URL as its Referer", "auto-referer")
	boolean(&p.random, "send a browser's User-Agent picked at random for each request", "random-agent")
	fs.IntVar(&p.maxhr, "maxhr", 0, "connects or timeouts in a row after which a host is not asked again (default 5)")
	fs.IntVar(&p.maxhr, "max-host-error", 0, "as -maxhr")
	fs.DurationVar(&p.delay, "delay", 0, "time between requests to targets: a pace of one request per DELAY over all hosts (as -rate 1/DELAY)")
}

// asSet reads the matchers and filters, so that a mistake is a usage
// error before anything is sent.
func (p *probeFlags) asSet() (*probefilter.Set, error) {
	var s probefilter.Set
	var err error
	rng := func(flagName, v string, into *[]probefilter.Range) {
		if err != nil || v == "" {
			return
		}
		*into, err = probefilter.ParseRanges("-"+flagName, v)
	}
	rng("mc", p.mc, &s.MatchStatus)
	rng("fc", p.fc, &s.FilterStatus)
	rng("ml", p.ml, &s.MatchLength)
	rng("fl", p.fl, &s.FilterLength)
	rng("mlc", p.mlc, &s.MatchLines)
	rng("flc", p.flc, &s.FilterLines)
	rng("mwc", p.mwc, &s.MatchWords)
	rng("fwc", p.fwc, &s.FilterWords)
	if err != nil {
		return nil, err
	}
	s.MatchFavicon, s.FilterFavicon = splitList(p.mfc), splitList(p.ffc)
	s.MatchString, s.FilterString = splitList(p.ms), splitList(p.fs)
	s.MatchCDN, s.FilterCDN = splitList(strings.ToLower(p.mcdn)), splitList(strings.ToLower(p.fcdn))
	if s.MatchRegex, err = probefilter.Regexes("-mr", p.mr); err != nil {
		return nil, err
	}
	if s.FilterRegex, err = probefilter.Regexes("-fe", p.fe); err != nil {
		return nil, err
	}
	if p.mrt != "" {
		if s.MatchTime, err = probefilter.ParseTime("-mrt", p.mrt); err != nil {
			return nil, err
		}
	}
	if p.frt != "" {
		if s.FilterTime, err = probefilter.ParseTime("-frt", p.frt); err != nil {
			return nil, err
		}
	}
	if p.mdc != "" {
		if s.MatchExpr, err = probefilter.Compile("-mdc", p.mdc); err != nil {
			return nil, err
		}
	}
	if p.fdc != "" {
		if s.FilterExpr, err = probefilter.Compile("-fdc", p.fdc); err != nil {
			return nil, err
		}
	}
	return &s, nil
}

// spec turns the flags into what azhaq-http is asked.
func (p *probeFlags) spec(set *probefilter.Set, favicon bool) (*httpcol.Spec, error) {
	sp := &httpcol.Spec{
		Follow: p.follow, SameHost: p.sameHost, NoFallback: p.noFallback, SNI: p.sni,
		Retries: p.retries, TimeoutMS: p.reqTimeout.Milliseconds(),
		TLS: p.tlsGrab || p.tlsProbe, TLSProbe: p.tlsProbe, CSPProbe: p.cspProbe, EFQDN: p.efqdn, JARM: p.jarm, HTTP2: p.http2, Pipeline: p.pipeline, VHost: p.vhost,
		Preview: p.preview, NoDecode: p.noDecode, AllIPs: p.probeAllIPs,
		MinTLS10: true, CPE: p.cpe, WP: p.wp, KB: p.kb || p.fpt != "" || p.fep,
		Proxy: p.proxy, RespectHSTS: p.rhsts, AutoReferer: p.autoReferer, RandomAgent: p.random,
		ReadLimit: p.rstr, MaxHostErrs: p.maxhr,
	}
	if p.follow {
		sp.MaxRedirects = p.maxRedirects
	}
	if p.ports != "" {
		ports, err := httpcol.ParsePorts(p.ports)
		if err != nil {
			return nil, usagef("-p: %v", err)
		}
		sp.Ports = ports
	}
	if p.paths != "" {
		paths, err := pathList(p.paths)
		if err != nil {
			return nil, err
		}
		sp.Paths = paths
	}
	if p.hash != "" {
		for _, h := range splitList(strings.ToLower(p.hash)) {
			ok := false
			for _, k := range httpcol.HashKinds {
				ok = ok || k == h
			}
			if !ok {
				return nil, usagef("-hash: %q is not one of %s", h, strings.Join(httpcol.HashKinds, ", "))
			}
			sp.Hashes = append(sp.Hashes, h)
		}
	}
	if s := strings.ToLower(p.strip); s != "" && s != "html" && s != "xml" {
		return nil, usagef("-strip: want html or xml, got %q", p.strip)
	}
	for _, pre := range splitList(strings.ToLower(p.extractPreset)) {
		re, ok := httpcol.ExtractPresets[pre]
		if !ok {
			return nil, usagef("-ep: %q is not one of url, ipv4, mail", pre)
		}
		sp.Extract = append(sp.Extract, httpcol.Extract{Name: pre, Pattern: re})
	}
	for _, re := range p.extractRe {
		if _, err := regexp.Compile(re); err != nil {
			return nil, usagef("-er: %v", err)
		}
		sp.Extract = append(sp.Extract, httpcol.Extract{Name: re, Pattern: re})
	}
	if p.preview < 0 {
		return nil, usagef("-bp wants a number of characters")
	}
	switch strings.ToLower(p.methods) {
	case "":
	case "all":
		sp.Methods = []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT"}
	default:
		for _, m := range splitList(p.methods) {
			sp.Methods = append(sp.Methods, strings.ToUpper(m))
		}
	}
	sp.Body = p.body
	if p.body != "" && len(sp.Methods) == 0 {
		return nil, usagef("-body goes with the methods of -x (POST, PUT, …)")
	}
	if p.rawFile != "" {
		data, err := os.ReadFile(p.rawFile)
		if err != nil {
			return nil, usagef("-rr: %v", err)
		}
		rr, err := httpcol.ParseRawRequest(data)
		if err != nil {
			return nil, usagef("-rr %s: %v", p.rawFile, err)
		}
		sp.Raw = rr
	}
	for _, e := range splitList(p.exclude) {
		switch strings.ToLower(e) {
		case "cdn", "private-ips":
			sp.Exclude = append(sp.Exclude, strings.ToLower(e))
		default:
			if n, err := parsePortNumber(e); err == nil {
				sp.ExcludePorts = append(sp.ExcludePorts, n)
			} else if _, err := netip.ParseAddr(e); err == nil {
				sp.ExcludeNets = append(sp.ExcludeNets, e)
			} else if _, err := netip.ParsePrefix(e); err == nil {
				sp.ExcludeNets = append(sp.ExcludeNets, e)
			} else {
				sp.ExcludeRe = append(sp.ExcludeRe, e)
			}
		}
	}
	sp.Evidence = set.NeedsRaw() || p.debug || p.debugReq || p.debugResp || p.irh || p.irr || p.irrb || p.includeChain || p.sr || p.storeChain
	return sp, nil
}

// probeFields are the fields -json rows can hold.
var probeFields = []string{"timestamp", "url", "input", "host", "host_ip", "port", "scheme", "path", "method", "a", "aaaa", "cname", "resolvers", "status_code", "content_length", "content_type", "location", "title", "webserver", "tech", "words", "lines", "time", "final_url", "chain_status_codes", "chain", "favicon", "favicon_md5", "favicon_path", "favicon_url", "cdn", "cdn_name", "cdn_type", "asn", "tls", "csp", "hash", "jarm_hash", "body_preview", "body", "header", "raw_header", "request", "extracts", "body_fqdn", "body_domains", "sni", "websocket", "http2", "pipeline", "vhost", "cpe", "wordpress", "knowledgebase", "stored_response_path", "screenshot_path", "failed", "error"}

func parsePortNumber(s string) (int, error) {
	var n int
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil || fmt.Sprint(n) != s || n < 1 || n > 65535 {
		return 0, fmt.Errorf("not a port")
	}
	return n, nil
}

// pathList reads -path: a path, a comma list, or a file of paths.
func pathList(v string) ([]string, error) {
	if st, err := os.Stat(v); err == nil && !st.IsDir() {
		lines, err := loadLines(v)
		if err != nil {
			return nil, err
		}
		return lines, nil
	}
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil, usagef("-path wants a path, a comma-separated list or a file")
	}
	return out, nil
}

// matchFlagsGiven lists the matcher and filter flags given, for the summary.
func matchFlagsGiven(fs *flag.FlagSet) []string {
	var out []string
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "mc", "fc", "ml", "fl", "mlc", "flc", "mwc", "fwc", "mfc", "ffc", "ms", "fs", "mr", "fe", "mcdn", "fcdn", "mrt", "frt", "mdc", "fdc", "fd",
			"match-code", "filter-code", "match-length", "filter-length", "match-string", "filter-string", "match-regex", "filter-regex", "match-condition", "filter-condition":
			out = append(out, "-"+f.Name)
		}
	})
	return out
}

func probeDir(dir string) string {
	if dir == "" {
		dir = "output"
	}
	return filepath.Clean(dir)
}

// cmdProbe is httpx: one line per web service, as each answers.
func cmdProbe(args []string) error {
	fs := newFlags("probe")
	var c common
	c.register(fs)
	fs.BoolVar(&c.json, "j", false, "JSONL output (as -json)")
	var urls stringsFlag
	fs.Var(&urls, "u", "target: URL, host, host:port, IP, address range or AS number (repeatable, or comma-separated)")
	fs.Var(&urls, "target", "target (as -u)")
	list := fs.String("l", "", "file of targets (- for stdin; a glob such as 'hosts-*.txt')")
	var pf probeFlags
	pf.register(fs)
	rl := fs.Float64("rl", 0, "services asked per second, as httpx -rl: each target's first request waits its turn, its favicon, redirects and second scheme do not (-rate paces every request)")
	fs.Var(fs.Lookup("rl").Value, "rate-limit", "same as -rl")
	rlm := fs.Float64("rlm", 0, "services asked per minute (as -rl, per minute)")
	fs.Bool("nc", false, "accepted, as httpx has it: azhaq prints no color")
	given := inherit(fs, append([]string{"parallel", "t=parallel", "host-parallel", "no-follow", "no-tech", "resolvers", "dns-rate", "max-ips"}, targetFlags...)...)
	favicon := fs.Bool("favicon", false, "also hash each front page's favicon (one or two more requests per service)")
	if err := parse(fs, args); err != nil {
		return err
	}
	if pf.lof {
		for _, f := range probeFields {
			fmt.Println(f)
		}
		return nil
	}
	if pf.ss {
		pf.sr = true
	}
	if pf.sameHost {
		pf.follow = true // httpx: -fhr alone follows the redirects that stay on the host
	}
	if pf.csvo != "" {
		switch strings.ToLower(pf.csvo) {
		case "utf-8", "utf8":
			pf.csv = true
		default:
			return usagef("-csvo: want utf-8, got %q", pf.csvo)
		}
	}
	if pf.follow && hasFlag(args, "no-follow") {
		return usagef("-fr follows redirects and -no-follow does not: give one")
	}
	set, err := pf.asSet()
	if err != nil {
		return usageErr{err}
	}
	if pf.kb || pf.fpt != "" || pf.fep {
		if err := pagekind.Check(); err != nil {
			return usagef("-kb, -fpt and -fep: %v", err)
		}
	}
	if pf.cff != "" {
		if err := fingerprint.UseFile(pf.cff); err != nil {
			return usagef("-cff: %v", err)
		}
	}
	if pf.delay < 0 {
		return usagef("-delay wants a time such as 200ms")
	}
	if pf.csv && c.json || pf.md && c.json || pf.csv && pf.md {
		return usagef("give one of -json, -csv and -md")
	}
	needFavicon := *favicon || len(set.MatchFavicon)+len(set.FilterFavicon) > 0
	spec, err := pf.spec(set, needFavicon)
	if err != nil {
		return err
	}
	rep := newReport("probe")
	rep.what = "web services"
	maxIPs := 4096
	if v := fs.Lookup("max-ips"); v != nil && v.Value.String() != "" {
		fmt.Sscanf(v.Value.String(), "%d", &maxIPs)
	}
	if len(urls) == 0 && *list == "" && (pf.noStdin || !stdinPiped()) {
		return usagef("give -u TARGET, -l FILE or targets on stdin")
	}
	targets, perHost, err := probeInputs(urls, *list, &pf, spec.Ports, maxIPs, rep)
	if err != nil {
		return err
	}
	spec.PerHost = perHost
	for _, t := range targets {
		for _, l := range t.lines {
			if !strings.ContainsAny(l, ":/") && net.ParseIP(l) == nil {
				spec.Bare = append(spec.Bare, strings.ToLower(strings.TrimSuffix(l, ".")))
			}
		}
	}
	spec.TargetRate = *rl
	if *rlm > 0 && *rl == 0 {
		spec.TargetRate = *rlm / 60
	}
	if len(targets) == 0 {
		return usagef("give -u TARGET, -l FILE or targets on stdin")
	}
	var lines []string
	for _, t := range targets {
		lines = append(lines, t.lines...)
	}
	path, rm, err := tempList(lines)
	if err != nil {
		return err
	}
	defer rm()
	w, err := newWriter(&c)
	if err != nil {
		return err
	}
	out := &probeOut{w: w, c: &c, pf: &pf, set: set, spec: spec, cdn: map[string][2]string{}, cnames: map[string][]string{},
		seen: map[string]bool{}, shots: map[string]map[string]any{}, input: map[string][]string{}, answered: map[string]bool{}, sent: map[string]int{}}
	out.displays = pf.displayed()
	// httpx's input field is the line as given, not the URL it became.
	probeSeeding = true
	for _, t := range targets {
		out.order = append(out.order, t.given)
		for _, l := range t.lines {
			if s, err := listSeed(l); err == nil {
				if k := normalize.Seed(s).Key(); !slices.Contains(out.input[k], t.given) {
					out.input[k] = append(out.input[k], t.given)
				}
			}
		}
	}
	probeSeeding = false
	if pf.sr || pf.storeChain {
		if out.store, err = newRespStore(probeDir(pf.srd)); err != nil {
			return err
		}
		defer out.store.close()
	}
	if pf.oa != "" {
		for _, f := range []struct{ ext, format string }{{"", "text"}, {".json", "json"}, {".csv", "csv"}, {".md", "md"}} {
			fh, err := os.Create(pf.oa + f.ext)
			if err != nil {
				return err
			}
			defer fh.Close()
			switch f.format {
			case "csv":
				fmt.Fprintln(fh, csvHeader())
			case "md":
				fmt.Fprintln(fh, mdHeader())
			}
			out.extra = append(out.extra, rowSink{w: fh, format: f.format})
		}
	}
	switch {
	case pf.csv:
		if strings.EqualFold(pf.csvo, "utf-8") || strings.EqualFold(pf.csvo, "utf8") {
			w.line("\ufeff" + csvHeader())
		} else {
			w.line(csvHeader())
		}
	case pf.md:
		w.line(mdHeader())
	}
	run := []string{"-list", path, "-probe", "-probe-opts", specJSON(spec)}
	if pf.ss {
		run = append(run, "-screenshots", filepath.Join(probeDir(pf.srd), "screenshot"))
	}
	run = append(run, given()...)
	if pf.delay > 0 && !hasFlag(args, "rate", "rl", "rlm") {
		run = append(run, fmt.Sprintf("-rate=%g", 1/pf.delay.Seconds()))
	}
	if !needFavicon {
		run = append(run, "-no-favicon")
	}
	st, done, err := runPreset(&c, run, rep, out.see)
	if err != nil {
		return err
	}
	defer done()
	out.flushHeld()
	out.settle(rep, st, fs)
	if err := w.close(); err != nil {
		return err
	}
	// A target with no answer is said even under -silent: nothing printed for it.
	return rep.finish(c.json, c.silent && rep.Counts["without an answer"] == 0)
}

func specJSON(sp *httpcol.Spec) string {
	raw, _ := json.Marshal(sp)
	return string(raw)
}

// settle ends the run: every target given ends as a row, a failure or a
// skip, so one that has none is a row marked failed, and what the flags
// left out or sent is said.
func (o *probeOut) settle(rep *report, st *store.Store, fs *flag.FlagSet) {
	ents, _ := st.Entities()
	obs, _ := st.Observations()
	failed := map[string]string{} // entity key → why
	for _, f := range engine.FailedTargets(ents, obs) {
		if f.Collector == "azhaq-http" || f.Collector == "azhaq-dns" {
			if _, ok := failed[f.Target]; !ok {
				failed[f.Target] = f.Error
			}
		}
	}
	dnsErr := map[string]string{}
	wild := 0
	for _, ob := range obs {
		if ob.Collector != "azhaq-dns" {
			continue
		}
		m := payloadOf(ob.Observation)
		host, _ := m["fqdn"].(string)
		if w, _ := m["wildcard"].(bool); w {
			wild++
		}
		e, _ := m["error"].(string)
		if e == "" {
			switch r, _ := m["result"].(string); r {
			case "nodata":
				e = "the name has no address (no A or AAAA record)"
			case "reserved":
				e = "a special-use name (.invalid, .test, .local) the system resolver and /etc/hosts do not know"
			}
		}
		if e == "nxdomain" {
			e = "no such host"
		}
		if e != "" {
			dnsErr[host] = e
		}
	}
	skipped := map[string]string{}
	for _, sk := range rep.Skipped {
		skipped[sk.Target] = sk.Reason
	}
	keys := map[string][]string{}
	for key, ins := range o.input {
		for _, in := range ins {
			keys[in] = append(keys[in], key)
		}
	}
	accounted := map[string]bool{}
	for _, f := range rep.Failed {
		for _, t := range f.Targets {
			accounted[normalize.HostFromURL(t)], accounted[t] = true, true
		}
	}
	for _, sk := range rep.Skipped {
		accounted[normalize.HostFromURL(sk.Target)], accounted[sk.Target] = true, true
	}
	// A name a certificate or a policy led to is a target too.
	inOrder := map[string]bool{}
	for _, in := range o.order {
		inOrder[in] = true
		inOrder[normalize.HostFromURL(in)] = true // its name is not a target of its own
	}
	order := append([]string(nil), o.order...)
	var found []string
	for h := range dnsErr {
		if !inOrder[h] && !o.answered[h] {
			found = append(found, h)
		}
	}
	sort.Strings(found)
	order = append(order, found...)
	var gaps []string
	noAnswer, notAsked := 0, 0
	for _, in := range order {
		if o.answered[in] {
			continue
		}
		why := ""
		for _, k := range keys[in] {
			if why == "" {
				why = failed[k]
			}
			if why == "" {
				why = dnsErr[normalize.HostFromURL(k)]
			}
			if why == "" {
				why = skipped[k]
			}
		}
		if why == "" {
			why = dnsErr[in]
		}
		if why == "" && rep.Stopped != "" {
			notAsked++ // the run stopped before it came to this target: azhaq resume asks it
			continue
		}
		if why == "" {
			why = "no answer"
			if !accounted[in] && !accounted[normalize.HostFromURL(in)] {
				gaps = append(gaps, in)
			}
		}
		if why == "outside the scope" {
			continue // not sent by choice: the summary's skipped list names it, as no failure
		}
		o.failedRow(in, why)
		noAnswer++
	}
	if len(gaps) > 0 {
		rep.Failed = append(rep.Failed, engine.Failure{Collector: "azhaq-http", Error: "no answer and no failure recorded", Retryable: true, Count: len(gaps), Targets: gaps})
	}
	if noAnswer > 0 {
		rep.Counts = map[string]int{"without an answer": noAnswer}
	}
	if notAsked > 0 {
		if rep.Counts == nil {
			rep.Counts = map[string]int{}
		}
		rep.Counts["not asked yet"] = notAsked
	}
	if quiet := silentHosts(st); len(quiet) > 0 {
		if rep.Counts == nil {
			rep.Counts = map[string]int{}
		}
		rep.Counts["hosts without a web service"] = len(quiet)
	}
	rep.Results = o.w.count() // the lines printed, a failed row's among them when it is printed
	if o.pf.csv || o.pf.md {
		rep.Results-- // the header
	}
	if given := matchFlagsGiven(fs); len(given) > 0 {
		note := fmt.Sprintf("%s left out %d answers that did not match", strings.Join(given, " "), o.dropped)
		if o.condErrs > 0 {
			note += fmt.Sprintf("; %d could not be judged: %v", o.condErrs, o.condErr)
		}
		rep.Notes = append(rep.Notes, note)
	}
	if wild > 0 {
		rep.Notes = append(rep.Notes, fmt.Sprintf("%s resolve only through a wildcard answer: probed as given, not dropped", plural(wild, "name")))
	}
	if o.cut > 0 {
		rep.Notes = append(rep.Notes, fmt.Sprintf("%d redirects were not followed: they leave the site or the scope, or -maxr was reached", o.cut))
	}
	if len(o.sent) > 0 || o.spec.Raw != nil || o.spec.Body != "" {
		var parts []string
		for m, n := range o.sent {
			if m != "GET" {
				parts = append(parts, fmt.Sprintf("%s %d", m, n))
			}
		}
		sort.Strings(parts)
		rep.Notes = append(rep.Notes, "requests other than GET were sent to the targets ("+strings.Join(parts, ", ")+"): they can change data on a target")
	}
}
