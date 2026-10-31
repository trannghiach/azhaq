package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"maps"
	"os"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/trannghiach/azhaq/catalog"
	"github.com/trannghiach/azhaq/engine"
	"github.com/trannghiach/azhaq/internal/collectors/portcol"
	"github.com/trannghiach/azhaq/internal/portscan"
	"github.com/trannghiach/azhaq/types"
)

// cmdPlan is a run that stops before sending anything: what it would
// take, leave out, run and send.
func cmdPlan(args []string) error {
	fs := newFlags("plan")
	var names []string
	runFlags().VisitAll(func(f *flag.Flag) {
		if !strings.HasPrefix(f.Usage, "internal:") {
			names = append(names, f.Name)
		}
	})
	given := inherit(fs, names...)
	if err := parse(fs, args); err != nil {
		return err
	}
	rep := newReport("plan")
	out := runOut{embedded: true, plan: true}
	if err := mapTarget(given(), rep, &out); err != nil {
		return err
	}
	return rep.finish(out.json, false)
}

// runPlan is what a run would do, as plan prints it.
type runPlan struct {
	Targets    []planTarget      `json:"targets"`
	Skipped    []engine.Skip     `json:"skipped,omitempty"`
	Collectors map[string]string `json:"collectors"` // name → what it does to whom
	Active     []string          `json:"active"`
	Paths      []string          `json:"builtin_paths,omitempty"`
	Limits     map[string]string `json:"limits"`
	Sends      []string          `json:"sends"`
	Requests   planRequests      `json:"requests"`
}

type planTarget struct {
	Type       types.SeedType `json:"type"`
	Key        string         `json:"key"`
	Collectors []string       `json:"collectors"`
}

// planRequests is what is known of a run's requests before it sends any.
// The queries to third-party sources about the targets listed are known
// exactly. The requests to the targets are not: they follow from the
// names that resolve and what their pages lead to, so the plan gives
// what each web service costs before that, and the cap on them all.
type planRequests struct {
	Sources    map[string]int `json:"source_queries"` // collector → queries about the targets listed
	Total      int            `json:"source_queries_total"`
	NotCounted []string       `json:"source_queries_not_counted,omitempty"` // passive collectors that cannot say before they run
	Found      bool           `json:"found_domains_asked"`                  // domains found on the way are asked about too
	Passive    bool           `json:"passive,omitempty"`                    // none go to the targets
	PerService int            `json:"per_web_service,omitempty"`            // about: its page, the favicon, the built-in paths
	MaxNames   int            `json:"max_names,omitempty"`                  // names found under the domains looked up at most
	Cap        int64          `json:"cap"`                                  // requests to the targets at most; 0: no cap
	CapBy      string         `json:"cap_by,omitempty"`
	scoped     bool
}

// sendLimits are the options that bound or change what a run sends to its
// targets.
type sendLimits struct {
	max          int64  // requests at most; 0: no cap
	by           string // the option that set max
	noFavicon    bool
	chrome       bool // -browser or -screenshots
	chromeWrites bool // -browser-writes
	interact     bool // -interact
	login        string
	loginUser    string
	graphql      bool
	submitForms  bool
	dirs         bool
	params       bool
	paramsBody   string // POST, JSON or XML when -params sends names in a body
	tcpPorts     int    // ports asked on each address (-ports)
	udpPorts     int    // UDP ports asked on each address (-ports-udp)
	portsOn      bool   // some hosts have ports of their own
	portDetect   portscan.Detect
	portPayload  bool
	portDiscover portcol.Discovery
}

// planSends are the lines on what a run sends besides the GET requests for
// pages, each true of the options given. gets are the techniques that send
// GET requests too; others send something else: a port scan's connects and
// the probes of what answers, UDP datagrams, POST bodies, a sign-in, DNS
// guesses.
func planSends(b engine.Budgets, send sendLimits) (gets, others []string) {
	out := &others
	if send.dirs {
		gets = append(gets, "GET requests for each word of the -dirs wordlist (and each -dirs-ext extension) under each web service")
	}
	if send.params && send.paramsBody == "" {
		gets = append(gets, "GET requests with batches of the -params wordlist as query names")
	}
	if b.Active["ports"] && send.tcpPorts > 0 {
		ports := plural(send.tcpPorts, "port") + " of each address"
		if send.portsOn {
			ports += " (a host given with a port: that port only)"
		}
		line := "TCP connects (full handshakes) to " + ports + " (-ports)"
		switch send.portDiscover {
		case portcol.DiscoverFirst:
			line += ", after a connect to 80 and 443 to tell whether the address is up (-port-discover)"
		case portcol.DiscoverOnly:
			line = "TCP connects to ports 80 and 443 of each address, to tell whether it is up (-port-discover only), and no other port"
		}
		*out = append(*out, line)
		if send.portDiscover != portcol.DiscoverOnly {
			switch send.portDetect {
			case portscan.DetectAll:
				*out = append(*out, "each open port is asked what it is, on connections of their own (-port-detect all): its banner, and for a port that says nothing its protocol's own request on its usual number, one HEAD /, a TLS handshake and one request of each of the other protocols until one answers (at most 24 more connects per port; a GET / for a web page whose head names no product)")
			case portscan.DetectBanner:
				*out = append(*out, "an open port is read for what it says first, and nothing is sent on it (-port-detect banner)")
			default:
				*out = append(*out, "an open port is closed at once (-port-detect none)")
			}
			if send.portPayload {
				*out = append(*out, "the -port-payload text is sent to each open port before it is read")
			}
		}
	}
	if b.Active["ports"] && send.udpPorts > 0 {
		*out = append(*out, fmt.Sprintf("UDP datagrams to %s of each address (-ports-udp): the harmless request of the protocol the port usually carries, and, for a port that stays silent, each other request its protocol has (a port with no known protocol: a DNS query, an SNMP get with community public, memcached's version, an empty datagram)", plural(send.udpPorts, "port")))
	}
	if send.graphql {
		*out = append(*out, "POST requests with a GraphQL introspection query to the GraphQL endpoints found (-graphql): they read the schema and change nothing")
	}
	if send.paramsBody != "" {
		*out = append(*out, fmt.Sprintf("%s requests whose body holds the parameter names guessed (-params-method %s, -params-writes): a body may change data on the target", send.paramsBody, send.paramsBody))
	}
	if send.submitForms {
		*out = append(*out, "POST requests that submit the forms the crawl finds with neutral values (-submit-forms): this changes data on the target")
	}
	if send.login != "" {
		*out = append(*out, fmt.Sprintf("Chrome signs in at %s as %s (-login): the sign-in's POST goes to the target, and the session it gets goes with every request", send.login, send.loginUser))
	}
	if send.chrome && send.interact {
		line := "Chrome clicks the buttons, links and menus of each page (-interact): every click is made, a log out link included, and the GETs it sends are requested like any other"
		if !send.chromeWrites {
			line += "; the writes it would send are refused by their method and mapped, not sent"
		}
		*out = append(*out, line)
	}
	if b.Active["dns-brute"] || b.Active["permute"] {
		var what []string
		if b.Active["dns-brute"] {
			what = append(what, "WORD.domain for each word (-dns-brute)")
		}
		if b.Active["permute"] {
			what = append(what, "variations of the names found (-permute)")
		}
		*out = append(*out, "DNS queries for "+strings.Join(what, " and ")+", to the resolvers: not requests to the targets")
	}
	return gets, others
}

func buildPlan(cat *catalog.Catalog, seeds []types.Seed, b engine.Budgets, paths []string, limits map[string]string, send sendLimits, rep *report) runPlan {
	p := runPlan{Collectors: map[string]string{}, Limits: limits, Skipped: rep.Skipped}
	p.Requests = planRequests{Sources: map[string]int{}, Cap: send.max, scoped: !b.Scope.Empty()}
	if send.max > 0 {
		p.Requests.CapBy = send.by
	}
	notCounted := map[string]bool{}
	eng := &engine.Engine{Cat: cat}
	for _, s := range engine.ExpandSeeds(seeds) {
		t := planTarget{Type: s.Type, Key: s.Key()}
		for _, item := range eng.Plan([]types.Seed{s}) {
			col, ok := cat.Get(item.Collector)
			if !ok || !b.Allows(col, s) {
				continue
			}
			if sk, ok := col.(interface{ Skip(types.Seed) bool }); ok && sk.Skip(s) {
				continue
			}
			t.Collectors = append(t.Collectors, item.Collector)
			kind := catalog.InfoOf(col).Kind
			p.Collectors[item.Collector] = collectorRole(kind)
			if kind != catalog.Passive {
				continue
			}
			if a, ok := col.(catalog.Asker); ok {
				if n := len(a.Asks(s)); n > 0 {
					p.Requests.Sources[item.Collector] += n
					p.Requests.Total += n
				}
			} else {
				notCounted[item.Collector] = true
			}
			if s.Type == types.TypeDomain {
				// Names found under another domain (a CNAME's target, a
				// link) bring their domain: the scope decides whether it
				// is asked about, and -depth and -max-items how far.
				p.Requests.Found = true
				if p.Requests.MaxNames = b.MaxNames; b.MaxNames <= 0 {
					p.Requests.MaxNames = engine.DefaultBudgets().MaxNames
				}
			}
		}
		p.Targets = append(p.Targets, t)
	}
	p.Requests.NotCounted = sortedKeys(notCounted)
	for f, on := range b.Active {
		if on {
			p.Active = append(p.Active, "-"+f)
		}
	}
	sort.Strings(p.Active)
	// What runs on each web service, given or found under a domain.
	service := types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": "https://service.invalid/"}}
	runs := func(name string) bool {
		col, ok := cat.Get(name)
		return ok && b.Allows(col, service)
	}
	if runs("azhaq-paths") {
		p.Paths = paths
	}
	gets, others := planSends(b, send)
	switch {
	case b.Passive && len(others) == 0:
		p.Sends = []string{"nothing to the targets (-passive): third-party sources and DNS only"}
		p.Requests.Passive = true
		return p
	case b.Passive:
		// The techniques below still go to the targets: -passive leaves out the pages.
		p.Sends = append([]string{"no pages are requested (-passive); only what the active techniques send goes to the targets"}, append(gets, others...)...)
		return p
	case len(others) == 0 && !send.chrome:
		p.Sends = []string{"GET requests only, to the targets and what they lead to inside the scope"}
	default:
		p.Sends = []string{"GET requests to the targets and what they lead to inside the scope"}
	}
	p.Sends = append(p.Sends, "azhaq cannot know what a GET does on the server: every URL found in scope is requested, and writes (POST, PUT, PATCH, DELETE) only with their flags")
	for _, rule := range b.Scope.DenyPath {
		p.Sends = append(p.Sends, "never requested, by any collector or Chrome: a URL whose path or query matches -deny-path "+rule)
	}
	switch {
	case send.chrome && send.chromeWrites:
		p.Sends = append(p.Sends, "Chrome lets pages send their writes (-browser-writes): the POST, PUT and DELETE their scripts send change data on the target")
	case send.chrome:
		p.Sends = append(p.Sends, "Chrome sends GET, HEAD and OPTIONS only, except signing in: the writes pages would send are mapped and listed, not sent (-browser-writes to send them)")
	}
	p.Sends = append(append(p.Sends, gets...), others...)
	if runs("azhaq-http") {
		p.Requests.PerService = 1 + len(p.Paths)
		if !send.noFavicon {
			p.Requests.PerService++
		}
	}
	return p
}

func collectorRole(k catalog.Kind) string {
	switch k {
	case catalog.Passive:
		return "asks third parties or DNS resolvers, not the target"
	case catalog.Active:
		return "active: sends many requests to the target"
	default:
		return "sends requests to the target"
	}
}

func printPlan(p runPlan, asJSON bool) error {
	if asJSON {
		return json.NewEncoder(os.Stdout).Encode(p)
	}
	if len(p.Targets) == 0 {
		fmt.Println("targets (0): nothing to do")
	}
	fmt.Printf("targets (%d)\n", len(p.Targets))
	for _, t := range p.Targets {
		fmt.Printf("  %s %s: %s\n", t.Type, t.Key, strings.Join(t.Collectors, " "))
	}
	if len(p.Skipped) > 0 {
		fmt.Printf("left out (%d)\n", len(p.Skipped))
		for _, s := range p.Skipped {
			fmt.Printf("  %s: %s\n", s.Target, s.Reason)
		}
	}
	names := make([]string, 0, len(p.Collectors))
	for n := range p.Collectors {
		names = append(names, n)
	}
	sort.Strings(names)
	fmt.Println("collectors")
	for _, n := range names {
		fmt.Printf("  %-18s %s\n", n, p.Collectors[n])
	}
	if len(p.Paths) > 0 {
		fmt.Printf("built-in path checks on each web service (%d; -no-paths turns them off): %s\n", len(p.Paths), strings.Join(p.Paths, " "))
	}
	active := "none"
	if len(p.Active) > 0 {
		active = strings.Join(p.Active, " ")
	}
	fmt.Printf("active techniques (wordlists, ports, introspection; besides the built-in path checks): %s\n", active)
	var lim []string
	for _, k := range []string{"depth", "max-items", "max-requests", "rate", "timeout", "daily-requests"} {
		lim = append(lim, k+" "+p.Limits[k])
	}
	fmt.Printf("limits: %s\n", strings.Join(lim, ", "))
	for _, s := range p.Sends {
		fmt.Printf("sends: %s\n", s)
	}
	printRequests(p)
	return nil
}

// printRequests says what is known of the requests before any is sent:
// the source queries exactly, the requests to the targets as a bound.
func printRequests(p runPlan) {
	r := p.Requests
	var by []string
	for _, n := range slices.Sorted(maps.Keys(r.Sources)) {
		by = append(by, fmt.Sprintf("%s %d", n, r.Sources[n]))
	}
	switch {
	case len(by) > 0:
		fmt.Printf("source queries: %d about the targets above (%s)\n", r.Total, strings.Join(by, ", "))
	case len(r.NotCounted) > 0:
		fmt.Println("source queries:")
	default:
		fmt.Println("source queries: none")
	}
	for _, n := range r.NotCounted {
		fmt.Printf("  %s: not counted; it does not say which sources it asks before it runs\n", n)
	}
	switch {
	case r.Found && r.scoped:
		fmt.Println("  domains found on the way are asked about too, inside the scope")
	case r.Found:
		fmt.Println("  domains found on the way are asked about too (no scope: -depth and -max-items bound them)")
	}
	if r.Passive {
		fmt.Println("requests to the targets: none (-passive)")
		return
	}
	if r.Cap > 0 {
		fmt.Printf("requests to the targets: at most %d (%s)\n", r.Cap, r.CapBy)
	} else {
		fmt.Println("requests to the targets: no cap (-max-requests sets one)")
	}
	if r.PerService > 0 {
		names := "the names that resolve and answer"
		if r.MaxNames > 0 {
			names = fmt.Sprintf("how many names resolve and answer (up to %d are looked up, -max-names)", r.MaxNames)
		}
		what := fmt.Sprintf("its page, %d built-in paths", len(p.Paths))
		if r.PerService > 1+len(p.Paths) {
			what = fmt.Sprintf("its page, the favicon, %d built-in paths", len(p.Paths))
		}
		fmt.Printf("  how many depends on %s: about %d per web service (%s), then what its pages, scripts and archived URLs lead to\n", names, r.PerService, what)
	}
	if len(p.Active) > 0 {
		fmt.Printf("  %s add their own\n", strings.Join(p.Active, " "))
	}
}

func limitsOf(b engine.Budgets, maxRequests int64, rate float64, timeout time.Duration, daily int64) map[string]string {
	none := func(ok bool, s string) string {
		if !ok {
			return "none"
		}
		return s
	}
	return map[string]string{
		"depth":          fmt.Sprint(b.MaxDepth),
		"max-items":      fmt.Sprint(b.MaxItems),
		"max-requests":   none(maxRequests > 0, fmt.Sprint(maxRequests)),
		"rate":           none(rate > 0, fmt.Sprintf("%g/s", rate)),
		"timeout":        none(timeout > 0, timeout.String()),
		"daily-requests": none(daily > 0, fmt.Sprint(daily)),
	}
}
