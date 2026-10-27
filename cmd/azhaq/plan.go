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

// sendLimits are the options that bound what a run sends to its targets.
type sendLimits struct {
	max          int64  // requests at most; 0: no cap
	by           string // the option that set max
	noFavicon    bool
	chrome       bool // -browser or -screenshots
	chromeWrites bool // -browser-writes
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
	p.Sends = []string{"GET requests only, to the targets and what they lead to inside the scope"}
	if !b.AllGets {
		p.Sends = append(p.Sends, "found URLs that look like a GET would change something (logout, delete, save, reset…) are listed, not requested (-all-gets to request them)")
	}
	switch {
	case send.chrome && send.chromeWrites:
		p.Sends = append(p.Sends, "Chrome lets pages send their writes (-browser-writes): the POST, PUT and DELETE their scripts send change data on the target")
	case send.chrome:
		p.Sends = append(p.Sends, "Chrome sends GET, HEAD and OPTIONS only, except signing in: the writes pages would send are mapped and listed, not sent (-browser-writes to send them)")
	}
	if b.Passive {
		p.Sends = []string{"nothing to the targets (-passive): third-party sources and DNS only"}
		p.Requests.Passive = true
		return p
	}
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
		fmt.Printf("built-in paths asked on each web service (%d): %s\n", len(p.Paths), strings.Join(p.Paths, " "))
	}
	active := "none"
	if len(p.Active) > 0 {
		active = strings.Join(p.Active, " ")
	}
	fmt.Printf("active techniques: %s\n", active)
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
