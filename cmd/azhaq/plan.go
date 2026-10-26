package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
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
}

type planTarget struct {
	Type       types.SeedType `json:"type"`
	Key        string         `json:"key"`
	Collectors []string       `json:"collectors"`
}

func buildPlan(cat *catalog.Catalog, seeds []types.Seed, b engine.Budgets, paths []string, limits map[string]string, rep *report) runPlan {
	p := runPlan{Collectors: map[string]string{}, Limits: limits, Skipped: rep.Skipped}
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
			p.Collectors[item.Collector] = collectorRole(catalog.InfoOf(col).Kind)
		}
		p.Targets = append(p.Targets, t)
	}
	for f, on := range b.Active {
		if on {
			p.Active = append(p.Active, "-"+f)
		}
	}
	sort.Strings(p.Active)
	if _, ok := p.Collectors["azhaq-paths"]; ok {
		p.Paths = paths
	}
	p.Sends = []string{"GET requests only, to the targets and what they lead to inside the scope"}
	if !b.AllGets {
		p.Sends = append(p.Sends, "found URLs that look like a GET would change something (logout, delete, save, reset…) are listed, not requested (-all-gets to request them)")
	}
	if b.Passive {
		p.Sends = []string{"nothing to the targets (-passive): third-party sources and DNS only"}
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
	return nil
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
