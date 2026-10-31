package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strings"

	"github.com/trannghiach/azhaq/internal/normalize"
	"github.com/trannghiach/azhaq/internal/scopefile"
	"github.com/trannghiach/azhaq/scope"
	"github.com/trannghiach/azhaq/types"
)

// loadScope reads a scope file, or fetches a platform's program list.
func loadScope(spec, program string) (scopefile.Scope, error) {
	var data []byte
	var err error
	if _, ok := scopefile.Platforms[spec]; ok {
		if program == "" {
			return scopefile.Scope{}, fmt.Errorf("-scope %s needs -program", spec)
		}
		data, err = scopefile.Fetch(context.Background(), spec)
	} else {
		data, err = os.ReadFile(spec)
	}
	if err != nil {
		return scopefile.Scope{}, err
	}
	return scopefile.Parse(data, program)
}

// scopeSeeds starts a run from a scope: wildcards are enumerated as
// domains, everything else is probed as given.
func scopeSeeds(sc scopefile.Scope) ([]types.Seed, error) {
	var seeds []types.Seed
	for _, d := range sc.Domains {
		seeds = append(seeds, types.Seed{Type: types.TypeDomain, Keys: map[string]string{"domain": d}})
	}
	for _, t := range sc.Targets {
		s, err := listSeed(t)
		if err != nil {
			return nil, fmt.Errorf("scope target %q: %w", t, err)
		}
		seeds = append(seeds, s)
	}
	return seeds, nil
}

// cmdScope prints what a run would take from a scope.
func cmdScope(args []string) error {
	fs := newFlags("scope")
	spec := fs.String("scope", "", "a file or hackerone, bugcrowd, intigriti, yeswehack")
	program := fs.String("program", "", "the program to take from a list")
	asJSON := fs.Bool("json", false, "one JSON object: program, allow, deny, domains, targets, skipped")
	if err := parse(fs, args); err != nil {
		return err
	}
	if *spec == "" {
		return usagef("give -scope FILE or a platform (hackerone, bugcrowd, intigriti, yeswehack) with -program")
	}
	sc, err := loadScope(*spec, *program)
	if err != nil {
		return err
	}
	if *asJSON {
		return json.NewEncoder(os.Stdout).Encode(sc)
	}
	name := sc.Program
	if name == "" {
		name = *spec
	}
	fmt.Printf("%s: %d rules in, %d out; %d domains to enumerate, %d targets to probe as given; %d entries a run cannot use\n",
		name, len(sc.Allow), len(sc.Deny), len(sc.Domains), len(sc.Targets), len(sc.Skipped))
	for _, r := range sc.Allow {
		fmt.Printf("  in    %s\n", r)
	}
	for _, r := range sc.Deny {
		fmt.Printf("  out   %s\n", r)
	}
	for _, r := range sc.Skipped {
		fmt.Printf("  skip  %s\n", r)
	}
	return nil
}

// seedOutsideRange is a range seed that no address of can pass the scope.
func seedOutsideRange(rules scope.Rules, s types.Seed) bool {
	s = normalize.Seed(s)
	if s.Type != types.TypePrefix {
		return false
	}
	pf, err := netip.ParsePrefix(s.Key())
	return err == nil && !rules.AllowsPrefix(pf)
}

// outsideScope is the usage error of a run whose every target is outside
// the scope: it names them (the blocks of a range as the range), and nothing
// was sent.
func outsideScope(targets []string) error {
	if len(targets) == 0 {
		return usagef("every target is outside the scope (0 left out)")
	}
	var v4 []ipRange
	var names []string
	for _, t := range targets {
		pf, err := netip.ParsePrefix(t)
		if err != nil || !pf.Addr().Is4() {
			names = append(names, t)
			continue
		}
		pf = pf.Masked()
		lo := binary.BigEndian.Uint32(pf.Addr().AsSlice())
		v4 = append(v4, ipRange{lo, lo + uint32(uint64(1)<<(32-pf.Bits())-1)})
	}
	for _, pf := range cover(v4) {
		names = append(names, strings.TrimSuffix(pf.String(), "/32"))
	}
	for i, n := range names {
		names[i] = strings.TrimSuffix(n, "/128")
	}
	slices.Sort(names)
	shown := names
	if len(shown) > 5 {
		shown = shown[:5]
	}
	list := strings.Join(shown, ", ")
	if len(names) > len(shown) {
		list += fmt.Sprintf(" and %d more", len(names)-len(shown))
	}
	return usagef("every target is outside the scope (%d left out): %s; check -allow, -deny and -scope", len(names), list)
}
