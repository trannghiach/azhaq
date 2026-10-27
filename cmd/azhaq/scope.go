package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/trannghiach/azhaq/internal/scopefile"
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
