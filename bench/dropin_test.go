package main

import "testing"

// The routes only the full map reaches are all in the truth (a misspelt
// one would quietly raise the bar), and what is left is what a crawler's
// check counts.
func TestCrawlTruthSplit(t *testing.T) {
	truth := readTruth("truth/juice-shop-v20.3.0-routes.txt")
	mapOnly := readTruth("truth/juice-shop-v20.3.0-full-map-only.txt")
	for r := range mapOnly {
		if !truth[r] {
			t.Errorf("%s is listed as reached only by the full map, and is no known route", r)
		}
	}
	rest, only := splitTruth(truth, mapOnly)
	if len(only) != len(mapOnly) || len(rest)+len(only) != len(truth) || len(rest) == 0 {
		t.Errorf("%d known routes split into %d and %d (map only: %d)", len(truth), len(rest), len(only), len(mapOnly))
	}
	for r := range only {
		if rest[r] {
			t.Errorf("%s is on both sides", r)
		}
	}
}
