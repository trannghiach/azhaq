package main

import (
	"slices"
	"testing"
)

// A URL gau lists that azhaq's -raw output holds as junk is accounted
// for, with its reason; one azhaq never saw is missing.
func TestJunkOf(t *testing.T) {
	raw := []byte(`http://testphp.vulnweb.com/index.php
http://testphp.vulnweb.com/7zSo1DIz.exe
http://testphp.vulnweb.com/cart.php.[
http://testphp.vulnweb.com/page.php?id=NaN
http://example.org/7zSo1DIz.exe
http://testphp.vulnweb.com/logo.png
`)
	gauOnly := []string{
		"http://testphp.vulnweb.com/7zSo1DIz.exe",
		"http://testphp.vulnweb.com/never-seen.php",
	}
	all, junk, missing := junkOf(raw, "vulnweb.com", gauOnly)
	if len(all) == 0 {
		t.Fatal("no junk found in the raw output")
	}
	if _, ok := all["http://example.org/7zSo1DIz.exe"]; ok {
		t.Error("a URL off the domain is counted as junk")
	}
	if _, ok := all["http://testphp.vulnweb.com/index.php"]; ok {
		t.Error("a good URL is counted as junk")
	}
	if junk["http://testphp.vulnweb.com/7zSo1DIz.exe"] == "" || len(junk) != 1 {
		t.Errorf("gau's junk: %v", junk)
	}
	if !slices.Equal(missing, []string{"http://testphp.vulnweb.com/never-seen.php"}) {
		t.Errorf("missing: %v", missing)
	}
	by := reasonCounts(all)
	n := 0
	for _, c := range by {
		n += c
	}
	if n != len(all) || reasonList(map[string]int{}) != "none" {
		t.Errorf("reason counts %v for %d URLs", by, len(all))
	}
}
