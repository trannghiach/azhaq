package main

import (
	"strings"
	"testing"
)

func TestCrawlFields(t *testing.T) {
	f := urlFields("https://www.example.co.uk/a/b/page.php?x=1&y=2")
	want := map[string]string{
		"url": "https://www.example.co.uk/a/b/page.php?x=1&y=2", "path": "/a/b/page.php", "fqdn": "www.example.co.uk",
		"rdn": "example.co.uk", "rurl": "https://www.example.co.uk", "qpath": "/a/b/page.php?x=1&y=2",
		"file": "page.php", "dir": "/a/b/", "udir": "https://www.example.co.uk/a/b/", "key": "x", "kv": "x=1", "value": "1",
	}
	for k, v := range want {
		if len(f[k]) == 0 || f[k][0] != v {
			t.Errorf("%s = %v, want %s", k, f[k], v)
		}
	}
	if len(f["key"]) != 2 {
		t.Errorf("keys %v", f["key"])
	}
	if g := urlFields("http://h/"); len(g["file"])+len(g["dir"])+len(g["key"]) != 0 {
		t.Errorf("a bare root has no file, dir or key: %v", g)
	}
}

func TestCrawlOutputFilters(t *testing.T) {
	keep := func(o crawlOpts, json bool, u string) bool {
		return (&crawlOutput{o: o, json: json}).keep(u)
	}
	def, _ := crawlOutOpts(false, "", "", "", "", "", "", false, "", "", false)
	if keep(def, false, "http://h/a.png") || keep(def, false, "http://h/robots.txt") {
		t.Error("the default list leaves out images and .txt")
	}
	if !keep(def, false, "http://h/a.php") || !keep(def, false, "http://h/a") {
		t.Error("pages stay")
	}
	if !keep(def, true, "http://h/robots.txt") {
		t.Error("-json lists the map's rows as they are")
	}
	em, _ := crawlOutOpts(false, "", "", "", "", "php,none", "", false, "", "", false)
	if !keep(em, false, "http://h/a.php") || !keep(em, false, "http://h/a") || keep(em, false, "http://h/a.html") {
		t.Error("-em php,none")
	}
	nd, _ := crawlOutOpts(false, "", "", "", "", "", "php", true, "", "", false)
	if !keep(nd, false, "http://h/a.png") || keep(nd, false, "http://h/a.php") {
		t.Error("-ndef -ef php")
	}
	re, _ := crawlOutOpts(false, "", "", "", "", "", "", false, `/api/`, `/api/v2`, false)
	if !keep(re, false, "http://h/api/v1/x") || keep(re, false, "http://h/api/v2/x") || keep(re, false, "http://h/x") {
		t.Error("-mr and -fr")
	}
	if _, err := crawlOutOpts(false, "nope", "", "", "", "", "", false, "", "", false); err == nil || !strings.Contains(err.Error(), "-f") {
		t.Errorf("a bad field is a usage error: %v", err)
	}
	if _, err := crawlOutOpts(false, "", "", "", "{{bad}}", "", "", false, "", "", false); err == nil {
		t.Error("a bad template field is a usage error")
	}
}

func TestCrawlTarget(t *testing.T) {
	for in, want := range map[string]string{
		"example.com":        "https://example.com/",
		"10.0.0.1:8080":      "http://10.0.0.1:8080/",
		"10.0.0.1:80/app":    "http://10.0.0.1:80/app",
		"host:8443":          "https://host:8443/",
		"http://h:3001/x":    "http://h:3001/x",
		"https://example.io": "https://example.io",
	} {
		if got := crawlTarget(in); got != want {
			t.Errorf("%s: %s, want %s", in, got, want)
		}
	}
}
