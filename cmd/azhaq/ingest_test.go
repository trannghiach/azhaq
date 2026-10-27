package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/trannghiach/azhaq/engine"
)

// What httpx, katana and ffuf found feeds the exports as Azhaq's own
// probe, crawl and path sweep do: web services for nuclei and Burp,
// routes, body fields and forms for the OpenAPI description.
func TestIngestFeedsExports(t *testing.T) {
	db := filepath.Join(t.TempDir(), "x.db")
	for _, f := range []string{"httpx.jsonl", "katana.jsonl", "ffuf.json"} {
		if _, _, err := captureBoth(t, func() error {
			return cmdIngest([]string{"-in", filepath.Join("..", "..", "fixtures", f), "-db", db})
		}); err != nil {
			t.Fatal(f, err)
		}
	}
	export := func(format, origin string) string {
		var b bytes.Buffer
		if err := exportAs(db, format, origin, &b); err != nil {
			t.Fatal(format, err)
		}
		return b.String()
	}

	// The httpx probe that failed is no service; katana's front page is.
	want := "https://api.example.com:8443/\nhttps://old.example.com/\nhttps://shop.example.com/\nhttps://www.example.com/\n"
	if got := export("targets", ""); got != want {
		t.Errorf("targets\n%s\nwant\n%s", got, want)
	}

	var burp struct {
		Target struct {
			Scope struct {
				Include []struct{ Protocol, Host, Port string }
			}
		}
	}
	if err := json.Unmarshal([]byte(export("burp", "")), &burp); err != nil {
		t.Fatal(err)
	}
	var hosts []string
	for _, e := range burp.Target.Scope.Include {
		hosts = append(hosts, e.Protocol+" "+e.Host+" "+e.Port)
	}
	if want := []string{`https ^api\.example\.com$ ^8443$`, `https ^old\.example\.com$ ^443$`, `https ^shop\.example\.com$ ^443$`, `https ^www\.example\.com$ ^443$`}; !slices.Equal(hosts, want) {
		t.Errorf("burp include %q", hosts)
	}

	var doc struct {
		Paths map[string]map[string]struct {
			Parameters []struct{ Name, In string }
			Body       *struct {
				Content map[string]struct {
					Schema struct{ Properties map[string]any }
				}
			} `json:"requestBody"`
			X map[string]any `json:"x-azhaq"`
		}
	}
	raw := export("openapi", "https://shop.example.com")
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatal(err)
	}
	fields := func(path, method, media string) string {
		op, ok := doc.Paths[path][method]
		if !ok || op.Body == nil {
			t.Fatalf("%s %s: no body in %s", method, path, raw)
		}
		var out []string
		for k := range op.Body.Content[media].Schema.Properties {
			out = append(out, k)
		}
		slices.Sort(out)
		return strings.Join(out, ",")
	}
	if got := fields("/rest/user/login", "post", "application/json"); got != "email,password" {
		t.Errorf("a call katana saw a script make: %s", got)
	}
	if got := fields("/login", "post", "application/x-www-form-urlencoded"); got != "csrf,email,password" {
		t.Errorf("katana's form: %s", got)
	}
	if got := fields("/profile/avatar", "post", "multipart/form-data"); got != "avatar,note" {
		t.Errorf("katana's multipart form: %s", got)
	}
	if _, ok := doc.Paths["/rest/user/login"]["get"]; ok {
		t.Error("a route katana only POSTed to got a GET")
	}
	if op := doc.Paths["/api/v1/orders"]["get"]; op.X["status"] != 403.0 {
		t.Errorf("ffuf's hit: %+v", op)
	}
	if ps := doc.Paths["/api/products"]["get"].Parameters; len(ps) != 1 || ps[0].Name != "page" {
		t.Errorf("katana's GET with a query: %+v", ps)
	}

	rows, err := mapRows(db)
	if err != nil {
		t.Fatal(err)
	}
	byKey := map[string]engine.MapEntry{}
	for _, r := range rows {
		byKey[r.Entity.Key] = r
	}
	if r := byKey["http://legacy.example.com/"]; r.Coverage != "error" {
		t.Errorf("httpx's failed probe: %+v", r)
	}
	if r := byKey["https://old.example.com/"]; r.Status != 301 || r.Coverage != "visited" {
		t.Errorf("httpx -fr: the first answer is the status: %+v", r)
	}
	if r := byKey["https://shop.example.com/rest/user/login"]; strings.Join(r.Methods, ",") != "POST" || strings.Join(r.Body, ",") != "email,password" || r.Status != 0 {
		t.Errorf("katana's POST row: %+v", r)
	}
}
