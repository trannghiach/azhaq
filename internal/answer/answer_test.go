package answer

import (
	"io"
	"strings"
	"testing"
)

func TestReasonSaysWhyAnErrorIsOne(t *testing.T) {
	for body, want := range map[string]string{
		"API count exceeded - Increase Quota with Membership":       "API count exceeded - Increase Quota with Membership",
		"error check your search parameter":                         "error check your search parameter",
		"error input invalid - missing IP or hostname":              "error input invalid - missing IP or hostname",
		`{"error":"quota exceeded"}`:                                "quota exceeded",
		`{"error":{"code":429,"message":"slow down"}}`:              "slow down",
		`{"message":"Too Many Requests"}`:                           "Too Many Requests",
		`{"detail":"Not authenticated","status":401}`:               "Not authenticated",
		`{"success":false,"message":"daily limit"}`:                 "daily limit",
		`{"status":"error","message":"bad key"}`:                    "bad key",
		`{"status":429,"message":"Ratelimit"}`:                      "Ratelimit",
		`<html><head><title>Just a moment...</title></head></html>`: `an HTML page titled "Just a moment..."`,
		`<html><body><h1>Rate limit exceeded</h1></body></html>`:    "Rate limit exceeded",
		"<html><title>Attention Required! | Cloudflare</title>":     `an HTML page titled "Attention Required! | Cloudflare"`,
	} {
		if got := Reason([]byte(body)); got != want {
			t.Errorf("%q: got %q, want %q", body, got, want)
		}
	}
}

func TestReasonLeavesDataAndEmptyAnswersAlone(t *testing.T) {
	for _, body := range []string{
		"",
		"  \n",
		"[]",
		`["a.example.org","b.example.org"]`,
		`[["original"],["http://example.org/"]]`,
		"No records found",
		"www.example.org,192.0.2.1\napi.example.org,192.0.2.2",
		`{"data":{"employees_urls":[],"clients_urls":[]}}`,
		`{"error":null,"results":[]}`,
		`{"error":"","subdomains":["a.example.org"]}`,
		`{"success":true,"message":"done","data":["a.example.org"]}`,
		`{"error":"No Captures found for: example.org/*"}`,
		`{"urlkey":"org,example)/","url":"http://example.org/","status":"404"}`,
		`<html><head><title>Subdomain Finder: example.org - RapidDNS.io</title></head><body><table><tr><td>a.example.org</td></tr></table></body></html>`,
		"<html><title>404 Not Found</title></html>",
		`{"message":"ok","count":0,"subdomains":[],"extra":1}`,
	} {
		if got := Reason([]byte(body)); got != "" {
			t.Errorf("%q: called an error: %q", body, got)
		}
	}
	long := `{"error":"x","pad":"` + strings.Repeat("a", MaxBody) + `"}`
	if got := Reason([]byte(long)); got != "" {
		t.Errorf("a body past %d bytes is data, got %q", MaxBody, got)
	}
}

func TestScreenKeepsTheBody(t *testing.T) {
	for _, body := range []string{"API count exceeded", strings.Repeat("a.example.org\n", 5000)} {
		rc, why := Screen(io.NopCloser(strings.NewReader(body)))
		got, err := io.ReadAll(rc)
		if err != nil || string(got) != body {
			t.Errorf("body changed: %d bytes back of %d, %v", len(got), len(body), err)
		}
		if (why != "") != (len(body) < 100) {
			t.Errorf("%.20q: reason %q", body, why)
		}
		rc.Close()
	}
}
