package takeover

import "testing"

func TestByCNAME(t *testing.T) {
	for _, c := range []struct {
		host                   string
		chain                  []string
		gone, registered, want bool
		service                string
	}{
		{"app.example.com", []string{"example-app.azurewebsites.net"}, true, true, true, "Azure"},
		{"app.example.com", []string{"example-app.azurewebsites.net"}, false, true, false, ""}, // it resolves: someone holds it
		{"old.example.com", []string{"cdn.forgotten-vendor.io"}, true, false, true, "domain"},
		{"old.example.com", []string{"cdn.vendor.io"}, true, true, false, ""},              // the vendor's domain exists: nothing to claim from DNS alone
		{"a.example.com", []string{"b.example.com"}, true, false, false, ""},               // the owner's own name
		{"x.example.com", []string{"x.s3.eu-west-1.amazonaws.com"}, true, true, false, ""}, // S3 says so in its page, not in DNS
	} {
		f, ok := ByCNAME(c.host, c.chain, c.gone, c.registered)
		if ok != c.want || f.Service != c.service {
			t.Errorf("%s → %v: %v %+v", c.host, c.chain, ok, f)
		}
	}
}

func TestByPage(t *testing.T) {
	if f, ok := ByPage([]string{"acme.github.io"}, []byte(`<p>There isn't a GitHub Pages site here.</p>`)); !ok || f.Service != "GitHub Pages" || f.Strength != "strong" {
		t.Errorf("github %+v %v", f, ok)
	}
	if f, ok := ByPage([]string{"files.example.com.s3.amazonaws.com"}, []byte(`<Error><Code>NoSuchBucket</Code></Error>`)); !ok || f.Service != "AWS S3" {
		t.Errorf("s3 %+v %v", f, ok)
	}
	// The words on another service's name prove nothing.
	if _, ok := ByPage([]string{"lb.example.net"}, []byte(`There isn't a GitHub Pages site here.`)); ok {
		t.Error("a page's words on another service")
	}
	if _, ok := ByPage(nil, []byte(`<html>welcome</html>`)); ok {
		t.Error("an ordinary page")
	}
}

func TestDomain(t *testing.T) {
	for host, want := range map[string]string{
		"frontend-app-1.us-west-2.elb.amazonaws.com": "amazonaws.com", // a cloud's shared suffix is no registry
		"cdn.forgotten-vendor.io":                    "forgotten-vendor.io",
		"a.b.example.co.uk":                          "example.co.uk",
		"x.github.io":                                "github.io",
	} {
		if got := Domain(host); got != want {
			t.Errorf("%s: %q, want %q", host, got, want)
		}
	}
}
