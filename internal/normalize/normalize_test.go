package normalize

import "testing"

func TestURL(t *testing.T) {
	got, err := URL("HTTPS://Example.COM:443/a#frag")
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://example.com/a" {
		t.Fatalf("got %q", got)
	}
	// The start of a URL a script builds at run time: no port is no URL.
	if got, err := URL("http://127.0.0.1:/"); err == nil {
		t.Errorf("an empty port: %q", got)
	}
}

func TestHostname(t *testing.T) {
	if Hostname("Ex.COM.") != "ex.com" {
		t.Fatal(Hostname("Ex.COM."))
	}
}

func TestTenant(t *testing.T) {
	for host, want := range map[string]bool{
		"bucket.s3.us-west-2.amazonaws.com": true,
		"acme.github.io":                    true,
		"app.herokuapp.com":                 true,
		"www.hackerone.com":                 false,
		"api.example.co.uk":                 false,
		"juice.lab.test":                    false,
		"127.0.0.1":                         false,
	} {
		if got := Tenant(host); got != want {
			t.Errorf("Tenant(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestUnlisted(t *testing.T) {
	for host, want := range map[string]bool{
		"azqlab.lan":        true,
		"www.corp.lan":      true,
		"acme.github.io":    false,
		"www.example.com":   false,
		"api.example.co.uk": false,
		"127.0.0.1":         false,
	} {
		if got := Unlisted(host); got != want {
			t.Errorf("Unlisted(%q) = %v, want %v", host, got, want)
		}
	}
}

// A hash route is the view's address; any other fragment is not.
func TestClientURL(t *testing.T) {
	for in, want := range map[string]string{
		"HTTP://Shop.test:80/#/administration": "http://shop.test/#/administration",
		"https://shop.test/app#!/admin":        "https://shop.test/app#!/admin",
		"https://shop.test/docs#install":       "https://shop.test/docs",
		"https://shop.test/admin":              "https://shop.test/admin",
	} {
		if got, err := ClientURL(in); err != nil || got != want {
			t.Errorf("%s: %q %v", in, got, err)
		}
	}
}
