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
