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
