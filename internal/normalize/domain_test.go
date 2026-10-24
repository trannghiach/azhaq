package normalize

import "testing"

func TestRegistrableDomain(t *testing.T) {
	if g := RegistrableDomain("www.example.com"); g != "example.com" {
		t.Fatalf("got %q", g)
	}
	if g := RegistrableDomain("127.0.0.1"); g != "" {
		t.Fatalf("ip -> %q", g)
	}
}

func TestSpecialUse(t *testing.T) {
	if !SpecialUse("example.test") || !SpecialUse("foo.localhost") || !SpecialUse("x.invalid") {
		t.Fatal("reserved TLD")
	}
	if SpecialUse("example.com") || SpecialUse("127.0.0.1") || SpecialUse("") {
		t.Fatal("public or IP")
	}
}

func TestAppspotTenantsAreNotSameSite(t *testing.T) {
	if RegistrableDomain("public-firing-range.appspot.com") != "public-firing-range.appspot.com" {
		t.Fatalf("tenant %q", RegistrableDomain("public-firing-range.appspot.com"))
	}
	if SameSite("public-firing-range.appspot.com", "other.appspot.com") {
		t.Fatal("PaaS siblings must not share a site")
	}
	if RegistrableDomain("appspot.com") != "" {
		t.Fatal("platform suffix is not a tenant")
	}
}

func TestSameSite(t *testing.T) {
	if !SameSite("challs.test.brunnerne.xyz", "php.challs.brunnerne.xyz") {
		t.Fatal("same eTLD+1")
	}
	if SameSite("challs.test.brunnerne.xyz", "dead.traefik.default") {
		t.Fatal("default cert SAN is not same site")
	}
	if SameSite("challs.test.brunnerne.xyz", "other.test") {
		t.Fatal("other site")
	}
}
