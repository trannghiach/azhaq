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
