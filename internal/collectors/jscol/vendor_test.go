package jscol

import "testing"

func TestVendorScriptNames(t *testing.T) {
	for path, want := range map[string]bool{
		"/resources/js/angular_1-7-7.js":         true,
		"/js/jquery_3_6_0.min.js":                true,
		"/resources/js/react-dom.development.js": true,
		"/js/jquery-3.6.0.min.js":                true,
		"/js/chart_utils.js":                     false,
		"/js/angular_app.js":                     false,
		"/js/vue_router.js":                      false,
		"/js/app.js":                             false,
	} {
		if got := vendorScript.MatchString(path); got != want {
			t.Errorf("%s: library %v, want %v", path, got, want)
		}
	}
}
