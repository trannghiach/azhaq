package cpedetect

import (
	"strings"
	"testing"
)

func TestDetect(t *testing.T) {
	d, err := NewCPEDetector()
	if err != nil {
		t.Fatal(err)
	}
	got := d.Detect("Dashboard [Jenkins]", "", "")
	found := false
	for _, m := range got {
		found = found || strings.Contains(m.CPE, ":jenkins:")
	}
	if !found {
		t.Fatalf("no jenkins in %+v", got)
	}
	// A version tech reading fills the CPE version in.
	for _, m := range EnrichCPEVersions(got, []string{"Jenkins:2.440.1"}) {
		if strings.Contains(m.CPE, ":jenkins:") && !strings.Contains(m.CPE, ":2.440.1:") {
			t.Errorf("version not set: %s", m.CPE)
		}
	}
}

func TestWordPress(t *testing.T) {
	w, err := NewWordPressDetector()
	if err != nil {
		t.Fatal(err)
	}
	info := w.Detect(`<link href="/wp-content/plugins/akismet/x.css"><script src="/wp-content/themes/twentytwenty/a.js"></script><i src="/wp-content/plugins/no-such-plugin-zz/">`)
	if !info.HasData() || len(info.Plugins) != 1 || info.Plugins[0] != "akismet" || len(info.Themes) != 1 {
		t.Errorf("got %+v", info)
	}
	if w.Detect("<html>plain</html>").HasData() {
		t.Error("plain page has plugins")
	}
}
