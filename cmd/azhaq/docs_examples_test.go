package main

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
)

// A notify example in the docs names the provider config it needs: without
// one the command stops with exit 2 and sends nothing.
func TestDocsNotifyExamplesNameTheirConfig(t *testing.T) {
	for _, f := range []string{"README.md", "docs/MIGRATING.md", "docs/RECIPES.md"} {
		inFence := false
		for _, l := range strings.Split(readDoc(t, "../../"+f), "\n") {
			if strings.HasPrefix(strings.TrimSpace(l), "```") {
				inFence = !inFence
				continue
			}
			if !inFence || !regexp.MustCompile(`(^|\| )azhaq notify `).MatchString(strings.TrimSpace(l)) {
				continue
			}
			if !strings.Contains(l, " -pc ") && !strings.Contains(l, " -provider-config ") {
				t.Errorf("%s: a notify example without -pc FILE:\n  %s", f, l)
			}
		}
	}
}

// The sample config next to the notify examples loads, and its custom entry
// delivers the message the examples pipe in.
func TestMigratingNotifySampleConfigDelivers(t *testing.T) {
	doc := readDoc(t, "../../docs/MIGRATING.md")
	m := regexp.MustCompile("(?s)```yaml\n(.*?)```").FindStringSubmatch(doc[strings.Index(doc, "## notify:"):])
	if m == nil {
		t.Fatal("MIGRATING has no sample provider-config.yaml in its notify section")
	}
	rec := &recorder{}
	srv := rec.server(200)
	defer srv.Close()
	cfg := writeTemp(t, "provider-config.yaml", strings.ReplaceAll(m[1], "http://127.0.0.1:8000/hook", srv.URL+"/hook"))
	in := writeTemp(t, "in.txt", "127.0.0.1:22\n")
	_, errOut, err := captureAll(t, func() error {
		return cmdNotify([]string{"-p", "custom", "-rl", "0", "-pc", cfg, "-i", in})
	})
	if err != nil {
		t.Fatalf("the sample config: %v\n%s", err, errOut)
	}
	if len(rec.bodies) != 1 {
		t.Fatalf("custom delivered %d messages: %q", len(rec.bodies), rec.bodies)
	}
	var body struct{ Text string }
	if json.Unmarshal([]byte(rec.bodies[0]), &body) != nil || body.Text != "127.0.0.1:22" {
		t.Errorf("custom posted %q", rec.bodies[0])
	}
}
