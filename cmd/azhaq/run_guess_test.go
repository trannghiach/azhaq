package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// run -dns-brute with no passive source and -depth 0 does not go on to
// resolve the names it finds, and does not need to: DNS answered each one
// when it was guessed, so the map holds them live with their addresses.
func TestRunKeepsTheAnswersOfTheNamesItGuessed(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("AZHAQ_DATA_DIR", dir)
	resolvers := serveZone(t, fakeZone{
		a:     map[string]string{"app.example.com": "192.0.2.1", "dev.example.com": "192.0.2.2"},
		cname: map[string]string{"www.example.com": "app.example.com"},
	})
	words := filepath.Join(dir, "words.txt")
	if err := os.WriteFile(words, []byte("app\ndev\nwww\nnope\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, errOut, code := cli(t, "run", "-domain", "example.com", "-dns-brute", words, "-permute", "-sources", "none",
		"-resolvers", resolvers, "-no-paths", "-depth", "0", "-db", "r.db",
		"-skip", skipAllBut("azhaq-subdomains", "azhaq-dns", "azhaq-dns-brute", "azhaq-permute"))
	if code != exitOK {
		t.Fatalf("exit %d\n%s", code, errOut)
	}
	for _, want := range []string{"app.example.com  target  live  ips=[192.0.2.1]", "dev.example.com  target  live  ips=[192.0.2.2]"} {
		if !strings.Contains(out, want) {
			t.Errorf("the map lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "not resolved in this run") || strings.Contains(out, "unresolved") {
		t.Errorf("names DNS answered are listed as not resolved:\n%s", out)
	}
	rows, _, _ := cli(t, "query", "-db", "r.db", "-type", "Hostname", "-json")
	for name, ip := range map[string]string{"app.example.com": "192.0.2.1", "dev.example.com": "192.0.2.2"} {
		var line string
		for _, l := range strings.Split(rows, "\n") {
			if strings.Contains(l, `"key":"`+name+`"`) {
				line = l
			}
		}
		if !strings.Contains(line, `"role":"live"`) || !strings.Contains(line, ip) {
			t.Errorf("%s is not a live row with %s: %s", name, ip, line)
		}
	}
}
