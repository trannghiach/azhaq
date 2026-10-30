package main

import (
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestParseTargetsSpellings(t *testing.T) {
	tg, err := parseTargets([]string{"a.example.com,b.example.com", "127.0.0.1:3001", "10.0.0.0/30", "[::1]:22", "http://c.example.com:8080/x", "AS13335"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(tg.names, []string{"a.example.com", "b.example.com", "c.example.com"}) {
		t.Errorf("names %v", tg.names)
	}
	if !reflect.DeepEqual(tg.ports["127.0.0.1"], []int{3001}) || !reflect.DeepEqual(tg.ports["::1"], []int{22}) || !reflect.DeepEqual(tg.ports["c.example.com"], []int{8080}) {
		t.Errorf("ports %v", tg.ports)
	}
	if len(tg.asns) != 1 || tg.asns[0] != "AS13335" || len(tg.v4) != 1 {
		t.Errorf("asns %v v4 %v", tg.asns, tg.v4)
	}
	for _, bad := range []string{"10.0.0.0/33", "host:99999", "a b"} {
		if _, err := parseTargets([]string{bad}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestCoverMergesRanges(t *testing.T) {
	tg, _ := parseTargets([]string{"10.0.0.0/25", "10.0.0.128/25", "10.0.0.5", "10.0.1.0/24"})
	got := cover(tg.v4)
	want := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/23")}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%v", got)
	}
	if n := tg.addresses(); n != 512 {
		t.Errorf("%v addresses", n)
	}
	tg, _ = parseTargets([]string{"10.0.0.1", "10.0.0.2"})
	if got := cover(tg.v4); len(got) != 1 && len(got) != 2 {
		t.Errorf("%v", got)
	}
}

func TestListLinesBlocksOfBigRanges(t *testing.T) {
	tg, _ := parseTargets([]string{"10.0.0.0/8", "example.com"})
	lines, allow, err := tg.listLines()
	if err != nil || len(lines) != 1<<16+1 || len(allow) != 2 {
		t.Fatalf("%d lines %v err %v", len(lines), allow, err)
	}
	tg, _ = parseTargets([]string{"2001:db8::/32"})
	if _, _, err := tg.listLines(); err == nil {
		t.Error("an IPv6 /32 was accepted")
	}
}

func TestTimeoutNumberExplained(t *testing.T) {
	err := cmdPorts([]string{"-host", "127.0.0.1", "-timeout", "500"})
	if err == nil || !strings.Contains(err.Error(), "-connect-timeout") {
		t.Fatalf("%v", err)
	}
}

func TestMsDuration(t *testing.T) {
	var d msDuration
	if d.Set("500") != nil || time.Duration(d) != 500*time.Millisecond {
		t.Error(d)
	}
	if d.Set("2s") != nil || time.Duration(d) != 2*time.Second {
		t.Error(d)
	}
}

func TestNmapOutputs(t *testing.T) {
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	rows := []portRow{
		{Host: "b.test", IP: "10.0.0.2", Port: 443, Proto: "tcp", State: "open", TLS: true, At: at, Fields: map[string]any{"service": "https", "product": "nginx", "version": "1.2"}},
		{Host: "10.0.0.1", IP: "10.0.0.1", Port: 22, Proto: "tcp", State: "open", At: at, Fields: map[string]any{"service": "ssh?"}},
		{Host: "10.0.0.1", IP: "10.0.0.1", Port: 53, Proto: "udp", State: "open|filtered", At: at},
	}
	dir := t.TempDir()
	o := &portOut{keep: true, rows: rows, xmlPath: filepath.Join(dir, "x.xml"), gnmapOut: filepath.Join(dir, "x.gnmap"), jsonPath: filepath.Join(dir, "x.json")}
	if err := o.finish([]string{"-host", "b.test"}, at, at.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	x, _ := os.ReadFile(o.xmlPath)
	for _, want := range []string{`<nmaprun scanner="azhaq"`, `addr="10.0.0.1"`, `portid="443"`, `tunnel="ssl"`, `<hostname name="b.test"`, `state="open|filtered"`, `method="table"`} {
		if !strings.Contains(string(x), want) {
			t.Errorf("xml lacks %s:\n%s", want, x)
		}
	}
	if strings.Index(string(x), "10.0.0.1") > strings.Index(string(x), "10.0.0.2") {
		t.Error("hosts not in address order")
	}
	g, _ := os.ReadFile(o.gnmapOut)
	if !strings.Contains(string(g), "Host: 10.0.0.1 (10.0.0.1)\tPorts: 22/open/tcp//ssh//") || !strings.Contains(string(g), "443/open/tcp//https//nginx 1.2/") {
		t.Errorf("gnmap:\n%s", g)
	}
	j, _ := os.ReadFile(o.jsonPath)
	if strings.Count(string(j), "\n") != 3 {
		t.Errorf("json:\n%s", j)
	}
}

func TestRowJSONShape(t *testing.T) {
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.FixedZone("x", 7*3600))
	r := portRow{Host: "h", IP: "1.2.3.4", Port: 80, Proto: "tcp", State: "open", CDN: "cloudflare", At: at, Fields: map[string]any{"service": "http"}}
	j := r.jsonRow()
	if j["cdn"] != true || j["cdn-name"] != "cloudflare" || j["timestamp"] != "2026-01-01T20:04:05Z" {
		t.Errorf("%v", j)
	}
	if got := r.csvRow([]string{"host", "port", "cdn", "cdn-name"}); !reflect.DeepEqual(got, []string{"h", "80", "true", "cloudflare"}) {
		t.Errorf("%v", got)
	}
}
