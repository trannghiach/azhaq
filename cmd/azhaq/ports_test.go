package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/trannghiach/azhaq/store"
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

// A UDP port that stays silent is a result: a row with the state
// open|filtered in -json, a line with the state in plain output, counted
// in the summary, and a note says what the state means.
func TestPortsListsSilentUDPPort(t *testing.T) {
	t.Chdir(t.TempDir())
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 64)
		for {
			if _, _, err := pc.ReadFrom(buf); err != nil {
				return
			}
		}
	}()
	port := pc.LocalAddr().(*net.UDPAddr).Port
	gone, _ := net.ListenPacket("udp", "127.0.0.1:0")
	gonePort := gone.LocalAddr().(*net.UDPAddr).Port
	gone.Close()
	pu := fmt.Sprintf("%d,%d", port, gonePort)

	out, errOut, code := cli(t, "ports", "-host", "127.0.0.1", "-p", "none", "-pu", pu, "-connect-timeout", "200ms", "-json")
	var row struct {
		Port  int    `json:"port"`
		Proto string `json:"protocol"`
		State string `json:"state"`
	}
	if n := len(lines(out)); n != 1 || json.Unmarshal([]byte(lines(out)[0]), &row) != nil || row.Port != port || row.Proto != "udp" || row.State != "open|filtered" {
		t.Fatalf("rows %q", out)
	}
	sum := sumMap(t, errOut)
	notes, _ := json.Marshal(sum["notes"])
	if code != exitOK || sum["results"] != float64(1) || !strings.Contains(string(notes), "1 UDP port open|filtered: no reply and no ICMP port unreachable") {
		t.Errorf("exit %d, summary %v", code, sum)
	}

	out, _, _ = cli(t, "ports", "-host", "127.0.0.1", "-p", "none", "-pu", pu, "-connect-timeout", "200ms", "-silent")
	if want := fmt.Sprintf("127.0.0.1:%d/udp open|filtered", port); strings.TrimSpace(out) != want {
		t.Errorf("plain output %q, want %q", out, want)
	}
}

// Targets that are all outside the scope end the command with exit 2 and
// a message naming them, before anything is sent; one in scope runs, and
// the summary counts the other.
func TestPortsAllTargetsOutsideTheScope(t *testing.T) {
	t.Chdir(t.TempDir())
	l, err := net.Listen("tcp", "127.0.0.2:0")
	if err != nil {
		t.Skip(err)
	}
	defer l.Close()
	var dialed atomic.Int32
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			dialed.Add(1)
			c.Close()
		}
	}()
	port := fmt.Sprint(l.Addr().(*net.TCPAddr).Port)
	for _, args := range [][]string{
		{"ports", "-host", "127.0.0.2", "-allow", "127.0.0.1", "-p", port},
		{"ports", "-host", "127.0.0.2", "-deny", "127.0.0.2", "-p", port},
		{"ports", "-host", "127.0.0.2/30", "-allow", "example.test", "-p", port},
	} {
		_, errOut, code := cli(t, args...)
		if code != exitUsage || !strings.Contains(errOut, "every target is outside the scope (1 left out): 127.0.0.") {
			t.Errorf("%v: exit %d\n%s", args, code, errOut)
		}
	}
	time.Sleep(100 * time.Millisecond)
	if n := dialed.Load(); n != 0 {
		t.Errorf("%d connects to a target outside the scope", n)
	}
	_, _, code := cli(t, "ports", "-host", "127.0.0.2,127.0.0.1", "-allow", "127.0.0.1", "-p", port, "-json")
	if code != exitOK {
		t.Errorf("a target in scope: exit %d", code)
	}
}

// listenOpen is n accepting TCP listeners on 127.0.0.1, then the ports
// numbered in gone closed again so that a connect to them is refused, in
// ascending order.
func listenOpen(t *testing.T, n int, gone ...int) []int {
	t.Helper()
	type l struct {
		ln   net.Listener
		port int
	}
	var ls []l
	for i := 0; i < n; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Skip(err)
		}
		ls = append(ls, l{ln, ln.Addr().(*net.TCPAddr).Port})
	}
	sort.Slice(ls, func(i, j int) bool { return ls[i].port < ls[j].port })
	var ports []int
	for i, x := range ls {
		ports = append(ports, x.port)
		if slices.Contains(gone, i) {
			x.ln.Close()
			continue
		}
		t.Cleanup(func() { x.ln.Close() })
		go func() {
			for {
				c, err := x.ln.Accept()
				if err != nil {
					return
				}
				c.Close()
			}
		}()
	}
	return ports
}

// A scan the request budget stops counts the addresses it asked, partly or
// wholly, so the summary reconciles with the rows it printed.
func TestPortsStoppedSummaryCountsTheAddressScanned(t *testing.T) {
	t.Chdir(t.TempDir())
	ports := listenOpen(t, 6)
	spec := fmt.Sprintf("%d,%d,%d,%d,%d,%d", ports[0], ports[1], ports[2], ports[3], ports[4], ports[5])
	out, rep, code := runContract(t, "ports", "-host", "127.0.0.1", "-p", spec, "-order", "asc", "-detect", "none", "-max-requests", "3", "-db", "s.db")
	if code != exitLimit {
		t.Fatalf("exit %d, want %d\n%+v", code, exitLimit, rep)
	}
	if n := len(lines(out)); n != 3 || rep.Results != 3 {
		t.Errorf("%d rows printed, results %d, want the 3 open ports asked", n, rep.Results)
	}
	if rep.Counts["addresses"] != 1 {
		t.Errorf("counts %v: the one address asked is not counted", rep.Counts)
	}
}

// A scan the request budget stops, resumed under the same budget and then
// without one: each run prints the open ports it found and its summary
// counts those rows; the workspace's last row holds every open port, and
// the map shows that row, not the first stopped one.
func TestPortsResumeKeepsEveryOpenPort(t *testing.T) {
	t.Chdir(t.TempDir())
	ports := listenOpen(t, 5, 1, 3) // the second and the fourth refuse
	spec := fmt.Sprintf("%d,%d,%d,%d,%d", ports[0], ports[1], ports[2], ports[3], ports[4])
	portsOf := func(out string) (got []int) {
		for _, l := range lines(out) {
			var row struct {
				Port int `json:"port"`
			}
			if json.Unmarshal([]byte(l), &row) != nil || row.Port == 0 {
				t.Fatalf("row %q", l)
			}
			got = append(got, row.Port)
		}
		return got
	}
	var all []int
	step := func(code int, want []int, args ...string) report {
		t.Helper()
		out, rep, got := runContract(t, args...)
		if got != code {
			t.Fatalf("%v: exit %d, want %d\n%+v", args, got, code, rep)
		}
		if p := portsOf(out); !slices.Equal(p, want) || rep.Results != len(want) {
			t.Errorf("%v printed ports %v with results %d, want %v", args, p, rep.Results, want)
		}
		all = append(all, portsOf(out)...)
		return rep
	}
	step(exitLimit, ports[:1], "ports", "-host", "127.0.0.1", "-p", spec, "-order", "asc", "-detect", "none", "-max-requests", "2", "-db", "b.db")
	step(exitLimit, ports[2:3], "resume", "-db", "b.db")
	rep := step(exitOK, ports[4:], "resume", "-db", "b.db", "-max-requests", "0")
	if rep.Command != "ports" {
		t.Errorf("a resumed ports run reports itself as %q", rep.Command)
	}
	if want := []int{ports[0], ports[2], ports[4]}; !slices.Equal(all, want) {
		t.Errorf("the runs printed %v in all, want %v", all, want)
	}

	st, err := store.OpenExisting("b.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	obs, _ := st.Observations()
	type portsRow struct {
		Open    []int  `json:"open"`
		Partial bool   `json:"partial"`
		Asked   string `json:"asked_ports"`
		Scanned int    `json:"scanned"`
		IP      string `json:"ip"`
	}
	var asked []string
	var last portsRow
	for _, o := range obs {
		var row portsRow
		if o.Collector != "azhaq-ports" || json.Unmarshal(o.Payload, &row) != nil || row.IP == "" {
			continue
		}
		asked = append(asked, row.Asked)
		last = row
	}
	if last.Partial || !slices.Equal(last.Open, []int{ports[0], ports[2], ports[4]}) || last.Scanned != 5 {
		t.Errorf("the last row is %+v, want all three open ports and 5 asked", last)
	}
	want := []string{fmt.Sprintf("%d,%d", ports[0], ports[1]), fmt.Sprintf("%d,%d,%d,%d", ports[0], ports[1], ports[2], ports[3]), ""}
	if !slices.Equal(asked, want) {
		t.Errorf("asked_ports over the runs %q, want %q", asked, want)
	}

	rows, err := mapRows("b.db")
	if err != nil {
		t.Fatal(err)
	}
	var shown string
	for _, r := range rows {
		shown += r.Line()
	}
	if want := fmt.Sprintf("open=[%d %d %d]", ports[0], ports[2], ports[4]); !strings.Contains(shown, want) {
		t.Errorf("the map says %q, want %s", shown, want)
	}
}

// A UDP port the host refused (ICMP port unreachable) is closed, not a
// result; the summary says so, so that a scan that found nothing tells
// what it saw: how many ports were closed, a few of them named.
func TestPortsSaysWhichUDPPortsWereClosed(t *testing.T) {
	t.Chdir(t.TempDir())
	var gone []int
	var held []net.PacketConn
	for i := 0; i < 5; i++ {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Skip(err)
		}
		held = append(held, pc)
		gone = append(gone, pc.LocalAddr().(*net.UDPAddr).Port)
	}
	for _, pc := range held {
		pc.Close() // nothing listens on these ports now
	}
	sort.Ints(gone)
	for _, c := range []struct {
		pu   []int
		want string
	}{
		{gone[:1], fmt.Sprintf("1 UDP port closed (ICMP port unreachable): 127.0.0.1:%d", gone[0])},
		{gone, fmt.Sprintf("5 UDP ports closed (ICMP port unreachable): 127.0.0.1:%d, 127.0.0.1:%d, 127.0.0.1:%d and 2 more", gone[0], gone[1], gone[2])},
	} {
		var spec []string
		for _, p := range c.pu {
			spec = append(spec, fmt.Sprint(p))
		}
		out, errOut, code := cli(t, "ports", "-host", "127.0.0.1", "-p", "none", "-pu", strings.Join(spec, ","), "-connect-timeout", "300ms", "-json")
		sum := sumMap(t, errOut)
		notes, _ := json.Marshal(sum["notes"])
		if code != exitOK || strings.TrimSpace(out) != "" || sum["results"] != float64(0) || !strings.Contains(string(notes), c.want) {
			t.Errorf("-pu %v: exit %d, rows %q, summary %v, want the note %q", spec, code, out, sum, c.want)
		}
	}
}
