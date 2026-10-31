package portcol

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/trannghiach/azhaq/internal/dnsr"
	"github.com/trannghiach/azhaq/internal/neterr"
	"github.com/trannghiach/azhaq/internal/portscan"
	"github.com/trannghiach/azhaq/types"
)

// A name's IPv6 addresses this machine cannot reach are not scanned, and
// the summary says for how many names; a port the probe found HTTP on is
// handed on as http://, without an HTTPS try first.
func TestIPv6NotScannedAndHTTPHint(t *testing.T) {
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer web.Close()
	_, p, _ := net.SplitHostPort(web.Listener.Addr().String())
	port, _ := strconv.Atoi(p)

	pool := dnsr.New(dnsr.Options{Resolvers: []string{"192.0.2.1"}, PerSecond: -1})
	pool.Exchange = func(_ context.Context, q *dns.Msg, _ string) (*dns.Msg, error) {
		m := new(dns.Msg)
		m.SetReply(q)
		name, qt := q.Question[0].Name, q.Question[0].Qtype
		switch {
		case qt == dns.TypeA && name == "dual.example.org.":
			rr, _ := dns.NewRR(name + " 60 IN A 127.0.0.1")
			m.Answer = append(m.Answer, rr)
		case qt == dns.TypeAAAA && (name == "dual.example.org." || name == "six.example.org."):
			rr, _ := dns.NewRR(name + " 60 IN AAAA 2001:db8::1")
			m.Answer = append(m.Answer, rr)
		}
		return m, nil
	}
	c := New(pool, []int{port}, 1000)
	c.Scanner.Banner = 200 * time.Millisecond
	c.IPv6 = func() bool { return false }

	var obs []types.StoredObservation
	emit := func(o types.Observation) error {
		obs = append(obs, types.StoredObservation{Observation: o})
		return nil
	}
	meta, err := c.Run(context.Background(), types.Seed{Type: types.TypeHostname, Keys: map[string]string{"fqdn": "dual.example.org"}}, emit)
	if err != nil || meta.EmitCount != 1 {
		t.Fatalf("dual: %+v %v", meta, err)
	}
	var row struct {
		IP       string          `json:"ip"`
		Open     []int           `json:"open"`
		Services []portscan.Open `json:"services"`
		Unrouted []string        `json:"ipv6_not_scanned"`
	}
	_ = json.Unmarshal(obs[0].Payload, &row)
	if row.IP != "127.0.0.1" || len(row.Open) != 1 || row.Services[0].Service != "http" || len(row.Unrouted) != 1 || row.Unrouted[0] != "2001:db8::1" {
		t.Errorf("dual row %s", obs[0].Payload)
	}
	if len(meta.NextHints) != 1 || meta.NextHints[0].Keys["url"] != "http://dual.example.org:"+p+"/" || meta.NextHints[0].Keys["fallback"] != "" {
		t.Errorf("hints %+v", meta.NextHints)
	}
	if _, err := c.Run(context.Background(), types.Seed{Type: types.TypeHostname, Keys: map[string]string{"fqdn": "six.example.org"}}, emit); err != nil {
		t.Fatal(err)
	}
	if len(obs) != 2 {
		t.Fatalf("an IPv6-only name left no row: %d", len(obs))
	}
	got := Notes(obs)
	if len(got) != 1 || got[0] != "IPv6 addresses of 2 names not scanned: no IPv6 route from this machine" {
		t.Errorf("notes %q", got)
	}
	if n := Notes(obs[:1]); len(n) != 1 || n[0] != "IPv6 addresses of 1 name not scanned: no IPv6 route from this machine" {
		t.Errorf("notes %q", n)
	}
}

func TestNotesSilentPorts(t *testing.T) {
	row := func(host, ip string, silent ...int) types.StoredObservation {
		raw, _ := json.Marshal(map[string]any{"host": host, "ip": ip, "scanned": 3, "open": []int{22}, "filtered": len(silent), "filtered_ports": silent})
		return types.StoredObservation{Observation: types.Observation{Collector: Name, Payload: raw}}
	}
	got := Notes([]types.StoredObservation{row("scanme.nmap.org", "45.33.32.156", 80), row("10.0.0.5", "10.0.0.5", 1, 2, 3, 4, 5, 6, 7, 8, 9, 10)})
	want := "ports that neither accepted nor refused a connect, asked twice: 10.0.0.5 ports 1, 2, 3, 4, 5, 6, 7, 8, +2 more; scanme.nmap.org (45.33.32.156) port 80; filtered, or the host drops connects: scan them again to be sure (azhaq show -db FILE HOST lists them all)"
	if len(got) != 1 || got[0] != want {
		t.Errorf("notes %q\nwant %q", got, want)
	}
}

// With UDP ports given, a row says which answered, which were silent
// and how many were closed, and the note counts the silent ones.
func TestUDPFieldsInTheRow(t *testing.T) {
	answer, _ := net.ListenPacket("udp", "127.0.0.1:0")
	defer answer.Close()
	quiet, _ := net.ListenPacket("udp", "127.0.0.1:0")
	defer quiet.Close()
	go func() {
		buf := make([]byte, 64)
		for {
			_, from, err := answer.ReadFrom(buf)
			if err != nil {
				return
			}
			answer.WriteTo([]byte("hi"), from)
		}
	}()
	gone, _ := net.ListenPacket("udp", "127.0.0.1:0")
	goneAddr := gone.LocalAddr().(*net.UDPAddr)
	gone.Close()
	port := func(c net.PacketConn) int { return c.LocalAddr().(*net.UDPAddr).Port }

	c := New(nil, nil, 0)
	c.UDPPorts = []int{port(answer), port(quiet), goneAddr.Port}
	c.Scanner.Timeout = 300 * time.Millisecond
	var obs []types.StoredObservation
	emit := func(o types.Observation) error {
		obs = append(obs, types.StoredObservation{Observation: o})
		return nil
	}
	if _, err := c.Run(context.Background(), types.Seed{Type: types.TypeIPAddress, Keys: map[string]string{"ip": "127.0.0.1"}}, emit); err != nil {
		t.Fatal(err)
	}
	var row struct {
		UDPOpen     []int              `json:"udp_open"`
		UDPFiltered []int              `json:"udp_open_filtered"`
		UDPClosed   int                `json:"udp_closed"`
		UDPScanned  int                `json:"udp_scanned"`
		Services    []portscan.UDPPort `json:"udp_services"`
	}
	if len(obs) != 1 {
		t.Fatalf("%d rows", len(obs))
	}
	_ = json.Unmarshal(obs[0].Payload, &row)
	if len(row.UDPOpen) != 1 || row.UDPOpen[0] != port(answer) || len(row.UDPFiltered) != 1 || row.UDPFiltered[0] != port(quiet) ||
		row.UDPClosed != 1 || row.UDPScanned != 3 || len(row.Services) != 2 || row.Services[0].State != "open" || row.Services[1].State != "open|filtered" {
		t.Errorf("row %s", obs[0].Payload)
	}
	if n := Notes(obs); len(n) != 1 || !strings.HasPrefix(n[0], "1 UDP port open|filtered") {
		t.Errorf("notes %q", n)
	}
}

// An address whose open ports were not all asked what they serve, and a UDP
// scan that left silent ports unpaced, say so in the summary.
func TestNotesSayWhatWasNotProbed(t *testing.T) {
	payload, _ := json.Marshal(map[string]any{"host": "h.example", "ip": "10.0.0.5", "unprobed": 7, "udp_limited": 90})
	obs := []types.StoredObservation{{Observation: types.Observation{Collector: Name, Payload: payload}}}
	n := Notes(obs)
	if len(n) != 2 || !strings.Contains(n[0], "protocol was not probed") || !strings.Contains(n[0], "10.0.0.5: 7") || !strings.Contains(n[1], "90 silent ports") {
		t.Errorf("notes %q", n)
	}
}

// A scan the request budget stops keeps what it found and the ports it
// asked; the scan run again with that prior asks only the others, and its
// row holds every open port.
func TestStoppedScanResumes(t *testing.T) {
	var open []int
	for i := 0; i < 2; i++ {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				c.Close()
			}
		}()
		_, p, _ := net.SplitHostPort(l.Addr().String())
		n, _ := strconv.Atoi(p)
		open = append(open, n)
	}
	// The listeners and the 40 ports after the first.
	ports := append([]int{}, open...)
	for p := open[0] + 1; len(ports) < 42; p++ {
		if p != open[1] {
			ports = append(ports, p)
		}
	}
	seed := types.Seed{Type: types.TypeIPAddress, Keys: map[string]string{"ip": "127.0.0.1"}}
	var asked []int
	scan := func(c *Collector, budget int) []types.StoredObservation {
		c.Scanner.Banner = -1
		n := 0
		c.Scanner.Take = func() error {
			if budget > 0 && n >= budget {
				return neterrBudget
			}
			n++
			return nil
		}
		var obs []types.StoredObservation
		_, _ = c.Run(context.Background(), seed, func(o types.Observation) error {
			obs = append(obs, types.StoredObservation{Observation: o})
			return nil
		})
		asked = append(asked, n)
		return obs
	}
	first := scan(New(nil, ports, 1000), 10)
	prior := Priors(first)["127.0.0.1"]
	if len(prior.Asked) != 10 || len(first) != 1 {
		t.Fatalf("first: %d asked, %d rows", len(prior.Asked), len(first))
	}
	c := New(nil, ports, 1000)
	c.Prior = map[string]Prior{"127.0.0.1": prior}
	second := scan(c, 0)
	if asked[1] != len(ports)-10 {
		t.Errorf("the second scan asked %d ports, want %d", asked[1], len(ports)-10)
	}
	var row struct {
		Open    []int `json:"open"`
		Partial bool  `json:"partial"`
	}
	if len(second) != 1 || json.Unmarshal(second[0].Payload, &row) != nil || row.Partial || len(row.Open) != 2 {
		t.Errorf("second: %s", second[0].Payload)
	}
	if _, ok := Priors(append(first, second...))["127.0.0.1"]; ok {
		t.Error("a whole scan after the stopped one still reads as stopped")
	}
}

var neterrBudget = neterr.ErrBudget

// The row of a scan a limit stopped is in the summary only until the row
// that finishes the scan arrives: its silent ports are not counted twice.
func TestNotesReadAStoppedScanOnlyUntilItIsFinished(t *testing.T) {
	row := func(partial bool) types.StoredObservation {
		p, _ := json.Marshal(map[string]any{"host": "h.example", "ip": "10.0.0.5", "filtered_ports": []int{81}, "partial": partial})
		return types.StoredObservation{Observation: types.Observation{Collector: Name, Payload: p}}
	}
	for _, c := range []struct {
		obs  []types.StoredObservation
		want int
	}{
		{[]types.StoredObservation{row(true), row(true), row(false)}, 1},
		{[]types.StoredObservation{row(true), row(true)}, 1},
	} {
		n := Notes(c.obs)
		if len(n) != 1 || strings.Count(n[0], "h.example (10.0.0.5) port 81") != c.want {
			t.Errorf("notes %q", n)
		}
	}
}
