package portcol

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/trannghiach/azhaq/internal/portscan"
	"github.com/trannghiach/azhaq/types"
)

// silentUDP listens on addr and never answers.
func silentUDP(t *testing.T, addr string) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 64)
		for {
			if _, _, err := pc.ReadFrom(buf); err != nil {
				return
			}
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr).Port
}

func runUDPPrefix(t *testing.T, prefix string, ports []int) []types.StoredObservation {
	t.Helper()
	c := New(nil, nil, 0)
	c.UDPPorts = ports
	c.Scanner.Timeout = 150 * time.Millisecond
	var obs []types.StoredObservation
	_, err := c.Run(context.Background(), types.Seed{Type: types.TypePrefix, Keys: map[string]string{"prefix": prefix}}, func(o types.Observation) error {
		obs = append(obs, types.StoredObservation{Observation: o})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return obs
}

// An address asked on its own, whose only UDP port is silent, has a row
// for it, and the summary counts it.
func TestSilentUDPPortOfOneAddressIsARow(t *testing.T) {
	port := silentUDP(t, "127.0.0.1:0")
	obs := runUDPPrefix(t, "127.0.0.1/32", []int{port})
	var rows int
	var services []portscan.UDPPort
	for _, o := range obs {
		var row struct {
			IP       string             `json:"ip"`
			Services []portscan.UDPPort `json:"udp_services"`
		}
		if json.Unmarshal(o.Payload, &row) == nil && row.IP == "127.0.0.1" {
			rows++
			services = row.Services
		}
	}
	if rows != 1 || len(services) != 1 || services[0].Port != port || services[0].State != "open|filtered" {
		t.Fatalf("%d rows, services %+v", rows, services)
	}
	if n := Notes(obs); len(n) != 1 || !strings.HasPrefix(n[0], "1 UDP port open|filtered: no reply and no ICMP port unreachable") {
		t.Errorf("notes %q", n)
	}
}

// In a range, an address that answered nothing on UDP is not a row (a
// dead address would be a screenful); the range's row and the summary
// count its silent ports. One that refused another port is listed.
func TestSilentUDPPortsOfARange(t *testing.T) {
	port := silentUDP(t, "127.0.0.2:0")
	obs := runUDPPrefix(t, "127.0.0.0/30", []int{port})
	var addrRows int
	var rng map[string]any
	for _, o := range obs {
		var r map[string]any
		_ = json.Unmarshal(o.Payload, &r)
		if r["range"] == true {
			rng = r
		} else {
			addrRows++
		}
	}
	if addrRows != 0 || rng == nil || rng["udp_silent_addresses"] != float64(1) || rng["udp_silent_ports"] != float64(1) {
		t.Fatalf("%d address rows, range row %v", addrRows, rng)
	}
	if n := Notes(obs); len(n) != 1 || !strings.Contains(n[0], "1 addresses of the ranges answered no UDP port") {
		t.Errorf("notes %q", n)
	}

	// The same address with a second port the host refused did answer: its silent port is a row.
	gone, _ := net.ListenPacket("udp", "127.0.0.2:0")
	gonePort := gone.LocalAddr().(*net.UDPAddr).Port
	gone.Close()
	obs = runUDPPrefix(t, "127.0.0.0/30", []int{port, gonePort})
	var listed int
	for _, o := range obs {
		var r struct {
			IP       string             `json:"ip"`
			Services []portscan.UDPPort `json:"udp_services"`
		}
		if json.Unmarshal(o.Payload, &r) == nil && r.IP == "127.0.0.2" {
			listed += len(r.Services)
		}
	}
	if listed != 1 {
		t.Errorf("%d silent ports listed, want 1", listed)
	}
	if n := Notes(obs); len(n) != 1 || !strings.HasPrefix(n[0], "1 UDP port open|filtered") {
		t.Errorf("notes %q", n)
	}
}

// More silent ports on one address than a row lists are counted and kept
// in the row's udp_open_filtered, not printed one by one.
func TestManySilentUDPPortsAreNotRows(t *testing.T) {
	var rep portscan.UDPReport
	for p := 1; p <= maxListed+1; p++ {
		rep.OpenFiltered = append(rep.OpenFiltered, portscan.UDPPort{Port: p, State: portscan.UDPOpenFiltered})
	}
	row := map[string]any{"host": "10.0.0.9", "ip": "10.0.0.9"}
	addUDP(row, rep, len(rep.OpenFiltered))
	if _, ok := row["udp_services"]; ok || row["udp_unlisted"] != maxListed+1 || len(row["udp_open_filtered"].([]int)) != maxListed+1 {
		t.Fatalf("row %v", row)
	}
	raw, _ := json.Marshal(row)
	n := Notes([]types.StoredObservation{{Observation: types.Observation{Collector: Name, Payload: raw}}})
	if len(n) != 1 || !strings.Contains(n[0], "65 UDP ports open|filtered on 10.0.0.9 are not listed one by one") {
		t.Errorf("notes %q", n)
	}
}

// Two rows of one address (its range row's follow-up) count a silent
// port once.
func TestSilentUDPPortCountedOnce(t *testing.T) {
	raw, _ := json.Marshal(map[string]any{"host": "10.0.0.9", "ip": "10.0.0.9", "udp_open_filtered": []int{5, 6}})
	o := types.StoredObservation{Observation: types.Observation{Collector: Name, Payload: raw}}
	n := Notes([]types.StoredObservation{o, o})
	if len(n) != 1 || !strings.HasPrefix(n[0], "2 UDP ports open|filtered") {
		t.Errorf("notes %q", n)
	}
}
