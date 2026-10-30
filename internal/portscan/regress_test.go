package portscan

import (
	"context"
	"net"
	"strconv"
	"testing"
)

// PRB-07 (open, owner P1/P2: ports): on loopback a connect from the
// ephemeral range to a port that nothing listens on can pick that same
// port as its source and connect to itself (TCP simultaneous open), so
// the sweep lists a closed port as open. The fix is to count a connection
// whose local and remote addresses are the same as refused, in probe.
//
// The kernel picks the source port, so this sweeps the whole ephemeral
// range, which meets the case about once per sweep.
func TestRegressPRB07SelfConnectIsNotAnOpenPort(t *testing.T) {
	t.Skip("open: PRB-07 (owner P1/P2: ports); root cause is loopback self-connect, fix is in Scanner.probe")
	var ports []int
	for p := 32768; p < 61000; p++ {
		ports = append(ports, p)
	}
	s := &Scanner{Banner: -1}
	for sweep := 1; sweep <= 25; sweep++ {
		r, err := s.ScanEach(context.Background(), "127.0.0.1", "127.0.0.1", ports)
		if err != nil {
			t.Fatal(err)
		}
		for _, o := range r.Open {
			// A port that is free to bind now had no listener to connect to.
			if l, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(o.Port))); err == nil {
				l.Close()
				t.Fatalf("sweep %d: port %d listed open and nothing listens on it", sweep, o.Port)
			}
		}
	}
}
