package egress

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/trannghiach/azhaq/internal/neterr"
)

func listener(t *testing.T) (addr string, accepted *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	n := new(atomic.Int32)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			n.Add(1)
			c.Close()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String(), n
}

func TestPortDialerRecordsAndHoldsTheScope(t *testing.T) {
	Reset()
	defer Reset()
	entries := withLedger(t)
	addr, _ := listener(t)
	d := NewPortDialer(time.Second, nil, "", "")
	c, err := d.TCP(context.Background(), "app.test", addr)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	// A name in scope reaches an address the rules do not name; a name and an
	// address outside both do not.
	SetScope(func(h string) bool { return h == "app.test" })
	if c, err := d.TCP(context.Background(), "app.test", addr); err != nil {
		t.Fatalf("a name in scope: %v", err)
	} else {
		c.Close()
	}
	if _, err := d.TCP(context.Background(), "other.test", addr); !errors.Is(err, neterr.ErrOutOfScope) {
		t.Fatalf("a name outside the scope: %v", err)
	}
	SetScope(func(h string) bool { return h == "127.0.0.1" })
	if c, err := d.TCPDirect(context.Background(), "", addr); err != nil {
		t.Fatalf("an address in scope: %v", err)
	} else {
		c.Close()
	}
	got := entries()
	if len(got) != 3 || got[0] != "tcp/target" {
		t.Fatalf("ledger %v: the refused connect is not recorded, the others are", got)
	}
}

func TestPortDialerStopsAtTheKillFile(t *testing.T) {
	Reset()
	defer Reset()
	addr, accepted := listener(t)
	path := filepath.Join(t.TempDir(), "run.stop")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	defer SetKill(path)()
	d := NewPortDialer(time.Second, nil, "", "")
	if _, err := d.TCP(context.Background(), "", addr); !errors.Is(err, neterr.ErrKilled) {
		t.Fatalf("%v", err)
	}
	ua, _ := net.ResolveUDPAddr("udp", "127.0.0.1:9")
	if _, err := d.UDP(context.Background(), "", ua); !errors.Is(err, neterr.ErrKilled) {
		t.Fatalf("udp: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	if accepted.Load() != 0 {
		t.Fatalf("%d connections reached the listener", accepted.Load())
	}
}

func TestPortDialerUDPIsRecorded(t *testing.T) {
	Reset()
	defer Reset()
	entries := withLedger(t)
	d := NewPortDialer(time.Second, nil, "", "")
	ua, _ := net.ResolveUDPAddr("udp", "127.0.0.1:9")
	c, err := d.UDP(context.Background(), "", ua)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	c, err = d.UDPAnySource(context.Background(), "", ua)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if got := entries(); len(got) != 2 || got[0] != "udp/target" {
		t.Fatalf("ledger %v", got)
	}
}
