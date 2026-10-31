package portscan

import (
	"bytes"
	"context"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/trannghiach/azhaq/internal/ledger"
)

// holder accepts and answers by a rule of its own: reply gets the first bytes
// a connection sent and the connection, and writes what it will; a connection
// it leaves alone is held open and silent. maxOpen is the most connections
// that were open at once.
func holder(t *testing.T, reply func(first []byte, c net.Conn)) (port int, maxOpen *atomic.Int32) {
	t.Helper()
	var open atomic.Int32
	maxOpen = new(atomic.Int32)
	port = listen(t, func(c net.Conn) {
		n := open.Add(1)
		defer open.Add(-1)
		for {
			m := maxOpen.Load()
			if n <= m || maxOpen.CompareAndSwap(m, n) {
				break
			}
		}
		buf := make([]byte, 4096)
		k, _ := c.Read(buf)
		if reply != nil && k > 0 {
			reply(buf[:k], c)
		}
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, _ = c.Read(buf) // held open until the other side leaves
	})
	return port, maxOpen
}

// A port that says nothing to any request is run down the whole ladder in a
// few waits, not one for each protocol, and every connect is still counted
// and recorded.
func TestSilentPortLadderIsAskedAFewAtATime(t *testing.T) {
	path := filepath.Join(t.TempDir(), "l.jsonl")
	l, err := ledger.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ledger.Use(l)
	defer ledger.Use(nil)
	port, _ := holder(t, nil)
	var takes atomic.Int32
	s := &Scanner{Banner: 50 * time.Millisecond, Timeout: 200 * time.Millisecond, Take: func() error { takes.Add(1); return nil }}
	t0 := time.Now()
	r, err := s.ScanEach(context.Background(), "", "127.0.0.1", []int{port})
	took := time.Since(t0)
	if err != nil || len(r.Open) != 1 || r.Open[0].Service != "" {
		t.Fatalf("%+v %v", r, err)
	}
	// One wait per protocol would take 21 of 250 ms and more.
	if took > 3*time.Second {
		t.Errorf("took %v: the ladder is asked one protocol at a time", took)
	}
	if n := int(takes.Load()); n > 1+maxProbes || n < 20 {
		t.Errorf("%d connects counted, want the whole ladder within %d", n, 1+maxProbes)
	}
	l.Close()
	n := 0
	ledger.Read(path, func(e ledger.Entry) error {
		if e.Kind == "tcp" {
			n++
		}
		return nil
	})
	if n != int(takes.Load()) {
		t.Errorf("%d ledger entries, %d connects counted", n, takes.Load())
	}
}

// A HEAD that stays unanswered is waited on with the handshake and the
// ladder asked beside it, so a service that only answers its own protocol is
// found long before the HEAD's wait ends.
func TestSilentHeadDoesNotHoldUpTheLadder(t *testing.T) {
	port, _ := holder(t, func(first []byte, c net.Conn) {
		if bytes.HasPrefix(first, []byte("version")) {
			c.Write([]byte("VERSION 1.6.9\r\n"))
		}
	})
	var takes atomic.Int32
	s := &Scanner{Banner: 100 * time.Millisecond, Timeout: time.Second, Take: func() error { takes.Add(1); return nil }}
	t0 := time.Now()
	r, err := s.ScanEach(context.Background(), "", "127.0.0.1", []int{port})
	took := time.Since(t0)
	if err != nil || len(r.Open) != 1 || r.Open[0].Service != "memcached" || r.Open[0].Version != "1.6.9" {
		t.Fatalf("%+v %v", r, err)
	}
	// The HEAD's wait (1.1 s), the handshake's (1 s) and three silent
	// protocols (0.5 s each) one after another come to more than 3.5 s.
	if took > 2400*time.Millisecond {
		t.Errorf("took %v", took)
	}
	if n := int(takes.Load()); n > 1+maxProbes {
		t.Errorf("%d connects, bound %d", n, 1+maxProbes)
	}
}

// What the HEAD answers late is still what the port is: a slow web server
// is not taken for a protocol of the ladder that answered sooner.
func TestLateHeadAnswerStillGoesFirst(t *testing.T) {
	port, _ := holder(t, func(first []byte, c net.Conn) {
		switch {
		case bytes.HasPrefix(first, []byte("HEAD")):
			time.Sleep(700 * time.Millisecond)
			c.Write([]byte("HTTP/1.0 200 OK\r\nServer: slowhttp/2.1\r\n\r\n"))
		case bytes.HasPrefix(first, []byte("version")):
			c.Write([]byte("VERSION 1.6.9\r\n"))
		}
	})
	s := &Scanner{Banner: 100 * time.Millisecond, Timeout: time.Second, Take: func() error { return nil }}
	r, err := s.ScanEach(context.Background(), "", "127.0.0.1", []int{port})
	if err != nil || len(r.Open) != 1 {
		t.Fatalf("%+v %v", r, err)
	}
	if o := r.Open[0]; o.Service != "http" || o.Product != "slowhttp" || o.Version != "2.1" {
		t.Errorf("%+v", o)
	}
}

// Of two protocols of the ladder that both answer, the one that comes first
// in the list is the port's, whichever answers sooner.
func TestLadderKeepsItsOrderWhenAWindowAnswersOutOfOrder(t *testing.T) {
	port := listen(t, func(c net.Conn) {
		buf := make([]byte, 4096)
		n, _ := c.Read(buf)
		switch {
		case bytes.HasPrefix(buf[:n], []byte("INFO")):
			time.Sleep(200 * time.Millisecond)
			c.Write([]byte("$31\r\n# Server\r\nredis_version:6.2.1\r\n\r\n"))
		case bytes.HasPrefix(buf[:n], []byte{0, 0, 0, 8, 0, 1, 0, 0}):
			c.Write([]byte("EFATAL:  unsupported frontend protocol 1.0: server supports 3.0 to 3.0\n\x00"))
		}
		time.Sleep(100 * time.Millisecond)
	})
	s := &Scanner{Banner: 100 * time.Millisecond, Timeout: time.Second, Take: func() error { return nil }}
	r, err := s.ScanEach(context.Background(), "", "127.0.0.1", []int{port})
	if err != nil || len(r.Open) != 1 {
		t.Fatalf("%+v %v", r, err)
	}
	if o := r.Open[0]; o.Service != "redis" || o.Product != "Redis" || o.Version != "6.2.1" {
		t.Errorf("%+v", o)
	}
}

// The probes beside each other are taken from the scan's workers: with one
// worker they come one at a time, with the default several are open at once.
func TestIdentificationWidthFollowsTheFreeWorkers(t *testing.T) {
	scan := func(workers int) int32 {
		port, maxOpen := holder(t, nil)
		s := &Scanner{Workers: workers, Banner: 20 * time.Millisecond, Timeout: 100 * time.Millisecond, Take: func() error { return nil }}
		if _, err := s.ScanEach(context.Background(), "", "127.0.0.1", []int{port}); err != nil {
			t.Fatal(err)
		}
		return maxOpen.Load()
	}
	if n := scan(1); n > 3 { // the port's own, a probe, and one whose close the listener has not seen yet
		t.Errorf("one worker had %d connections open at once, want the port's own and one probe", n)
	}
	if n := scan(0); n < 6 {
		t.Errorf("the default had %d connections open at once, want the ladder asked several at a time", n)
	}
}
