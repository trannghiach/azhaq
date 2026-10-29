package portscan

import (
	"context"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/trannghiach/azhaq/internal/ledger"
)

// Every connect the scanner makes is one ledger entry: the count its Take
// hook saw and the ports of the entries agree.
func TestEveryConnectIsRecorded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "l.jsonl")
	l, err := ledger.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ledger.Use(l)
	defer ledger.Use(nil)

	var accepted atomic.Int32
	var ports []int
	for i := 0; i < 3; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		ports = append(ports, ln.Addr().(*net.TCPAddr).Port)
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				accepted.Add(1)
				c.Write([]byte("SSH-2.0-test\r\n")) // speaks first: no HTTP probe follows
				c.Close()
			}
		}()
	}
	for p := 1; p <= 60; p++ { // closed ports, most of them
		ports = append(ports, p)
	}
	var takes atomic.Int32
	s := &Scanner{Take: func() error { takes.Add(1); return nil }}
	if _, err := s.ScanEach(context.Background(), "localhost", "127.0.0.1", ports); err != nil {
		t.Fatal(err)
	}
	l.Close()
	got := 0
	if err := ledger.Read(path, func(e ledger.Entry) error {
		if e.Kind == "tcp" && e.Host == "localhost" {
			got++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got != int(takes.Load()) || got != len(ports) {
		t.Fatalf("ledger has %d tcp entries, the scanner took %d, %d ports were given", got, takes.Load(), len(ports))
	}
	if accepted.Load() != 3 {
		t.Fatalf("the listeners accepted %d connections, want 3", accepted.Load())
	}
}
