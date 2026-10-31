package portscan

import (
	"context"
	"net"
	"strconv"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// fullListener is a listener whose accept queue is full: Linux drops the
// SYN of the next connect until something accepts. drain accepts what is
// queued, so the next connect gets in.
func fullListener(t *testing.T) (port int, drain func()) {
	t.Helper()
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { syscall.Close(fd) })
	if err := syscall.Bind(fd, &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Skip(err)
	}
	if err := syscall.Listen(fd, 0); err != nil {
		t.Skip(err)
	}
	sa, _ := syscall.Getsockname(fd)
	port = sa.(*syscall.SockaddrInet4).Port
	// Connect until one times out: the queue is full.
	var held []net.Conn
	t.Cleanup(func() {
		for _, c := range held {
			c.Close()
		}
	})
	for i := 0; ; i++ {
		c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 150*time.Millisecond)
		if err != nil {
			break
		}
		held = append(held, c)
		if i == 8 {
			t.Skip("the accept queue does not fill on this kernel")
		}
	}
	return port, func() {
		_ = syscall.SetNonblock(fd, true)
		for {
			nfd, _, err := syscall.Accept(fd)
			if err != nil {
				return
			}
			syscall.Close(nfd)
		}
	}
}

// A port whose connect timed out because its accept queue was full is asked
// again after the others, once the queue had time to drain, and that connect
// is counted like any other.
func TestTimedOutConnectIsAskedAgainAfterTheQueueDrains(t *testing.T) {
	port, drain := fullListener(t)
	var takes atomic.Int32
	s := &Scanner{Detect: DetectNone, Timeout: 400 * time.Millisecond, Take: func() error { takes.Add(1); return nil }}
	time.AfterFunc(600*time.Millisecond, drain)
	r, err := s.ScanEach(context.Background(), "", "127.0.0.1", []int{port})
	if err != nil || len(r.Open) != 1 || r.Open[0].Port != port || len(r.Silent) != 0 {
		t.Fatalf("open %+v silent %v, %v", r.Open, r.Silent, err)
	}
	if takes.Load() != 2 {
		t.Errorf("%d connects counted, want 2 (the first and the second ask)", takes.Load())
	}
}
