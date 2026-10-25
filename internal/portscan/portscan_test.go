package portscan

import (
	"context"
	"net"
	"reflect"
	"testing"
	"time"
)

func TestPorts(t *testing.T) {
	got, err := Ports("443,22,8000-8002,22")
	if err != nil || !reflect.DeepEqual(got, []int{22, 443, 8000, 8001, 8002}) {
		t.Fatalf("%v %v", got, err)
	}
	for spec, n := range map[string]int{"top-100": 100, "top-1000": 1000, "full": 65535} {
		if p, err := Ports(spec); err != nil || len(p) != n {
			t.Errorf("%s: %d ports, %v", spec, len(p), err)
		}
	}
	for _, bad := range []string{"0", "70000", "90-80", "x"} {
		if _, err := Ports(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestScanAndBanner(t *testing.T) {
	ssh, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ssh.Close()
	go func() {
		for {
			c, err := ssh.Accept()
			if err != nil {
				return
			}
			c.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n"))
			c.Close()
		}
	}()
	silent, _ := net.Listen("tcp", "127.0.0.1:0")
	defer silent.Close()
	go func() {
		for {
			c, err := silent.Accept()
			if err != nil {
				return
			}
			time.Sleep(200 * time.Millisecond)
			c.Close()
		}
	}()
	closed, _ := net.Listen("tcp", "127.0.0.1:0")
	closedPort := closed.Addr().(*net.TCPAddr).Port
	closed.Close()
	sshPort := ssh.Addr().(*net.TCPAddr).Port
	silentPort := silent.Addr().(*net.TCPAddr).Port

	s := &Scanner{Rate: 1000, Banner: 100 * time.Millisecond}
	open, err := s.Scan(context.Background(), "127.0.0.1", []int{sshPort, silentPort, closedPort})
	if err != nil || len(open) != 2 {
		t.Fatalf("open %+v err %v", open, err)
	}
	for _, o := range open {
		if o.Port == sshPort && (o.Service != "ssh" || o.Banner != "SSH-2.0-OpenSSH_9.6" || o.Web()) {
			t.Errorf("ssh %+v", o)
		}
		if o.Port == silentPort && (o.Banner != "" || !o.Web()) {
			t.Errorf("silent %+v", o)
		}
	}
	if printable([]byte{0x50, 0x3e, 0xfa, 0x01, 0x9c, 0xda, 0x83, 0x40, 0xe0, 0x12}) != "(binary)" {
		t.Error("binary banner shown as text")
	}
}
