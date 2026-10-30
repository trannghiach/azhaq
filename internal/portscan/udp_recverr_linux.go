//go:build linux

package portscan

import (
	"net"
	"syscall"
)

// listenAnySource opens a UDP socket that is not connected to the host,
// since a TFTP server answers from a port of its own, and asks the kernel
// to hand it ICMP errors (IP_RECVERR) as a connected socket would get
// them, so a closed port is still told from a silent one.
func listenAnySource(to *net.UDPAddr) (*net.UDPConn, error) {
	network, level, opt := "udp4", syscall.IPPROTO_IP, syscall.IP_RECVERR
	if to.IP.To4() == nil {
		network, level, opt = "udp6", syscall.IPPROTO_IPV6, syscall.IPV6_RECVERR
	}
	conn, err := net.ListenUDP(network, nil)
	if err != nil {
		return nil, err
	}
	if rc, err := conn.SyscallConn(); err == nil {
		_ = rc.Control(func(fd uintptr) { _ = syscall.SetsockoptInt(int(fd), level, opt, 1) })
	}
	return conn, nil
}
