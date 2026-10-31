//go:build !linux

package egress

import "net"

// listenAnySource opens a UDP socket that is not connected to the host,
// since a TFTP server answers from a port of its own. Without Linux's
// IP_RECVERR an ICMP error does not reach it: a closed port reads
// open|filtered.
func listenAnySource(to *net.UDPAddr) (*net.UDPConn, error) {
	network := "udp4"
	if to.IP.To4() == nil {
		network = "udp6"
	}
	return net.ListenUDP(network, nil)
}
