//go:build !linux

package browser

import "net"

// peers cannot tell which process a loopback connection comes from here:
// the guard relays for any local process, to hosts in the scope, while
// its Chrome runs.
type peers struct{}

func (*peers) set(int) {}

func (*peers) owns(net.Conn) bool { return true }
