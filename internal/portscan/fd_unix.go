//go:build unix

package portscan

import "syscall"

// fdBudget is how many connections may be open at once: what the process's
// file limit leaves after the files azhaq keeps for itself.
func fdBudget() int {
	var l syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &l); err != nil || l.Cur == 0 {
		return 1000
	}
	return int(min(uint64(l.Cur), 1<<30)) - 256
}
