package egress

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
)

// peers is the processes of one Chrome: its browser process and those it
// started (the network service among them). A connection to the guard is
// theirs when the socket at its other end is one of their open files:
// found by its two ends in /proc/net/tcp, then among /proc/PID/fd.
type peers struct {
	mu   sync.Mutex
	root int   // the browser process; 0 until Chrome runs
	pids []int // root and the processes under it, the last that owned a connection first
}

func (p *peers) set(pid int) {
	p.mu.Lock()
	p.root, p.pids = pid, nil
	p.mu.Unlock()
}

// owns says whether c, accepted by the guard, comes from Chrome. A socket
// of another user's, or one another process holds, is refused. Where it
// cannot tell (a Chrome process whose files cannot be read, a confined
// Chrome, no /proc/net), it says yes, as off Linux.
func (p *peers) owns(c net.Conn) bool {
	from, ok1 := c.RemoteAddr().(*net.TCPAddr)
	to, ok2 := c.LocalAddr().(*net.TCPAddr)
	if !ok1 || !ok2 {
		return false
	}
	inode, uid, err := socketOf(from, to)
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, fs.ErrPermission) {
		return true
	}
	if err != nil || uid != os.Getuid() {
		return false
	}
	link := "socket:[" + strconv.FormatUint(inode, 10) + "]"
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.root == 0 {
		return false
	}
	for fresh := p.pids == nil; ; fresh = true {
		if fresh {
			p.pids = tree(p.root)
		}
		unreadable := false
		for i, pid := range p.pids {
			has, err := holds(pid, link)
			if has {
				p.pids[0], p.pids[i] = p.pids[i], p.pids[0]
				return true
			}
			unreadable = unreadable || errors.Is(err, fs.ErrPermission)
		}
		if fresh {
			return unreadable && !heldElsewhere(link, p.pids)
		}
	}
}

// heldElsewhere says whether a process other than chrome's holds link.
func heldElsewhere(link string, chrome []int) bool {
	ents, _ := os.ReadDir("/proc")
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || slices.Contains(chrome, pid) {
			continue
		}
		if has, _ := holds(pid, link); has {
			return true
		}
	}
	return false
}

// socketOf finds the socket whose local end is from and whose remote end
// is to: its inode, and the user it belongs to.
func socketOf(from, to *net.TCPAddr) (inode uint64, uid int, err error) {
	read := false
	for _, table := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		v6 := strings.HasSuffix(table, "6")
		local, remote := procAddr(from, v6), procAddr(to, v6)
		if local == "" || remote == "" {
			continue
		}
		raw, rerr := os.ReadFile(table)
		if rerr != nil {
			err = rerr
			continue
		}
		read = true
		sc := bufio.NewScanner(bytes.NewReader(raw))
		for sc.Scan() {
			// sl local_address rem_address st tx:rx tr:when retrnsmt uid timeout inode
			f := strings.Fields(sc.Text())
			if len(f) < 10 || !strings.EqualFold(f[1], local) || !strings.EqualFold(f[2], remote) {
				continue
			}
			uid, _ = strconv.Atoi(f[7])
			inode, _ = strconv.ParseUint(f[9], 10, 64)
			return inode, uid, nil
		}
	}
	if !read {
		return 0, 0, err
	}
	return 0, 0, errors.New("no such socket")
}

// procAddr is a as /proc/net/tcp writes it: the address as 32-bit words
// in the machine's byte order, the port in hex.
func procAddr(a *net.TCPAddr, v6 bool) string {
	ip := a.IP.To4()
	if v6 {
		ip = a.IP.To16()
	}
	if ip == nil {
		return ""
	}
	var s strings.Builder
	for i := 0; i < len(ip); i += 4 {
		fmt.Fprintf(&s, "%08X", binary.NativeEndian.Uint32(ip[i:i+4]))
	}
	fmt.Fprintf(&s, ":%04X", a.Port)
	return s.String()
}

// tree is root and the processes under it.
func tree(root int) []int {
	ents, _ := os.ReadDir("/proc")
	children := map[int][]int{}
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		stat, err := os.ReadFile("/proc/" + e.Name() + "/stat")
		if err != nil {
			continue
		}
		// pid (comm) state ppid …: comm may hold spaces and parentheses.
		i := bytes.LastIndexByte(stat, ')')
		if i < 0 {
			continue
		}
		f := strings.Fields(string(stat[i+1:]))
		if len(f) < 2 {
			continue
		}
		if ppid, err := strconv.Atoi(f[1]); err == nil {
			children[ppid] = append(children[ppid], pid)
		}
	}
	out := []int{root}
	for i := 0; i < len(out); i++ {
		out = append(out, children[out[i]]...)
	}
	return out
}

// holds says whether process pid has link (socket:[inode]) open.
func holds(pid int, link string) (bool, error) {
	dir := "/proc/" + strconv.Itoa(pid) + "/fd/"
	ents, err := os.ReadDir(dir)
	if err != nil {
		return false, err
	}
	for _, e := range ents {
		if l, err := os.Readlink(dir + e.Name()); err == nil && l == link {
			return true, nil
		}
	}
	return false, nil
}
