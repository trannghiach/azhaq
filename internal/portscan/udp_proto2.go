package portscan

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"regexp"
	"strings"
)

// tftpRead is a read request (RFC 1350, 5) for a file that does not exist:
// a TFTP server answers with an ERROR packet, which proves it is one.
func tftpRead() []byte {
	return append([]byte{0, 1}, "azhaq-no-such-file\x00octet\x00"...)
}

func parseTFTP(r, _ []byte) (udpInfo, bool) {
	if len(r) < 5 || r[0] != 0 || r[1] != 5 || r[2] != 0 || r[3] > 8 || r[len(r)-1] != 0 {
		return udpInfo{}, false
	}
	return udpInfo{service: "tftp", banner: "tftp error " + fmt.Sprint(r[3]) + ": " + printable(r[4:])}, true
}

// rpcDump is a call of the portmapper's DUMP procedure (RFC 1833, 3.1;
// RFC 5531 for the message format): AUTH_NONE, no arguments.
func rpcDump() []byte {
	b := append(randBytes(4), 0, 0, 0, 0) // xid, CALL
	for _, v := range []uint32{2, 100000, 2, 4, 0, 0, 0, 0} {
		b = binary.BigEndian.AppendUint32(b, v) // rpc version, program, version, procedure, two AUTH_NONE
	}
	return b
}

var rpcPrograms = map[uint32]string{
	100000: "portmapper", 100003: "nfs", 100005: "mountd", 100021: "nlockmgr", 100024: "status",
	100011: "rquotad", 100227: "nfs_acl", 100007: "ypbind", 100004: "ypserv",
}

func parseRPCBind(r, sent []byte) (udpInfo, bool) {
	if len(r) < 24 || !bytes.Equal(r[:4], sent[:4]) || binary.BigEndian.Uint32(r[4:]) != 1 ||
		binary.BigEndian.Uint32(r[8:]) != 0 || binary.BigEndian.Uint32(r[20:]) != 0 {
		return udpInfo{}, false
	}
	info := udpInfo{service: "rpcbind", banner: "rpcbind"}
	seen := map[string]bool{}
	var names []string
	for p := r[24:]; len(p) >= 20 && binary.BigEndian.Uint32(p) == 1; p = p[20:] {
		prog := binary.BigEndian.Uint32(p[4:])
		n := rpcPrograms[prog]
		if n == "" {
			n = fmt.Sprint(prog)
		}
		if !seen[n] {
			seen[n] = true
			names = append(names, n)
		}
	}
	if len(names) > 0 {
		info.banner = "rpcbind: " + strings.Join(names[:min(len(names), 8)], ", ")
	}
	return info, true
}

var sqlVersionRe = regexp.MustCompile(`(?i)Version;(\d+(?:\.\d+)+)`)

// parseSQLBrowser reads SVR_RESP of the SQL Server Browser ([MS-SQLR] 2.2.2).
func parseSQLBrowser(r, _ []byte) (udpInfo, bool) {
	if len(r) < 3 || r[0] != 5 || int(binary.LittleEndian.Uint16(r[1:])) != len(r)-3 {
		return udpInfo{}, false
	}
	info := udpInfo{service: "mssql-browser", product: "Microsoft SQL Server Browser", banner: printable(r[3:])}
	if m := sqlVersionRe.FindSubmatch(r); m != nil {
		info.product, info.version = "Microsoft SQL Server", string(m[1])
	}
	return info, true
}

func parseSIP(r, _ []byte) (udpInfo, bool) {
	var o Open
	if !sipRead(r, &o) {
		return udpInfo{}, false
	}
	return udpInfo{service: "sip", product: o.Product, version: o.Version, banner: o.Banner}, true
}

// parseNATPMP reads the answer to a public-address request (RFC 6886, 3.2).
func parseNATPMP(r, _ []byte) (udpInfo, bool) {
	if len(r) != 12 || r[0] != 0 || r[1] != 128 {
		return udpInfo{}, false
	}
	return udpInfo{service: "nat-pmp", banner: fmt.Sprintf("nat-pmp result %d", binary.BigEndian.Uint16(r[2:]))}, true
}

// parseUbiquiti reads a discovery answer (version 1: a type-length-value
// list of the device's name, model and firmware).
func parseUbiquiti(r, _ []byte) (udpInfo, bool) {
	if len(r) < 4 || r[0] != 1 || r[1] != 0 || int(binary.BigEndian.Uint16(r[2:])) != len(r)-4 {
		return udpInfo{}, false
	}
	info := udpInfo{service: "ubiquiti-discovery", product: "Ubiquiti"}
	var name, model string
	for t := r[4:]; len(t) >= 3; {
		n := int(binary.BigEndian.Uint16(t[1:]))
		if len(t) < 3+n {
			break
		}
		v := printable(t[3 : 3+n])
		switch t[0] {
		case 0x0b:
			name = v
		case 0x14, 0x0c:
			if model == "" || t[0] == 0x14 {
				model = v
			}
		case 0x03:
			info.version = v
		}
		t = t[3+n:]
	}
	info.banner = strings.TrimSpace("ubiquiti " + model + " " + name)
	return info, true
}

// rmcpPing is an ASF presence ping in an RMCP message (DMTF DSP0114).
func rmcpPing() []byte {
	return []byte{6, 0, 0xff, 6, 0, 0, 0x11, 0xbe, 0x80, 0, 0, 0}
}

func parseRMCP(r, _ []byte) (udpInfo, bool) {
	if len(r) < 12 || r[0] != 6 || r[3] != 6 || !bytes.Equal(r[4:8], []byte{0, 0, 0x11, 0xbe}) || r[8] != 0x40 {
		return udpInfo{}, false
	}
	return udpInfo{service: "asf-rmcp", banner: "rmcp presence pong"}, true
}
