package portscan

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

func init() {
	register(
		// Telnet: the option negotiation a server opens with (RFC 854/855).
		&protocol{name: "telnet", passive: true, read: telnetRead},
		// VNC: the ProtocolVersion message of the RFB protocol (RFC 6143, 7.1.1).
		&protocol{name: "vnc", passive: true, read: vncRead},
		// IRC: the NOTICE AUTH or PING a server opens with (RFC 2812, 3.1, 3.7.2).
		&protocol{name: "irc", passive: true, read: ircRead},
		// NNTP: the 200 or 201 greeting (RFC 3977, 5.1).
		&protocol{name: "nntp", passive: true, read: nntpRead},
		// ManageSieve: the capability list sent on connect (RFC 5804, 1.2).
		&protocol{name: "sieve", passive: true, read: sieveRead},
		// RTSP: OPTIONS * (RFC 2326, 10.1).
		&protocol{name: "rtsp", ports: []int{554, 8554}, passive: true,
			request: func(target) []byte { return []byte("OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n") },
			read:    rtspRead},
		// SIP: OPTIONS (RFC 3261, 11).
		&protocol{name: "sip", ports: []int{5060}, tlsPorts: []int{5061}, passive: true,
			request: func(t target) []byte { return sipOptions(t.host, "TCP") },
			read:    sipRead},
		// SOCKS5: the method selection (RFC 1928, 3).
		&protocol{name: "socks5", ports: []int{1080},
			request: func(target) []byte { return []byte{5, 1, 0} },
			frame:   func(b []byte) int { return 2 }, read: socksRead},
		// SMB2: NEGOTIATE with no session ([MS-SMB2] 2.2.3, 2.2.4).
		&protocol{name: "smb", ports: []int{445},
			request: func(target) []byte { return smb2Negotiate() },
			frame:   nbssFrame, read: smbRead},
		// NetBIOS session service: a session request to *SMBSERVER (RFC 1002, 4.3.2).
		&protocol{name: "netbios-ssn", ports: []int{139},
			request: func(target) []byte { return nbssRequest() },
			frame:   nbssFrame, read: nbssRead},
		// RDP: the X.224 connection request with a negotiation request
		// ([MS-RDPBCGR] 2.2.1.1).
		&protocol{name: "rdp", ports: []int{3389},
			request: func(target) []byte { return rdpRequest() },
			frame:   tpktFrame, read: rdpRead},
		// X11: the connection setup with no authorization (X Window System
		// Protocol, Connection Setup).
		&protocol{name: "x11", ports: []int{6000, 6001, 6002},
			request: func(target) []byte { return []byte{'l', 0, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
			frame:   x11Frame, read: x11Read},
		// Finger: a query for a name that does not exist (RFC 1288, 2.3).
		&protocol{name: "finger", ports: []int{79},
			request: func(target) []byte { return []byte("azhaq-no-such-user\r\n") },
			read:    fingerRead},
		// Gopher: an empty selector (RFC 1436, 3).
		&protocol{name: "gopher", ports: []int{70},
			request: func(target) []byte { return []byte("\r\n") },
			read:    gopherRead},
		// JDWP: the handshake, which a debug port answers with itself
		// (Java Debug Wire Protocol, Handshake).
		&protocol{name: "jdwp", ports: []int{5005, 8787},
			request: func(target) []byte { return []byte("JDWP-Handshake") },
			read: func(r []byte, o *Open) bool {
				if string(r) != "JDWP-Handshake" {
					return false
				}
				o.Service, o.Product, o.Banner = "jdwp", "Java Debug Wire Protocol", "JDWP-Handshake"
				return true
			}},
		// AFP: the DSI GetStatus request, no login (Apple Filing Protocol
		// Programming Guide, DSI).
		&protocol{name: "afp", ports: []int{548},
			request: func(target) []byte { return []byte{0, 3, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
			frame:   afpFrame, read: afpRead},
		// Minecraft Java Edition: handshake and status request (Server List Ping).
		&protocol{name: "minecraft", ports: []int{25565},
			request: minecraftPing, frame: mcFrame, read: minecraftRead},
	)
}

func telnetRead(r []byte, o *Open) bool {
	if len(r) < 3 || r[0] != 0xff || r[1] < 251 || r[1] > 254 {
		return false
	}
	var text []byte
	for i := 0; i < len(r); {
		if r[i] == 0xff && i+2 < len(r) {
			i += 3
			continue
		}
		text = append(text, r[i])
		i++
	}
	o.Service, o.Banner = "telnet", printable(text)
	if o.Banner == "" || o.Banner == "(binary)" {
		o.Banner = "telnet option negotiation"
	}
	return true
}

func vncRead(r []byte, o *Open) bool {
	m := rfbRe.FindSubmatch(r)
	if m == nil || len(r) < 11 {
		return false
	}
	maj, _ := strconv.Atoi(string(m[1]))
	min, _ := strconv.Atoi(string(m[2]))
	o.Service, o.Product, o.Version, o.Banner = "vnc", "VNC", fmt.Sprintf("%d.%d", maj, min), printable(r)
	return true
}

var (
	ircRe  = regexp.MustCompile(`^(?::\S+ NOTICE (?:AUTH|\*) :|PING :\S|ERROR :(?:Closing Link|Too many)|:\S+ 0?0[1-5] )`)
	innRe  = regexp.MustCompile(`(?i)\bINN (\d[\w.]*)`)
	hdrSrv = regexp.MustCompile(`(?im)^(?:server|user-agent):[ \t]*([^\r\n]+)`)
)

func ircRead(r []byte, o *Open) bool {
	if !ircRe.Match(r) {
		return false
	}
	o.Service, o.Banner = "irc", printable(r)
	return true
}

func nntpRead(r []byte, o *Open) bool {
	if len(r) < 5 || r[0] != '2' || r[1] != '0' || r[2] != '0' && r[2] != '1' || r[3] != ' ' || !isText(r) {
		return false
	}
	o.Service, o.Banner = "nntp", printable(r)
	if m := innRe.FindSubmatch(r); m != nil {
		o.Product, o.Version = "INN", string(m[1])
	}
	return true
}

var sieveRe = regexp.MustCompile(`^"IMPLEMENTATION" "([^"]+)"`)

func sieveRead(r []byte, o *Open) bool {
	m := sieveRe.FindSubmatch(r)
	if m == nil {
		return false
	}
	o.Service, o.Product, o.Banner = "sieve", string(m[1]), printable(r)
	return true
}

var rtspRe = regexp.MustCompile(`^RTSP/\d\.\d \d{3}`)

// headerProduct reads the Server or User-Agent header of a text answer.
func headerProduct(r []byte) (product, version string) {
	m := hdrSrv.FindSubmatch(r)
	if m == nil {
		return "", ""
	}
	v := strings.TrimSpace(string(m[1]))
	if p, ver := serverProduct(v); p != "" && ver != "" {
		return p, ver
	}
	if i := strings.LastIndexByte(v, ' '); i > 0 && genVerRe.MatchString(v[i+1:]) {
		return strings.TrimSpace(v[:i]), genVerRe.FindStringSubmatch(v[i+1:])[1]
	}
	return printable([]byte(v)), ""
}

func rtspRead(r []byte, o *Open) bool {
	if !rtspRe.Match(r) {
		return false
	}
	o.Service, o.Banner = "rtsp", printable(r)
	o.Product, o.Version = headerProduct(r)
	return true
}

func sipOptions(host, transport string) []byte {
	return []byte("OPTIONS sip:probe@" + host + " SIP/2.0\r\n" +
		"Via: SIP/2.0/" + transport + " azhaq.invalid:5060;branch=z9hG4bKazhaq1\r\n" +
		"Max-Forwards: 70\r\nFrom: <sip:azhaq@azhaq.invalid>;tag=azhaq\r\nTo: <sip:probe@" + host + ">\r\n" +
		"Call-ID: azhaq-1@azhaq.invalid\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n")
}

var sipRe = regexp.MustCompile(`^SIP/2\.0 \d{3}`)

func sipRead(r []byte, o *Open) bool {
	if !sipRe.Match(r) {
		return false
	}
	o.Service, o.Banner = "sip", printable(r)
	o.Product, o.Version = headerProduct(r)
	return true
}

func socksRead(r []byte, o *Open) bool {
	if len(r) != 2 || r[0] != 5 || r[1] > 2 && r[1] != 0xff {
		return false
	}
	o.Service, o.Banner = "socks5", "socks5 method "+strconv.Itoa(int(r[1]))
	if r[1] == 0xff {
		o.Banner = "socks5, no acceptable method"
	}
	return true
}

// smb2Negotiate is a NEGOTIATE request for dialects 2.0.2 to 3.1.1, with the
// pre-authentication integrity context 3.1.1 requires, in a NetBIOS session
// message.
func smb2Negotiate() []byte {
	dialects := []uint16{0x0202, 0x0210, 0x0300, 0x0302, 0x0311}
	hdr := make([]byte, 64)
	copy(hdr, "\xfeSMB")
	binary.LittleEndian.PutUint16(hdr[4:], 64)
	binary.LittleEndian.PutUint16(hdr[14:], 1) // credit request
	off := 64 + 36 + 2*len(dialects)
	pad := (8 - off%8) % 8
	body := make([]byte, 36, 36+2*len(dialects)+pad)
	binary.LittleEndian.PutUint16(body, 36)
	binary.LittleEndian.PutUint16(body[2:], uint16(len(dialects)))
	binary.LittleEndian.PutUint16(body[4:], 1) // signing enabled
	copy(body[12:28], randBytes(16))
	binary.LittleEndian.PutUint32(body[28:], uint32(off+pad)) // negotiate context offset
	binary.LittleEndian.PutUint16(body[32:], 1)
	for _, d := range dialects {
		body = binary.LittleEndian.AppendUint16(body, d)
	}
	body = append(body, make([]byte, pad)...)
	// PREAUTH_INTEGRITY_CAPABILITIES: SHA-512 and a salt.
	ctx := binary.LittleEndian.AppendUint16(nil, 1)
	ctx = binary.LittleEndian.AppendUint16(ctx, 2+2+2+32)
	ctx = append(ctx, 0, 0, 0, 0)
	ctx = binary.LittleEndian.AppendUint16(ctx, 1)
	ctx = binary.LittleEndian.AppendUint16(ctx, 32)
	ctx = binary.LittleEndian.AppendUint16(ctx, 1)
	ctx = append(ctx, randBytes(32)...)
	pkt := append(append(hdr, body...), ctx...)
	return append([]byte{0, byte(len(pkt) >> 16), byte(len(pkt) >> 8), byte(len(pkt))}, pkt...)
}

// nbssFrame frames a NetBIOS session message: a type, then a 17-bit length.
func nbssFrame(b []byte) int {
	if len(b) < 4 {
		return 0
	}
	if b[0] != 0 && b[0] < 0x81 || b[0] > 0x85 {
		return -1
	}
	return 4 + (int(b[1]&1)<<16 | int(b[2])<<8 | int(b[3]))
}

var smbDialects = map[uint16]string{0x0202: "2.0.2", 0x0210: "2.1", 0x0300: "3.0", 0x0302: "3.0.2", 0x0311: "3.1.1", 0x02ff: "2"}

func smbRead(r []byte, o *Open) bool {
	if len(r) < 4+64+64 || r[0] != 0 || !bytes.Equal(r[4:8], []byte("\xfeSMB")) ||
		binary.LittleEndian.Uint32(r[12:]) != 0 || binary.LittleEndian.Uint16(r[16:]) != 0 {
		return false
	}
	b := r[4+64:]
	if binary.LittleEndian.Uint16(b) != 65 {
		return false
	}
	dialect := smbDialects[binary.LittleEndian.Uint16(b[4:])]
	if dialect == "" {
		dialect = fmt.Sprintf("0x%04x", binary.LittleEndian.Uint16(b[4:]))
	}
	signing := "signing enabled"
	if b[2]&2 != 0 {
		signing = "signing required"
	}
	o.Service = "smb"
	o.Banner = "smb " + dialect + ", " + signing
	// Samba reports the server start time as zero; Windows gives it.
	if binary.LittleEndian.Uint64(b[48:]) == 0 {
		o.Product = "Samba smbd"
	}
	return true
}

// nbssRequest is a session request, called name *SMBSERVER, calling name AZHAQ.
func nbssRequest() []byte {
	enc := func(name string, suffix byte) []byte {
		b := make([]byte, 0, 34)
		b = append(b, 0x20)
		n := []byte(name + strings.Repeat(" ", 15-len(name)))
		n = append(n, suffix)
		for _, c := range n {
			b = append(b, 'A'+c>>4, 'A'+c&0xf)
		}
		return append(b, 0)
	}
	body := append(enc("*SMBSERVER", 0x20), enc("AZHAQ", 0)...)
	return append([]byte{0x81, 0, 0, byte(len(body))}, body...)
}

func nbssRead(r []byte, o *Open) bool {
	if len(r) < 4 || r[1] != 0 || r[2] != 0 {
		return false
	}
	switch {
	case r[0] == 0x82 && r[3] == 0:
		o.Banner = "netbios session accepted"
	case r[0] == 0x83 && r[3] == 1:
		o.Banner = "netbios session refused"
	default:
		return false
	}
	o.Service = "netbios-ssn"
	return true
}

// rdpRequest is a TPKT with an X.224 connection request asking for TLS or
// CredSSP.
func rdpRequest() []byte {
	return []byte{3, 0, 0, 0x13, 0x0e, 0xe0, 0, 0, 0, 0, 0, 1, 0, 8, 0, 3, 0, 0, 0}
}

func tpktFrame(b []byte) int {
	if len(b) < 4 {
		return 0
	}
	if b[0] != 3 || b[1] != 0 {
		return -1
	}
	return int(binary.BigEndian.Uint16(b[2:]))
}

var rdpProtocols = map[uint32]string{0: "standard RDP security", 1: "TLS", 2: "CredSSP", 4: "RDSTLS", 8: "CredSSP with early user authorization"}

func rdpRead(r []byte, o *Open) bool {
	if len(r) < 11 || r[0] != 3 || r[1] != 0 || int(binary.BigEndian.Uint16(r[2:])) != len(r) || r[5] != 0xd0 {
		return false
	}
	o.Service, o.Banner = "rdp", "rdp connection confirm"
	if len(r) >= 19 && r[11] == 2 {
		o.Banner = "rdp, " + rdpProtocols[binary.LittleEndian.Uint32(r[15:])]
	} else if len(r) >= 19 && r[11] == 3 {
		o.Banner = "rdp, negotiation failure"
	}
	return true
}

func x11Frame(b []byte) int {
	if len(b) < 8 {
		return 0
	}
	if b[0] > 2 {
		return -1
	}
	return 8 + 4*int(binary.LittleEndian.Uint16(b[6:]))
}

func x11Read(r []byte, o *Open) bool {
	if len(r) < 8 || r[0] > 2 || binary.LittleEndian.Uint16(r[2:]) != 11 || len(r) != x11Frame(r) {
		return false
	}
	o.Service = "x11"
	switch r[0] {
	case 0:
		n := int(r[1])
		if 8+n > len(r) {
			return false
		}
		o.Banner = "x11 refused: " + printable(r[8:8+n])
	case 1:
		o.Banner = "x11 connection accepted"
		if len(r) >= 40 {
			n := int(binary.LittleEndian.Uint16(r[24:]))
			if 40+n <= len(r) {
				o.Product = printable(r[40 : 40+n])
				o.Version = strconv.FormatUint(uint64(binary.LittleEndian.Uint32(r[8:])), 10)
			}
		}
	default:
		o.Banner = "x11 wants authorization"
	}
	return true
}

var fingerRe = regexp.MustCompile(`(?i)no such user|not found|login\b|unknown user|finger\b|name\b.*\bhome\b`)

func fingerRead(r []byte, o *Open) bool {
	if !isText(r) || !fingerRe.Match(r) {
		return false
	}
	o.Service, o.Banner = "finger", printable(r)
	return true
}

var gopherRe = regexp.MustCompile(`(?m)^[0-9iIhgs+3][^\t\r\n]*\t[^\t\r\n]*\t[^\t\r\n]*\t\d+`)

func gopherRead(r []byte, o *Open) bool {
	if !gopherRe.Match(r) {
		return false
	}
	o.Service, o.Banner = "gopher", printable(r)
	return true
}

func afpFrame(b []byte) int {
	if len(b) < 16 {
		return 0
	}
	if b[0] != 1 || b[1] != 3 {
		return -1
	}
	return 16 + int(binary.BigEndian.Uint32(b[8:]))
}

func afpRead(r []byte, o *Open) bool {
	if len(r) < 16+11 || r[0] != 1 || r[1] != 3 {
		return false
	}
	b := r[16:]
	o.Service = "afp"
	if mo := int(binary.BigEndian.Uint16(b)); mo > 0 && mo < len(b) && mo+1+int(b[mo]) <= len(b) {
		machine := string(b[mo+1 : mo+1+int(b[mo])])
		o.Banner = "afp, " + printable([]byte(machine))
		if m := regexp.MustCompile(`^Netatalk(\d[\w.]*)`).FindStringSubmatch(machine); m != nil {
			o.Product, o.Version = "Netatalk", m[1]
		}
	}
	return true
}

func varint(n int) []byte {
	var b []byte
	for {
		c := byte(n & 0x7f)
		n >>= 7
		if n != 0 {
			b = append(b, c|0x80)
			continue
		}
		return append(b, c)
	}
}

// readVarint reads a Minecraft VarInt off b.
func readVarint(b []byte) (n, size int) {
	for i := 0; i < 5 && i < len(b); i++ {
		n |= int(b[i]&0x7f) << (7 * i)
		if b[i]&0x80 == 0 {
			return n, i + 1
		}
	}
	return 0, 0
}

func minecraftPing(t target) []byte {
	pkt := append([]byte{0}, varint(765)...)
	pkt = append(pkt, varint(len(t.host))...)
	pkt = append(pkt, t.host...)
	pkt = binary.BigEndian.AppendUint16(pkt, uint16(t.port))
	pkt = append(pkt, 1)
	out := append(varint(len(pkt)), pkt...)
	return append(out, 1, 0) // status request
}

func mcFrame(b []byte) int {
	n, size := readVarint(b)
	if size == 0 {
		return 0
	}
	if n > 1<<16 {
		return -1
	}
	return size + n
}

func minecraftRead(r []byte, o *Open) bool {
	n, size := readVarint(r)
	if size == 0 || size+n != len(r) || r[size] != 0 {
		return false
	}
	l, ls := readVarint(r[size+1:])
	if ls == 0 || size+1+ls+l > len(r) {
		return false
	}
	var doc struct {
		Version struct {
			Name string `json:"name"`
		} `json:"version"`
	}
	if json.Unmarshal(r[size+1+ls:size+1+ls+l], &doc) != nil || doc.Version.Name == "" {
		return false
	}
	o.Service, o.Product, o.Banner = "minecraft", "Minecraft", "minecraft "+doc.Version.Name
	if v := vendorVerRe.FindString(doc.Version.Name); v != "" {
		o.Version = v
	}
	return true
}
