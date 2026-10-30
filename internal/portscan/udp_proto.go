package portscan

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

// udpInfo is what an answer in the protocol asked for says.
type udpInfo struct {
	service, product, version, banner string
}

// udpReq is the harmless request for a port and how to read its answer.
type udpReq struct {
	payload []byte
	parse   func(reply, sent []byte) (udpInfo, bool)
	// anySource: the answer comes from another port than the one asked
	// (TFTP's reply uses a fresh transfer id), so it is read on a socket
	// that is not connected.
	anySource bool
}

// udpRequest returns a standard discovery or version request of the
// protocol a port usually carries; an empty datagram for the others (the
// first pass of a scan asks those a DNS query instead).
func udpRequest(port int) udpReq {
	switch port {
	case 53:
		return udpReq{dnsQuery(), parseDNS, false}
	case 123:
		p := make([]byte, 48)
		p[0] = 0x1b // version 3, mode 3 (client)
		return udpReq{p, parseNTP, false}
	case 161:
		return udpReq{snmpGet(), parseSNMP, false}
	case 1900:
		return udpReq{[]byte("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n"), parseSSDP, false}
	case 5353:
		return udpReq{mdnsQuery(), parseMDNS, false}
	case 137:
		return udpReq{nbstat(), parseNBStat, false}
	case 500:
		return udpReq{ikeInit(false), parseIKE, false}
	case 4500:
		return udpReq{ikeInit(true), parseIKE, false}
	case 3478:
		return udpReq{stunBinding(), parseSTUN, false}
	case 11211:
		// UDP frame header: request id, sequence 0, one datagram, reserved.
		return udpReq{append([]byte{0, 1, 0, 0, 0, 1, 0, 0}, "version\r\n"...), parseMemcached, false}
	case 47808:
		// BVLC original-unicast-NPDU, NPDU v1 without routing, unconfirmed Who-Is.
		return udpReq{[]byte{0x81, 0x0a, 0x00, 0x08, 0x01, 0x00, 0x10, 0x08}, parseBACnet, false}
	case 5683:
		return udpReq{coapWellKnown(), parseCoAP, false}
	case 69:
		return udpReq{tftpRead(), parseTFTP, true}
	case 111:
		return udpReq{rpcDump(), parseRPCBind, false}
	case 1434:
		return udpReq{[]byte{3}, parseSQLBrowser, false} // CLNT_UCAST_EX
	case 5060:
		return udpReq{sipOptions("azhaq.invalid", "UDP"), parseSIP, false}
	case 5351:
		return udpReq{[]byte{0, 0}, parseNATPMP, false}
	case 10001:
		return udpReq{[]byte{1, 0, 0, 0}, parseUbiquiti, false}
	case 623:
		return udpReq{rmcpPing(), parseRMCP, false}
	}
	return udpReq{nil, func([]byte, []byte) (udpInfo, bool) { return udpInfo{}, false }, false}
}

// udpRequestHook lets a test choose the request of any port.
var udpRequestHook func(port int) (udpReq, bool)

// udpAsk is the request for the pass-th ask of a port (0 is the first), and
// false when there is none. A port with a protocol of its own is asked it
// twice (the second ask of 161 is SNMPv3 discovery, which an agent that
// wants a community string still answers); any other is asked DNS, then
// SNMP with the community public, then memcached's version, then an empty
// datagram.
func udpAsk(port, pass int) (udpReq, bool) {
	if udpRequestHook != nil {
		return udpRequestHook(port)
	}
	req := udpRequest(port)
	if len(req.payload) > 0 {
		switch {
		case pass == 1 && port == 161:
			return udpReq{snmpV3Discovery(), parseSNMP, false}, true
		case pass > 1:
			return udpReq{}, false
		}
		return req, true
	}
	switch pass {
	case 0:
		return udpReq{dnsQuery(), parseDNS, false}, true
	case 1:
		return udpReq{snmpGet(), parseSNMP, false}, true
	case 2:
		return udpRequest(11211), true
	case 3:
		return req, true
	}
	return udpReq{}, false
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// dnsQuery asks for the NS records of the root, as dig . NS does.
func dnsQuery() []byte {
	q := append(randBytes(2), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0)
	return append(q, 0, 0, 2, 0, 1)
}

func parseDNS(r, sent []byte) (udpInfo, bool) {
	if len(r) < 12 || !bytes.Equal(r[:2], sent[:2]) || r[2]&0x80 == 0 {
		return udpInfo{}, false
	}
	return udpInfo{service: "dns", banner: fmt.Sprintf("dns answer, rcode %d, %d records", r[3]&0x0f, binary.BigEndian.Uint16(r[6:8]))}, true
}

func parseNTP(r, _ []byte) (udpInfo, bool) {
	if len(r) < 48 || r[0]&7 != 4 { // mode 4: server
		return udpInfo{}, false
	}
	return udpInfo{service: "ntp", banner: fmt.Sprintf("ntp v%d stratum %d", r[0]>>3&7, r[1])}, true
}

// BER helpers for the one SNMP message.
func tlv(tag byte, parts ...[]byte) []byte {
	body := bytes.Join(parts, nil)
	out := []byte{tag}
	if len(body) < 128 {
		out = append(out, byte(len(body)))
	} else {
		out = append(out, 0x81, byte(len(body)))
	}
	return append(out, body...)
}

// snmpGet is a v1 GetRequest for sysDescr.0 with the community "public".
func snmpGet() []byte {
	oid := tlv(0x06, []byte{0x2b, 6, 1, 2, 1, 1, 1, 0})
	vb := tlv(0x30, tlv(0x30, oid, []byte{0x05, 0x00}))
	pdu := tlv(0xa0, tlv(0x02, randBytes(3)[:2]), tlv(0x02, []byte{0}), tlv(0x02, []byte{0}), vb)
	return tlv(0x30, tlv(0x02, []byte{0}), tlv(0x04, []byte("public")), pdu)
}

// berNext splits one TLV off b.
func berNext(b []byte) (tag byte, val, rest []byte, ok bool) {
	if len(b) < 2 {
		return 0, nil, nil, false
	}
	tag, n, off := b[0], int(b[1]), 2
	if n&0x80 != 0 {
		k := n & 0x7f
		if k == 0 || k > 2 || len(b) < 2+k {
			return 0, nil, nil, false
		}
		n = 0
		for _, c := range b[2 : 2+k] {
			n = n<<8 | int(c)
		}
		off = 2 + k
	}
	if len(b) < off+n {
		return 0, nil, nil, false
	}
	return tag, b[off : off+n], b[off+n:], true
}

func parseSNMP(r, _ []byte) (udpInfo, bool) {
	_, msg, _, ok := berNext(r)
	if !ok {
		return udpInfo{}, false
	}
	_, ver, rest, ok := berNext(msg) // version
	if !ok {
		return udpInfo{}, false
	}
	if len(ver) == 1 && ver[0] == 3 {
		return parseSNMPv3(rest)
	}
	_, _, rest, ok = berNext(rest) // community
	if !ok {
		return udpInfo{}, false
	}
	tag, pdu, _, ok := berNext(rest)
	if !ok || tag != 0xa2 { // GetResponse
		return udpInfo{}, false
	}
	for i := 0; i < 3; i++ { // request id, error status, error index
		if _, _, pdu, ok = berNext(pdu); !ok {
			return udpInfo{}, false
		}
	}
	_, list, _, ok := berNext(pdu)
	if !ok {
		return udpInfo{}, false
	}
	_, vb, _, ok := berNext(list)
	if !ok {
		return udpInfo{}, false
	}
	_, _, val, ok := berNext(vb) // the OID, then the value
	if !ok {
		return udpInfo{service: "snmp"}, true
	}
	info := udpInfo{service: "snmp"}
	if tag, s, _, ok := berNext(val); ok && tag == 0x04 {
		info.banner = printable(s)
		info.product, info.version = sysDescrProduct(info.banner)
	}
	return info, true
}

var (
	ciscoRe = regexp.MustCompile(`^Cisco IOS.*?Version (\d[\w.()]*)`)
	junosRe = regexp.MustCompile(`JUNOS (\d[\w.\-]*)`)
	linuxRe = regexp.MustCompile(`^Linux \S+ (\d+\.\d+[\w.\-+]*)`)
	winRe   = regexp.MustCompile(`Software: Windows`)
)

// sysDescrProduct names what a sysDescr.0 says it is: the operating system
// or firmware of the device (the agent's own name is not in it).
func sysDescrProduct(d string) (string, string) {
	switch {
	case ciscoRe.MatchString(d):
		return "Cisco IOS", ciscoRe.FindStringSubmatch(d)[1]
	case junosRe.MatchString(d):
		return "Juniper JUNOS", junosRe.FindStringSubmatch(d)[1]
	case linuxRe.MatchString(d):
		return "Linux", linuxRe.FindStringSubmatch(d)[1]
	case winRe.MatchString(d):
		return "Microsoft Windows", ""
	}
	return "", ""
}

// snmpV3Discovery is the message RFC 3414 (4) has a manager send to learn
// an agent's engine id: version 3, reportable, no authentication, an empty
// security-parameters block and an empty GetRequest.
func snmpV3Discovery() []byte {
	usm := tlv(0x30, tlv(0x04, nil), tlv(0x02, []byte{0}), tlv(0x02, []byte{0}), tlv(0x04, nil), tlv(0x04, nil), tlv(0x04, nil))
	global := tlv(0x30, tlv(0x02, randBytes(3)[:2]), tlv(0x02, []byte{0x00, 0xff, 0xe3}), tlv(0x04, []byte{4}), tlv(0x02, []byte{3}))
	pdu := tlv(0xa0, tlv(0x02, randBytes(3)[:2]), tlv(0x02, []byte{0}), tlv(0x02, []byte{0}), tlv(0x30))
	scoped := tlv(0x30, tlv(0x04, nil), tlv(0x04, nil), pdu)
	return tlv(0x30, tlv(0x02, []byte{3}), global, tlv(0x04, usm), scoped)
}

// snmpEnterprises name the vendor in an engine id (the IANA private
// enterprise numbers).
var snmpEnterprises = map[uint32]string{
	9: "Cisco", 11: "HP", 311: "Microsoft", 674: "Dell", 2011: "Huawei", 2021: "Net-SNMP", 2636: "Juniper",
	6876: "VMware", 8072: "Net-SNMP", 12356: "Fortinet", 14988: "MikroTik", 25506: "H3C", 41112: "Ubiquiti",
}

// parseSNMPv3 reads what an agent answers a discovery with: a Report whose
// security parameters carry its engine id (RFC 3414, 4).
func parseSNMPv3(rest []byte) (udpInfo, bool) {
	_, _, rest, ok := berNext(rest) // msgGlobalData
	if !ok {
		return udpInfo{}, false
	}
	tag, sec, _, ok := berNext(rest)
	if !ok || tag != 0x04 {
		return udpInfo{}, false
	}
	_, usm, _, ok := berNext(sec)
	if !ok {
		return udpInfo{}, false
	}
	_, id, _, ok := berNext(usm)
	if !ok || len(id) < 5 {
		return udpInfo{}, false
	}
	info := udpInfo{service: "snmp", banner: "snmpv3 engine id " + hex.EncodeToString(id)}
	if id[0]&0x80 != 0 {
		ent := uint32(id[0]&0x7f)<<24 | uint32(id[1])<<16 | uint32(id[2])<<8 | uint32(id[3])
		info.product = snmpEnterprises[ent]
	}
	return info, true
}

func parseSSDP(r, _ []byte) (udpInfo, bool) {
	if !bytes.HasPrefix(r, []byte("HTTP/1.1 200")) && !bytes.HasPrefix(r, []byte("NOTIFY")) {
		return udpInfo{}, false
	}
	info := udpInfo{service: "ssdp"}
	for _, l := range strings.Split(string(r), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(l), ":"); ok && strings.EqualFold(k, "server") {
			info.banner = printable([]byte(strings.TrimSpace(v)))
			info.product, info.version = upnpProduct(info.banner)
		}
	}
	return info, true
}

// upnpProduct picks the UPnP stack out of "Linux/5.15 UPnP/1.1 MiniUPnPd/2.3.3":
// the last token that names neither UPnP nor the operating system.
func upnpProduct(server string) (string, string) {
	var name, ver string
	for _, t := range strings.Fields(server) {
		n, v, ok := strings.Cut(t, "/")
		if !ok || strings.HasPrefix(strings.ToUpper(n), "UPNP") {
			continue
		}
		if name == "" || !isOS(n) {
			name, ver = n, v
		}
	}
	return name, ver
}

func isOS(n string) bool {
	switch strings.ToLower(n) {
	case "linux", "windows", "darwin", "freebsd", "openbsd", "netbsd", "macos":
		return true
	}
	return false
}

// mdnsQuery asks which service types the host offers (DNS-SD).
func mdnsQuery() []byte {
	q := []byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, l := range []string{"_services", "_dns-sd", "_udp", "local"} {
		q = append(append(q, byte(len(l))), l...)
	}
	return append(q, 0, 0, 12, 0, 1)
}

func parseMDNS(r, _ []byte) (udpInfo, bool) {
	if len(r) < 12 || r[2]&0x80 == 0 {
		return udpInfo{}, false
	}
	return udpInfo{service: "mdns", banner: fmt.Sprintf("mdns answer, %d records", binary.BigEndian.Uint16(r[6:8]))}, true
}

// nbstat is a NetBIOS node status request for the wildcard name.
func nbstat() []byte {
	q := append(randBytes(2), 0, 0, 0, 1, 0, 0, 0, 0, 0, 0)
	q = append(q, 0x20, 'C', 'K')
	q = append(q, bytes.Repeat([]byte{'A'}, 30)...)
	return append(q, 0, 0, 0x21, 0, 1)
}

func parseNBStat(r, sent []byte) (udpInfo, bool) {
	if len(r) < 12 || !bytes.Equal(r[:2], sent[:2]) || r[2]&0x80 == 0 {
		return udpInfo{}, false
	}
	info := udpInfo{service: "netbios-ns"}
	// header, name (34), type, class, ttl, rdlength, then the name count.
	if off := 12 + 34 + 10; len(r) >= off+16 && r[off] > 0 {
		info.banner = "netbios name " + strings.TrimSpace(printable(r[off+1:off+16]))
	}
	return info, true
}

// ikeInit is the 28-byte header of an IKEv2 SA_INIT exchange with no
// payloads, which a server answers with an error or ignores.
func ikeInit(natT bool) []byte {
	h := append(randBytes(8), make([]byte, 8)...)
	h = append(h, 0, 0x20, 34, 0x08, 0, 0, 0, 0, 0, 0, 0, 28)
	if natT {
		return append(make([]byte, 4), h...) // non-ESP marker
	}
	return h
}

func parseIKE(r, sent []byte) (udpInfo, bool) {
	if len(sent) == 32 {
		if len(r) < 4 {
			return udpInfo{}, false
		}
		r, sent = r[4:], sent[4:]
	}
	if len(r) < 28 || !bytes.Equal(r[:8], sent[:8]) {
		return udpInfo{}, false
	}
	return udpInfo{service: "isakmp", banner: fmt.Sprintf("ikev%d", r[17]>>4)}, true
}

// stunBinding is a Binding request, as every STUN client sends.
func stunBinding() []byte {
	return append([]byte{0, 1, 0, 0, 0x21, 0x12, 0xa4, 0x42}, randBytes(12)...)
}

var softwareRe = regexp.MustCompile(`^([A-Za-z][\w]*)[-/ ]v?(\d[\w.]*)`)

func parseSTUN(r, sent []byte) (udpInfo, bool) {
	if len(r) < 20 || r[0] != 0x01 || r[1] != 0x01 || !bytes.Equal(r[4:8], sent[4:8]) {
		return udpInfo{}, false
	}
	info := udpInfo{service: "stun", banner: "stun binding response"}
	attrs := r[20:]
	for len(attrs) >= 4 {
		t, n := binary.BigEndian.Uint16(attrs), int(binary.BigEndian.Uint16(attrs[2:]))
		if len(attrs) < 4+n {
			break
		}
		if t == 0x8022 { // SOFTWARE
			sw := printable(attrs[4 : 4+n])
			info.banner = sw
			if m := softwareRe.FindStringSubmatch(sw); m != nil {
				info.product, info.version = m[1], m[2]
			} else {
				info.product = sw
			}
		}
		if next := 4 + (n+3)&^3; next < len(attrs) {
			attrs = attrs[next:]
		} else {
			break
		}
	}
	return info, true
}

var memcachedRe = regexp.MustCompile(`^VERSION (\S+)`)

func parseMemcached(r, _ []byte) (udpInfo, bool) {
	if len(r) < 8 {
		return udpInfo{}, false
	}
	m := memcachedRe.FindStringSubmatch(printable(r[8:]))
	if m == nil {
		return udpInfo{}, false
	}
	return udpInfo{service: "memcached", product: "memcached", version: m[1], banner: "VERSION " + m[1]}, true
}

func parseBACnet(r, _ []byte) (udpInfo, bool) {
	if len(r) < 4 || r[0] != 0x81 {
		return udpInfo{}, false
	}
	return udpInfo{service: "bacnet", banner: "bacnet/ip answer"}, true
}

// coapWellKnown is GET /.well-known/core, a confirmable request.
func coapWellKnown() []byte {
	req := append([]byte{0x40, 0x01}, randBytes(2)...)
	req = append(req, 0xbb)
	req = append(req, ".well-known"...)
	req = append(req, 0x04)
	return append(req, "core"...)
}

func parseCoAP(r, sent []byte) (udpInfo, bool) {
	if len(r) < 4 || r[0]>>6 != 1 || !bytes.Equal(r[2:4], sent[2:4]) {
		return udpInfo{}, false
	}
	info := udpInfo{service: "coap", banner: fmt.Sprintf("coap %d.%02d", r[1]>>5, r[1]&0x1f)}
	if i := bytes.IndexByte(r, 0xff); i > 0 && i+1 < len(r) {
		info.banner += " " + printable(r[i+1:])
	}
	return info, true
}
