package portscan

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"regexp"
	"strings"
)

func init() {
	register(
		// LDAP: an anonymous search of the root DSE, no bind (RFC 4511,
		// section 4.5; RFC 4512, section 5.1).
		&protocol{name: "ldap", ports: []int{389, 3268}, tlsPorts: []int{636, 3269}, passive: true,
			request: func(target) []byte { return ldapRootDSE() },
			frame:   berFrame, read: ldapRead},
		// DNS over TCP: a length-prefixed query (RFC 1035, section 4.2.2),
		// then the CHAOS TXT version.bind (RFC 4892, section 2).
		&protocol{name: "dns", ports: []int{53}, tlsPorts: []int{853},
			request: func(target) []byte { return dnsTCP(dnsQuery()) },
			frame:   lengthFrame(0, 2, 0), read: dnsTCPRead, deepen: dnsDeepen},
		// Kerberos: an AS-REQ for a principal that does not exist; the
		// KRB-ERROR names the realm (RFC 4120, sections 5.9.1 and 7.2).
		&protocol{name: "kerberos", ports: []int{88},
			request: func(target) []byte { return krbASReq() },
			frame:   lengthFrame(0, 4, 0), read: krbRead},
	)
}

// BER helpers for requests.
func berInt(n int) []byte { return tlv(0x02, []byte{byte(n)}) }

// ldapRootDSE is a SearchRequest: base "", scope baseObject, no limits,
// filter (objectClass=*), attributes * and + (the operational ones).
func ldapRootDSE() []byte {
	req := tlv(0x63,
		tlv(0x04, nil), tlv(0x0a, []byte{0}), tlv(0x0a, []byte{0}), berInt(0), berInt(0), tlv(0x01, []byte{0}),
		tlv(0x87, []byte("objectClass")),
		tlv(0x30, tlv(0x04, []byte("*")), tlv(0x04, []byte("+"))))
	return tlv(0x30, berInt(1), req)
}

// berFrame says how long a BER message is from its header.
func berFrame(b []byte) int {
	if len(b) < 2 {
		return 0
	}
	if b[0] != 0x30 {
		return -1
	}
	n, off := int(b[1]), 2
	if n&0x80 != 0 {
		k := n & 0x7f
		if k == 0 || k > 3 {
			return -1
		}
		if len(b) < 2+k {
			return 0
		}
		n = 0
		for _, c := range b[2 : 2+k] {
			n = n<<8 | int(c)
		}
		off = 2 + k
	}
	return off + n
}

// ldapRead reads the first message of the answer to the root DSE search: the
// entry's attributes, or the search's own result when there is no entry (a
// server that wants a bind still says it is LDAP).
func ldapRead(r []byte, o *Open) bool {
	tag, msg, _, ok := berNext(r)
	if !ok || tag != 0x30 {
		return false
	}
	_, id, msg, ok := berNext(msg)
	if !ok || len(id) != 1 || id[0] != 1 {
		return false
	}
	tag, op, _, ok := berNext(msg)
	if !ok {
		return false
	}
	attrs := map[string][]string{}
	switch tag {
	case 0x64: // SearchResultEntry: objectName, then the attributes
		_, _, rest, ok := berNext(op)
		if !ok {
			return false
		}
		_, list, _, _ := berNext(rest)
		for len(list) > 0 {
			var attr []byte
			_, attr, list, ok = berNext(list)
			if !ok {
				break
			}
			_, name, vals, ok := berNext(attr)
			if !ok {
				break
			}
			_, set, _, _ := berNext(vals)
			for len(set) > 0 {
				var v []byte
				_, v, set, ok = berNext(set)
				if !ok {
					break
				}
				attrs[string(name)] = append(attrs[string(name)], string(v))
			}
		}
	case 0x65, 0x78: // SearchResultDone; ExtendedResponse (notice of disconnection)
	default:
		return false
	}
	o.Service, o.Banner = "ldap", "ldap rootDSE"
	ldapProduct(attrs, o)
	return true
}

// adLevels are the functional levels a Windows domain controller states
// in domainControllerFunctionality ([MS-ADTS] 6.1.4.2).
var adLevels = map[string]string{
	"0": "2000", "1": "2003 interim", "2": "2003", "3": "2008", "4": "2008 R2",
	"5": "2012", "6": "2012 R2", "7": "2016",
}

var vendorVerRe = regexp.MustCompile(`(\d+(?:\.\d+)+)`)

func ldapProduct(a map[string][]string, o *Open) {
	first := func(k string) string {
		if v := a[k]; len(v) > 0 {
			return v[0]
		}
		return ""
	}
	oc := strings.Join(a["objectClass"], " ")
	switch {
	case first("domainControllerFunctionality") != "" || first("isGlobalCatalogReady") != "":
		o.Product = "Microsoft Windows Active Directory LDAP"
		if l := adLevels[first("domainControllerFunctionality")]; l != "" {
			o.Version = "Windows Server " + l + " functional level"
		}
	case strings.Contains(oc, "OpenLDAProotDSE"):
		o.Product = "OpenLDAP"
	case first("vendorName") != "":
		o.Product = first("vendorName")
		if v := vendorVerRe.FindString(first("vendorVersion")); v != "" {
			o.Version = v
		}
	}
	if nc := a["namingContexts"]; len(nc) > 0 {
		o.Banner = "ldap rootDSE, namingContexts " + strings.Join(nc, ", ")
	}
}

// dnsTCP prefixes a query with its length.
func dnsTCP(q []byte) []byte {
	return append([]byte{byte(len(q) >> 8), byte(len(q))}, q...)
}

func dnsTCPRead(r []byte, o *Open) bool {
	if len(r) < 14 || int(binary.BigEndian.Uint16(r)) != len(r)-2 || r[4]&0x80 == 0 {
		return false
	}
	o.Service, o.Banner = "dns", fmt.Sprintf("dns answer, rcode %d, %d records", r[5]&0x0f, binary.BigEndian.Uint16(r[8:10]))
	return true
}

// versionBindQuery asks for the TXT record version.bind in class CHAOS.
func versionBindQuery() []byte {
	q := append(randBytes(2), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0)
	for _, l := range []string{"version", "bind"} {
		q = append(append(q, byte(len(l))), l...)
	}
	return append(q, 0, 0, 16, 0, 3)
}

// dnsDeepen asks version.bind on the same connection.
func dnsDeepen(s *Scanner, c net.Conn, o *Open) {
	q := versionBindQuery()
	r, _ := s.talk(c, dnsTCP(q), lengthFrame(0, 2, 0), s.Banner)
	if len(r) > 2 {
		if p, v, ok := versionBind(r[2:], q); ok {
			o.Product, o.Version = p, v
		}
	}
}

var (
	bindVerRe   = regexp.MustCompile(`^(\d+\.\d+[\w.\-+~]*)$`)
	nameVerRe   = regexp.MustCompile(`^([A-Za-z][A-Za-z ]*?)[- ]v?(\d[\w.\-+~]*)$`)
	isBindBuild = regexp.MustCompile(`^9\.\d+`)
)

// versionBind reads the TXT string of an answer to version.bind: BIND says
// its number, dnsmasq "dnsmasq-2.90", Unbound "unbound 1.19.0".
func versionBind(r, sent []byte) (product, version string, ok bool) {
	if len(r) < 12 || !bytes.Equal(r[:2], sent[:2]) || r[2]&0x80 == 0 || r[3]&0x0f != 0 || binary.BigEndian.Uint16(r[6:]) == 0 {
		return "", "", false
	}
	// The answer repeats the question, then a record: name, type, class,
	// ttl, rdlength, then the TXT's length-prefixed string.
	i := 12
	for i < len(r) && r[i] != 0 {
		i += int(r[i]) + 1
	}
	i += 1 + 4 // the root label, type and class
	if i >= len(r) {
		return "", "", false
	}
	if r[i]&0xc0 == 0xc0 {
		i += 2
	} else {
		for i < len(r) && r[i] != 0 {
			i += int(r[i]) + 1
		}
		i++
	}
	i += 10 // type, class, ttl, rdlength
	if i+1 >= len(r) || i+1+int(r[i]) > len(r) {
		return "", "", false
	}
	txt := strings.TrimSpace(printable(r[i+1 : i+1+int(r[i])]))
	switch {
	case txt == "":
		return "", "", false
	case bindVerRe.MatchString(txt):
		return "ISC BIND", txt, true
	}
	if m := nameVerRe.FindStringSubmatch(txt); m != nil {
		name := m[1]
		switch strings.ToLower(name) {
		case "dnsmasq":
			name = "dnsmasq"
		case "unbound":
			name = "Unbound"
		}
		return name, m[2], true
	}
	return txt, "", true
}

// krbASReq is an AS-REQ with no pre-authentication for the principal
// "azhaq" in the realm "AZHAQ.INVALID", framed for TCP (RFC 4120, 5.4.1).
func krbASReq() []byte {
	str := func(s string) []byte { return tlv(0x1b, []byte(s)) } // GeneralString
	ctx := func(n byte, v []byte) []byte { return tlv(0xa0|n, v) }
	name := func(typ int, parts ...string) []byte {
		var ss []byte
		for _, p := range parts {
			ss = append(ss, str(p)...)
		}
		return tlv(0x30, ctx(0, berInt(typ)), ctx(1, tlv(0x30, ss)))
	}
	body := tlv(0x30,
		ctx(0, tlv(0x03, []byte{0, 0x40, 0, 0, 0})), // kdc-options
		ctx(1, name(1, "azhaq")),
		ctx(2, str("AZHAQ.INVALID")),
		ctx(3, name(2, "krbtgt", "AZHAQ.INVALID")),
		ctx(5, tlv(0x18, []byte("20370913024805Z"))),
		ctx(7, tlv(0x02, []byte{0x2a, 0x10, 0x20, 0x31})),
		ctx(8, tlv(0x30, berInt(18))))
	req := tlv(0x6a, tlv(0x30, ctx(1, berInt(5)), ctx(2, berInt(10)), ctx(4, body)))
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(req))), req...)
}

// krbRead takes a KRB-ERROR ([APPLICATION 30]): the realm and the error
// code (6, client unknown, is what a principal that does not exist gets).
func krbRead(r []byte, o *Open) bool {
	if len(r) < 8 || int(binary.BigEndian.Uint32(r)) != len(r)-4 {
		return false
	}
	tag, seq, _, ok := berNext(r[4:])
	if !ok || tag != 0x7e {
		return false
	}
	_, fields, _, ok := berNext(seq)
	if !ok {
		return false
	}
	realm, code := "", -1
	for len(fields) > 0 {
		var f []byte
		var t byte
		t, f, fields, ok = berNext(fields)
		if !ok {
			break
		}
		_, v, _, _ := berNext(f)
		switch t {
		case 0xa6:
			if len(v) == 1 {
				code = int(v[0])
			}
		case 0xa9:
			realm = printable(v)
		}
	}
	if code < 0 {
		return false
	}
	o.Service, o.Banner = "kerberos", fmt.Sprintf("kerberos error %d, realm %s", code, realm)
	return true
}
