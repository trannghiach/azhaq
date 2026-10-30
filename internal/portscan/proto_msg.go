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
		// MQTT: a CONNECT without credentials, then a subscription to the
		// broker's own version topic (MQTT 3.1.1, sections 3.1, 3.2, 3.8).
		&protocol{name: "mqtt", ports: []int{1883}, tlsPorts: []int{8883},
			request: func(target) []byte { return mqttConnect() },
			frame:   mqttFrame, read: mqttRead, deepen: mqttDeepen},
		// AMQP: the protocol header; a broker answers with Connection.Start
		// and its server properties, or with the header it speaks (AMQP 0-9-1
		// specification, sections 2.2.4 and 4.2.5.5).
		&protocol{name: "amqp", ports: []int{5672}, tlsPorts: []int{5671}, passive: true,
			request: func(target) []byte { return []byte("AMQP\x00\x00\x09\x01") },
			frame:   amqpFrame, read: amqpRead},
		// STOMP: a CONNECT frame without credentials (STOMP 1.2, "CONNECT").
		&protocol{name: "stomp", ports: []int{61613},
			request: func(t target) []byte {
				return []byte("CONNECT\naccept-version:1.2\nhost:" + t.host + "\n\n\x00")
			},
			read: stompRead},
		// XMPP: the opening of a stream (RFC 6120, section 4).
		&protocol{name: "xmpp", ports: []int{5222, 5269}, tlsPorts: []int{5223},
			request: func(t target) []byte {
				ns := "jabber:client"
				if t.port == 5269 {
					ns = "jabber:server"
				}
				return []byte("<?xml version='1.0'?><stream:stream to='" + t.host + "' xmlns='" + ns +
					"' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>")
			},
			read: xmppRead},
	)
}

// mqttConnect is a CONNECT, protocol level 4 (3.1.1), clean session, no
// user name or password, keep alive 60 s, client id "azhaq".
func mqttConnect() []byte {
	body := []byte{0, 4, 'M', 'Q', 'T', 'T', 4, 0x02, 0, 60, 0, 5, 'a', 'z', 'h', 'a', 'q'}
	return append([]byte{0x10, byte(len(body))}, body...)
}

func mqttFrame(b []byte) int {
	if len(b) < 2 {
		return 0
	}
	if b[0]>>4 == 2 && b[1] == 2 {
		return 4 // CONNACK
	}
	return -1
}

var mqttCodes = []string{"accepted", "unacceptable protocol version", "identifier rejected", "server unavailable", "bad user name or password", "not authorized"}

func mqttRead(r []byte, o *Open) bool {
	if len(r) < 4 || r[0] != 0x20 || r[1] != 2 || r[2]&0xfe != 0 || int(r[3]) >= len(mqttCodes) {
		return false
	}
	o.Service, o.Banner = "mqtt", "connack "+mqttCodes[r[3]]
	return true
}

// mqttDeepen subscribes to $SYS/broker/version, which brokers such as
// Mosquitto answer with a retained message, and then disconnects.
func mqttDeepen(s *Scanner, c net.Conn, o *Open) {
	if !strings.HasSuffix(o.Banner, "accepted") {
		return
	}
	topic := "$SYS/broker/version"
	body := append([]byte{0, 1, 0, byte(len(topic))}, topic...)
	body = append(body, 0)
	r := s.talk(c, append([]byte{0x82, byte(len(body))}, body...), nil, s.Banner)
	for len(r) >= 2 {
		n := int(r[1])
		if r[1]&0x80 != 0 || len(r) < 2+n {
			break
		}
		pkt := r[2 : 2+n]
		if r[0]>>4 == 3 && len(pkt) >= 2 { // PUBLISH
			tl := int(binary.BigEndian.Uint16(pkt))
			if len(pkt) >= 2+tl {
				product, version := mqttBroker(string(pkt[2+tl:]))
				if product != "" {
					o.Product, o.Version = product, version
				}
			}
		}
		r = r[2+n:]
	}
	_, _ = c.Write([]byte{0xe0, 0})
}

var brokerRe = regexp.MustCompile(`^([A-Za-z][\w .-]*?)(?: version)?[ /-]v?(\d[\w.]*)`)

// mqttBroker reads "mosquitto version 2.0.18" (or "name 1.2.3").
func mqttBroker(s string) (product, version string) {
	m := brokerRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return "", ""
	}
	product = m[1]
	if strings.EqualFold(product, "mosquitto") {
		product = "Mosquitto"
	}
	return product, m[2]
}

func amqpFrame(b []byte) int {
	if len(b) < 8 {
		return 0
	}
	if string(b[:4]) == "AMQP" {
		return 8
	}
	if b[0] != 1 || len(b) < 7 {
		return -1
	}
	return 8 + int(binary.BigEndian.Uint32(b[3:]))
}

func amqpRead(r []byte, o *Open) bool {
	if len(r) >= 8 && string(r[:4]) == "AMQP" {
		o.Service = "amqp"
		o.Banner = fmt.Sprintf("amqp %d-%d-%d", r[5], r[6], r[7])
		return true
	}
	// Connection.Start: frame type 1, channel 0, size, class 10, method 10.
	if len(r) < 20 || r[0] != 1 || r[1] != 0 || r[2] != 0 || binary.BigEndian.Uint16(r[7:]) != 10 || binary.BigEndian.Uint16(r[9:]) != 10 {
		return false
	}
	props := amqpTable(r[13:]) // after version-major and version-minor
	o.Service, o.Product, o.Version = "amqp", props["product"], props["version"]
	o.Banner = fmt.Sprintf("amqp %d-%d", r[11], r[12])
	if p := props["platform"]; p != "" {
		o.Banner += ", " + p
	}
	return true
}

// amqpTable reads the string entries of a field table (AMQP 0-9-1, section
// 4.2.5.5): a 4-byte length, then name (short string), type, value.
func amqpTable(b []byte) map[string]string {
	out := map[string]string{}
	if len(b) < 4 {
		return out
	}
	n := int(binary.BigEndian.Uint32(b))
	if n > len(b)-4 {
		n = len(b) - 4
	}
	t := b[4 : 4+n]
	for len(t) > 1 {
		nl := int(t[0])
		if len(t) < 2+nl {
			break
		}
		name, typ, v := string(t[1:1+nl]), t[1+nl], t[2+nl:]
		var size int
		switch typ {
		case 'S', 'x', 'A', 'F':
			if len(v) < 4 {
				return out
			}
			size = 4 + int(binary.BigEndian.Uint32(v))
			if typ == 'S' && len(v) >= size {
				out[name] = printable(v[4:size])
			}
		case 's':
			if len(v) < 1 {
				return out
			}
			size = 1 + int(v[0])
		case 't', 'b', 'B':
			size = 1
		case 'U', 'u':
			size = 2
		case 'I', 'i', 'f':
			size = 4
		case 'l', 'L', 'd', 'T':
			size = 8
		case 'D':
			size = 5
		case 'V':
		default:
			return out
		}
		if len(v) < size {
			return out
		}
		t = v[size:]
	}
	return out
}

var stompServerRe = regexp.MustCompile(`(?m)^server:([^\r\n]+)`)

func stompRead(r []byte, o *Open) bool {
	if !bytes.HasPrefix(r, []byte("CONNECTED\n")) && !bytes.HasPrefix(r, []byte("ERROR\n")) {
		return false
	}
	if !bytes.Contains(r, []byte("version:")) && !bytes.Contains(r, []byte("message:")) {
		return false
	}
	o.Service, o.Banner = "stomp", printable(r)
	if m := stompServerRe.FindSubmatch(r); m != nil {
		o.Product, o.Version = serverProduct(strings.TrimSpace(string(m[1])))
	}
	return true
}

func xmppRead(r []byte, o *Open) bool {
	if !bytes.Contains(r, []byte("etherx.jabber.org/streams")) {
		return false
	}
	o.Service, o.Banner = "xmpp", "xmpp stream"
	return true
}
