package portscan

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

func init() {
	register(
		// Redis: the inline command INFO (the Redis protocol, RESP). A
		// server that wants a password answers -NOAUTH and says no more.
		&protocol{name: "redis", ports: []int{6379}, passive: true,
			request: func(target) []byte { return []byte("INFO server\r\n") },
			frame:   respFrame, read: redisRead},
		// PostgreSQL: a StartupMessage of a protocol version that does not
		// exist; the server's ErrorResponse names the versions it speaks
		// (PostgreSQL frontend/backend protocol, message formats).
		&protocol{name: "postgresql", ports: []int{5432, 5433}, passive: true,
			request: func(target) []byte { return pgStartup(1, 0) },
			frame:   pgFrame, read: pgRead},
		// MongoDB: an OP_MSG isMaster, then buildInfo (both answered before
		// authentication).
		&protocol{name: "mongodb", ports: []int{27017, 27018, 27019},
			request: func(target) []byte { return mongoCommand("isMaster") },
			frame:   mongoFrame,
			read: func(r []byte, o *Open) bool {
				v, ok := mongoHello(r)
				if ok {
					o.Product, o.Version, o.Banner = "MongoDB", v, "mongodb isMaster answered"
				}
				return ok
			},
			deepen: mongoDeepen},
		// memcached: the text command version (memcached's protocol.txt).
		&protocol{name: "memcached", ports: []int{11211},
			request: func(target) []byte { return []byte("version\r\n") },
			read: func(r []byte, o *Open) bool {
				m := memcachedRe.FindSubmatch(r)
				if m == nil {
					return false
				}
				o.Product, o.Version, o.Banner = "memcached", string(m[1]), "VERSION "+string(m[1])
				return true
			}},
		// ZooKeeper: the four-letter command srvr (ZooKeeper Administrator's
		// Guide); a server that does not allow it says so.
		&protocol{name: "zookeeper", ports: []int{2181},
			request: func(target) []byte { return []byte("srvr") },
			read:    zookeeperRead},
		// Kafka: ApiVersions v0 (Apache Kafka protocol guide).
		&protocol{name: "kafka", ports: []int{9092},
			request: func(target) []byte { return kafkaApiVersions() },
			frame:   lengthFrame(0, 4, 0), read: kafkaRead},
		// Microsoft SQL Server: the TDS PRELOGIN packet ([MS-TDS] 2.2.6.5).
		&protocol{name: "mssql", ports: []int{1433},
			request: func(target) []byte { return tdsPrelogin() },
			frame:   tdsFrame, read: tdsRead},
		// Cassandra: the native protocol's OPTIONS frame (CQL binary
		// protocol v4, section 4.1.5).
		&protocol{name: "cassandra", ports: []int{9042},
			request: func(target) []byte { return []byte{0x04, 0, 0, 0, 0x05, 0, 0, 0, 0} },
			frame:   lengthFrame(5, 4, 9), read: cassandraRead},
	)
}

// lengthFrame frames a message whose length is a big-endian integer of n
// bytes at off in the header, with hdr bytes before the body.
func lengthFrame(off, n, hdr int) func([]byte) int {
	return func(b []byte) int {
		if len(b) < off+n {
			return 0
		}
		l := 0
		for _, c := range b[off : off+n] {
			l = l<<8 | int(c)
		}
		if l > 1<<20 {
			return -1
		}
		if hdr == 0 {
			return n + l // the length counts what follows it
		}
		return hdr + l
	}
}

// respFrame ends a RESP answer: a simple string or error at its line, a bulk
// string after its body.
func respFrame(b []byte) int {
	i := bytes.Index(b, []byte("\r\n"))
	if i < 0 {
		return 0
	}
	switch b[0] {
	case '+', '-', ':':
		return i + 2
	case '$':
		n, err := strconv.Atoi(string(b[1:i]))
		if err != nil || n < 0 {
			return i + 2
		}
		return i + 2 + n + 2
	}
	return -1
}

var redisVersionRe = regexp.MustCompile(`(?m)^redis_version:(\S+)`)

// redisError is what Redis answers a request that is not its own with
// (an old server quotes the command with ', a newer one with `): the HEAD
// of the HTTP probe, or a password it wants.
var redisError = regexp.MustCompile("^-(?:NOAUTH|DENIED)\\b|^-ERR unknown command [`']")

func redisRead(r []byte, o *Open) bool {
	s := string(r)
	if m := redisVersionRe.FindStringSubmatch(s); m != nil && strings.HasPrefix(s, "$") {
		o.Service, o.Product, o.Version, o.Banner = "redis", "Redis", m[1], "redis_version:"+m[1]
		return true
	}
	if strings.HasPrefix(s, "+PONG") || redisError.MatchString(s) {
		o.Service, o.Product, o.Banner = "redis", "Redis", printable(r)
		return true
	}
	return false
}

// pgStartup is a StartupMessage: length, protocol version major.minor.
func pgStartup(major, minor uint16) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint32(b, 8)
	binary.BigEndian.PutUint16(b[4:], major)
	binary.BigEndian.PutUint16(b[6:], minor)
	return b
}

// pgFrame frames an ErrorResponse: a version 3 message has a length after
// its tag, the old format a server answers an unknown protocol with is text
// ended by a NUL.
func pgFrame(b []byte) int {
	if len(b) < 2 {
		return 0
	}
	switch b[0] {
	case 'S', 'N':
		return 1
	case 'E':
	default:
		return -1
	}
	if b[1] != 0 {
		if i := bytes.IndexByte(b, 0); i >= 0 {
			return i + 1
		}
		return 0
	}
	if len(b) < 5 {
		return 0
	}
	return 1 + int(binary.BigEndian.Uint32(b[1:]))
}

var pgSupportsRe = regexp.MustCompile(`unsupported frontend protocol \d+\.\d+: server supports (\d+)\.(\d+) to (\d+)\.(\d+)`)

// postgresError is what PostgreSQL answers a request that is not its own
// with.
func postgresError(answer []byte) bool {
	return len(answer) > 0 && answer[0] == 'E' && bytes.Contains(answer, []byte("unsupported frontend protocol"))
}

// pgRead takes the ErrorResponse to an unsupported protocol version. The
// versions it supports bound the release: 2.0 went in 14, 3.2 came in 18.
func pgRead(r []byte, o *Open) bool {
	if !postgresError(r) {
		return false
	}
	o.Service, o.Product = "postgresql", "PostgreSQL"
	o.Banner = ""
	if m := pgSupportsRe.FindSubmatch(r); m != nil {
		lo, hi := string(m[1])+"."+string(m[2]), string(m[3])+"."+string(m[4])
		switch {
		case lo == "2.0":
			o.Version = "7.4 - 13"
		case lo == "3.0" && hi == "3.0":
			o.Version = "14 - 17"
		case lo == "3.0" && hi >= "3.2":
			o.Version = "18 or later"
		}
		o.Banner = "protocol " + lo + " to " + hi
	}
	return true
}

// mongoCommand is an OP_MSG carrying {name: 1, $db: "admin"}.
func mongoCommand(name string) []byte {
	var doc bytes.Buffer
	doc.Write([]byte{0, 0, 0, 0, 0x10})
	doc.WriteString(name + "\x00")
	doc.Write([]byte{1, 0, 0, 0, 0x02})
	doc.WriteString("$db\x00")
	doc.Write([]byte{6, 0, 0, 0})
	doc.WriteString("admin\x00")
	doc.WriteByte(0)
	d := doc.Bytes()
	binary.LittleEndian.PutUint32(d, uint32(len(d)))
	msg := make([]byte, 16, 21+len(d))
	binary.LittleEndian.PutUint32(msg[0:], uint32(21+len(d)))
	binary.LittleEndian.PutUint32(msg[4:], 1)
	binary.LittleEndian.PutUint32(msg[12:], 2013)
	msg = append(msg, 0, 0, 0, 0, 0) // flag bits, section kind 0
	return append(msg, d...)
}

func mongoFrame(b []byte) int {
	if len(b) < 4 {
		return 0
	}
	n := int(binary.LittleEndian.Uint32(b))
	if n < 16 || n > 1<<20 {
		return -1
	}
	return n
}

// bsonString finds a string element of a top-level BSON document.
func bsonString(doc []byte, key string) string {
	if len(doc) < 5 {
		return ""
	}
	for el := doc[4:]; len(el) > 1; {
		typ := el[0]
		end := bytes.IndexByte(el[1:], 0)
		if end < 0 {
			return ""
		}
		name, val := string(el[1:1+end]), el[2+end:]
		var size int
		switch typ {
		case 0x01, 0x09, 0x11, 0x12:
			size = 8
		case 0x02:
			if len(val) < 4 {
				return ""
			}
			n := int(binary.LittleEndian.Uint32(val))
			if n < 1 || len(val) < 4+n {
				return ""
			}
			if name == key {
				return string(val[4 : 4+n-1])
			}
			size = 4 + n
		case 0x03, 0x04:
			if len(val) < 4 {
				return ""
			}
			size = int(binary.LittleEndian.Uint32(val))
		case 0x05:
			if len(val) < 4 {
				return ""
			}
			size = 5 + int(binary.LittleEndian.Uint32(val))
		case 0x07:
			size = 12
		case 0x08:
			size = 1
		case 0x0a:
		case 0x10:
			size = 4
		case 0x13:
			size = 16
		default:
			return ""
		}
		if size < 0 || len(val) < size {
			return ""
		}
		el = val[size:]
	}
	return ""
}

// mongoDeepen asks buildInfo for the exact version: isMaster gives only
// the wire version, which names the release (major.minor).
func mongoDeepen(s *Scanner, c net.Conn, o *Open) {
	r, _ := s.talk(c, mongoCommand("buildInfo"), mongoFrame, s.Banner)
	if len(r) > 26 && binary.LittleEndian.Uint32(r[12:]) == 2013 {
		if v := bsonString(r[21:], "version"); v != "" {
			o.Version = v
		}
	}
}

var zkVersionRe = regexp.MustCompile(`Zookeeper version: (\d+(?:\.\d+)*)`)

func zookeeperRead(r []byte, o *Open) bool {
	if m := zkVersionRe.FindSubmatch(r); m != nil {
		o.Service, o.Product, o.Version, o.Banner = "zookeeper", "Apache ZooKeeper", string(m[1]), "Zookeeper version: "+string(m[1])
		return true
	}
	if bytes.Contains(r, []byte("is not executed because it is not in the whitelist")) {
		o.Service, o.Product, o.Banner = "zookeeper", "Apache ZooKeeper", printable(r)
		return true
	}
	return false
}

// kafkaApiVersions is a request header (api key 18, version 0, a
// correlation id, the client id "azhaq") with no body.
func kafkaApiVersions() []byte {
	b := make([]byte, 4, 20)
	b = append(b, 0, 18, 0, 0, 0x61, 0x7a, 0x68, 0x71)
	b = append(b, 0, 5)
	b = append(b, "azhaq"...)
	binary.BigEndian.PutUint32(b, uint32(len(b)-4))
	return b
}

// kafkaRead takes an ApiVersions response: the correlation id, an error
// code (0, or 35 when version 0 is not supported), and the list of apis.
func kafkaRead(r []byte, o *Open) bool {
	if len(r) < 14 || int(binary.BigEndian.Uint32(r)) != len(r)-4 || binary.BigEndian.Uint32(r[4:]) != 0x617a6871 {
		return false
	}
	code := binary.BigEndian.Uint16(r[8:])
	if code != 0 && code != 35 {
		return false
	}
	n := int(binary.BigEndian.Uint32(r[10:]))
	if code == 0 && (n < 1 || n > 200 || len(r) < 14+6*n) {
		return false
	}
	o.Service, o.Banner = "kafka", fmt.Sprintf("kafka protocol, %d apis", n)
	return true
}

// tdsPrelogin is a PRELOGIN packet ([MS-TDS] 2.2.6.5): the options VERSION,
// ENCRYPTION (not supported), INSTOPT, THREADID and MARS.
func tdsPrelogin() []byte {
	opts := []struct {
		token byte
		data  []byte
	}{
		{0, []byte{0x09, 0, 0, 0, 0, 0}},
		{1, []byte{2}},
		{2, []byte{0}},
		{3, []byte{0, 0, 0, 0}},
		{4, []byte{0}},
	}
	table := len(opts)*5 + 1
	var head, data []byte
	for _, o := range opts {
		head = append(head, o.token, byte((table+len(data))>>8), byte(table+len(data)), 0, byte(len(o.data)))
		data = append(data, o.data...)
	}
	body := append(append(head, 0xff), data...)
	pkt := []byte{0x12, 0x01, byte((8 + len(body)) >> 8), byte(8 + len(body)), 0, 0, 1, 0}
	return append(pkt, body...)
}

func tdsFrame(b []byte) int {
	if len(b) < 8 {
		return 0
	}
	if b[0] != 0x04 {
		return -1
	}
	return int(binary.BigEndian.Uint16(b[2:]))
}

// sqlServerYears names the release by the major version of its TDS
// version token (Microsoft's version history).
var sqlServerYears = map[int]string{
	8: "2000", 9: "2005", 10: "2008", 11: "2012", 12: "2014", 13: "2016", 14: "2017", 15: "2019", 16: "2022", 17: "2025",
}

func tdsRead(r []byte, o *Open) bool {
	if len(r) < 9 || r[0] != 0x04 || int(binary.BigEndian.Uint16(r[2:])) != len(r) {
		return false
	}
	p := r[8:]
	for i := 0; i+5 <= len(p); i += 5 {
		if p[i] == 0xff {
			return false
		}
		if p[i] != 0 {
			continue
		}
		off, n := int(binary.BigEndian.Uint16(p[i+1:])), int(binary.BigEndian.Uint16(p[i+3:]))
		if n != 6 || off+n > len(p) {
			return false
		}
		v := p[off : off+n]
		build := binary.BigEndian.Uint16(v[2:])
		o.Service, o.Product = "mssql", "Microsoft SQL Server"
		if y := sqlServerYears[int(v[0])]; y != "" {
			o.Product += " " + y
		}
		o.Version = fmt.Sprintf("%d.%d.%d", v[0], v[1], build)
		o.Banner = "tds prelogin"
		return true
	}
	return false
}

var cqlVersionRe = regexp.MustCompile(`3\.\d+\.\d+`)

// cassandraRead takes a SUPPORTED frame (opcode 6), or the protocol ERROR
// (opcode 0) of a server that does not speak version 4.
func cassandraRead(r []byte, o *Open) bool {
	if len(r) < 9 || r[0]&0x80 == 0 || r[0]&0x7f < 3 || r[0]&0x7f > 6 || r[1]&0xf0 != 0 {
		return false
	}
	switch r[4] {
	case 0x06:
		o.Service, o.Banner = "cassandra", "cql supported"
		if m := cqlVersionRe.Find(r[9:]); m != nil {
			o.Banner = "cql " + string(m)
		}
		return true
	case 0x00:
		if len(r) >= 13 && binary.BigEndian.Uint32(r[9:]) == 0x0a { // protocol error
			o.Service, o.Banner = "cassandra", "cql protocol error"
			return true
		}
	}
	return false
}

func init() {
	// Oracle Net (TNS): a Connect packet asking the listener to ping
	// (packet layout as in Wireshark's TNS dissector; the connect data is
	// the descriptor Oracle's own tnsping sends).
	register(&protocol{name: "oracle-tns", ports: []int{1521, 1522, 1526},
		request: func(target) []byte { return tnsConnect() },
		frame:   tnsFrame, read: tnsRead})
}

func tnsConnect() []byte {
	data := []byte("(CONNECT_DATA=(COMMAND=ping))")
	h := make([]byte, 58)
	binary.BigEndian.PutUint16(h[8:], 0x013a)  // version
	binary.BigEndian.PutUint16(h[10:], 0x012c) // lowest compatible version
	binary.BigEndian.PutUint16(h[12:], 0x0c01) // service options
	binary.BigEndian.PutUint16(h[14:], 0x2000) // session data unit
	binary.BigEndian.PutUint16(h[16:], 0xffff) // transport data unit
	binary.BigEndian.PutUint16(h[18:], 0x7f08) // protocol characteristics
	binary.BigEndian.PutUint16(h[22:], 1)
	binary.BigEndian.PutUint16(h[24:], uint16(len(data)))
	binary.BigEndian.PutUint16(h[26:], 58) // offset of the connect data
	h[32], h[33] = 0x41, 0x41              // connect flags
	pkt := append(h, data...)
	binary.BigEndian.PutUint16(pkt, uint16(len(pkt)))
	pkt[4] = 1 // type: connect
	return pkt
}

func tnsFrame(b []byte) int {
	if len(b) < 8 {
		return 0
	}
	if b[4] < 1 || b[4] > 19 || b[5] != 0 {
		return -1
	}
	return int(binary.BigEndian.Uint16(b))
}

var tnsVsnRe = regexp.MustCompile(`VSNNUM=(\d+)`)

func tnsRead(r []byte, o *Open) bool {
	if len(r) < 8 || int(binary.BigEndian.Uint16(r)) != len(r) || r[4] < 2 || r[4] > 5 || r[5] != 0 {
		return false
	}
	o.Service, o.Product, o.Banner = "oracle-tns", "Oracle TNS Listener", "tns "+[]string{"", "", "accept", "ack", "refuse", "redirect"}[r[4]]
	if m := tnsVsnRe.FindSubmatch(r); m != nil {
		if n, err := strconv.ParseUint(string(m[1]), 10, 32); err == nil {
			// VSNNUM packs the release one byte per part (19.0.0.0.0 is 0x13000000).
			o.Version = fmt.Sprintf("%d.%d.%d.%d.%d", n>>24, n>>20&0xf, n>>12&0xff, n>>8&0xf, n&0xff)
		}
	}
	return true
}
