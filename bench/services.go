package main

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// servicesRow compares service and version detection with nmap -sV on the
// services lab (bench/services.yaml): fifteen daemons on ports that are not
// their usual ones, so a name has to come from what the service says.
type servicesRow struct {
	Profile    string          `json:"profile,omitempty"`
	Ports      int             `json:"ports"`
	AzhaqNamed int             `json:"azhaq_named"` // the service the port really runs
	NmapNamed  int             `json:"nmap_named"`
	AzhaqVer   int             `json:"azhaq_with_product"`
	NmapVer    int             `json:"nmap_with_product"`
	AzhaqSecs  float64         `json:"azhaq_seconds"`
	NmapSecs   float64         `json:"nmap_seconds"`
	Rows       []serviceRow    `json:"rows"`
	UDP        map[string]bool `json:"azhaq_udp,omitempty"`
}

type serviceRow struct {
	Port    int    `json:"port"`
	Truth   string `json:"truth"`
	Azhaq   string `json:"azhaq"`
	Nmap    string `json:"nmap"`
	AzOK    bool   `json:"azhaq_ok"`
	NmapOK  bool   `json:"nmap_ok"`
	Product string `json:"azhaq_product,omitempty"`
}

// serviceTruth is what each lab port runs (bench/services.yaml) and the
// names a tool may call it.
var serviceTruth = []struct {
	port  int
	what  string
	names []string
}{
	{16379, "redis", []string{"redis"}}, {13306, "mariadb", []string{"mysql", "mariadb"}}, {15432, "postgres", []string{"postgres"}},
	{17017, "mongo", []string{"mongo"}}, {11883, "mosquitto (mqtt)", []string{"mqtt"}}, {15682, "rabbitmq (amqp)", []string{"amqp", "rabbit"}},
	{21211, "memcached", []string{"memcache"}}, {12222, "openssh", []string{"ssh"}}, {10021, "ftp", []string{"ftp"}},
	{10025, "mailpit smtp", []string{"smtp"}}, {18825, "mailpit web", []string{"http"}}, {10389, "openldap", []string{"ldap"}},
	{10445, "samba", []string{"smb", "microsoft-ds", "netbios"}}, {19200, "elasticsearch", []string{"http", "elasticsearch"}}, {10053, "coredns (tcp)", []string{"domain", "dns"}},
}

// serviceReady is how to tell that the daemon behind a lab port serves, not
// only that docker's proxy listens: it accepts a connection and closes it
// until the container's process is up, which nmap and azhaq both name
// tcpwrapped. send is what to say first (nothing for a service that
// greets), ok judges what comes back; with no ok the service waits to be
// asked, and is serving when a connection stays open.
type serviceReady struct {
	send []byte
	ok   func(reply []byte) bool
}

func startsWith(p string) func([]byte) bool {
	return func(b []byte) bool { return bytes.HasPrefix(b, []byte(p)) }
}

// httpOK is a reply that is an HTTP status line with the code, any when "".
func httpOK(code string) func([]byte) bool {
	return func(b []byte) bool {
		return bytes.HasPrefix(b, []byte("HTTP/1.")) && (code == "" || bytes.Contains(firstLine(b), []byte(" "+code)))
	}
}

func firstLine(b []byte) []byte {
	l, _, _ := bytes.Cut(b, []byte("\n"))
	return l
}

var (
	httpGet = []byte("GET / HTTP/1.0\r\nHost: lab\r\n\r\n")
	// What each lab port is asked, by port (see serviceTruth).
	readyBy = map[int]serviceReady{
		16379: {[]byte("PING\r\n"), startsWith("+PONG")},
		// A handshake packet: a 4-byte header, then protocol version 10; an error packet counts as serving.
		13306: {nil, func(b []byte) bool { return len(b) > 4 && (b[4] == 10 || b[4] == 0xff) }},
		// An SSLRequest: a server that is up answers S or N.
		15432: {[]byte{0, 0, 0, 8, 4, 0xd2, 0x16, 0x2f}, func(b []byte) bool { return len(b) >= 1 && (b[0] == 'S' || b[0] == 'N') }},
		17017: {},
		// MQTT CONNECT, protocol 4, clean session: CONNACK.
		11883: {[]byte{0x10, 0x0c, 0, 4, 'M', 'Q', 'T', 'T', 4, 2, 0, 60, 0, 0}, func(b []byte) bool { return len(b) >= 2 && b[0] == 0x20 }},
		// AMQP 0-9-1 header: a method frame (Connection.Start).
		15682: {[]byte("AMQP\x00\x00\x09\x01"), func(b []byte) bool { return len(b) >= 7 && b[0] == 1 }},
		21211: {[]byte("version\r\n"), startsWith("VERSION ")},
		12222: {nil, startsWith("SSH-")},
		10021: {nil, startsWith("220")},
		10025: {nil, startsWith("220")},
		18825: {httpGet, httpOK("")},
		// An anonymous simple bind: a LDAPMessage with a bindResponse (0x61).
		10389: {[]byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00}, func(b []byte) bool { return len(b) > 5 && b[0] == 0x30 && bytes.IndexByte(b, 0x61) > 0 }},
		10445: {},
		// Elasticsearch answers 503 or 401 while it starts.
		19200: {httpGet, httpOK("200")},
		// A DNS query for "a." over TCP, length-prefixed: any answer to it
		// (REFUSED for a zone it does not hold) shows the daemon is up.
		10053: dnsTCPReady("a."),
	}
)

// dnsTCPReady asks for name's A record over TCP: the message after a 2-byte
// length, and an answer, after its length, that is a response to that query.
func dnsTCPReady(name string) serviceReady {
	q := new(dns.Msg)
	q.SetQuestion(name, dns.TypeA)
	q.Id = 0x1234
	wire, err := q.Pack()
	if err != nil {
		panic(err)
	}
	return serviceReady{
		send: append([]byte{byte(len(wire) >> 8), byte(len(wire))}, wire...),
		ok: func(b []byte) bool {
			if len(b) < 2 {
				return false
			}
			n := int(b[0])<<8 | int(b[1])
			if n == 0 || len(b) < 2+n {
				return false
			}
			var r dns.Msg
			return r.Unpack(b[2:2+n]) == nil && r.Response && r.Id == q.Id
		},
	}
}

// serving says whether the lab port answers as its daemon does.
func serving(port int) bool { return servingAs(port, readyBy[port]) }

// servingAs is one look: connect, say what the protocol says first, read
// what comes back.
func servingAs(port int, r serviceReady) bool {
	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 2*time.Second)
	if err != nil {
		return false
	}
	defer c.Close()
	wait := 2 * time.Second
	if r.ok == nil {
		wait = 400 * time.Millisecond // a closed connection is closed at once
	}
	_ = c.SetDeadline(time.Now().Add(wait))
	if len(r.send) > 0 {
		if _, err := c.Write(r.send); err != nil {
			return false
		}
	}
	buf := make([]byte, 512)
	n, err := c.Read(buf)
	if r.ok == nil {
		// Waits to be asked: serving unless something closes the connection.
		ne, isNet := err.(net.Error)
		return n > 0 || isNet && ne.Timeout()
	}
	// An answer may arrive in pieces (a DNS length, then the message).
	for n > 0 && !r.ok(buf[:n]) && err == nil && n < len(buf) {
		var m int
		m, err = c.Read(buf[n:])
		n += m
	}
	return n > 0 && r.ok(buf[:n])
}

// waitServing waits up to max for every lab service to serve, and returns
// the ports that do not.
func waitServing(max time.Duration, every time.Duration, ports []int) []int {
	deadline := time.Now().Add(max)
	for {
		var not []int
		for _, p := range ports {
			if !serving(p) {
				not = append(not, p)
			}
		}
		if len(not) == 0 || time.Now().After(deadline) {
			return not
		}
		time.Sleep(every)
	}
}

// servicesStartWait is how long the daemons of the lab get to start
// (Elasticsearch's JVM, RabbitMQ and OpenLDAP take a minute on a runner).
const servicesStartWait = 4 * time.Minute

func servicesLab() bool {
	up := func() bool {
		snap := listening()
		for _, s := range serviceTruth {
			if !listensOn(snap, strconv.Itoa(s.port)) {
				return false
			}
		}
		return true
	}
	if !up() {
		// Containers are only ever started, never stopped, by the bench.
		logf("starting the services lab")
		_ = exec.Command("docker", "compose", "-f", "bench/services.yaml", "up", "-d").Run()
		for i := 0; i < 30 && !up(); i++ {
			time.Sleep(2 * time.Second)
		}
		if !up() {
			return false
		}
	}
	// docker's proxy listens before its daemon does: nothing is timed until
	// each one answers as its protocol does.
	var ports []int
	for _, s := range serviceTruth {
		ports = append(ports, s.port)
	}
	if not := waitServing(servicesStartWait, 2*time.Second, ports); len(not) > 0 {
		var names []string
		for _, s := range serviceTruth {
			for _, p := range not {
				if s.port == p {
					names = append(names, fmt.Sprintf("%d %s", p, s.what))
				}
			}
		}
		addCheck("services: every lab daemon serves before anything is timed", false, "not serving after %s: %v (the rows for them measure a lab that was not up)", servicesStartWait, names)
	}
	return true
}

func nmapBin() string {
	if nmapAt != "" {
		return nmapAt
	}
	if refBin != "" && fileExists(refBin+"/nmap.sh") {
		return refBin + "/nmap.sh"
	}
	if p, err := exec.LookPath("nmap"); err == nil {
		return p
	}
	return ""
}

type nmapRun struct {
	Hosts []struct {
		Ports []struct {
			Protocol string `xml:"protocol,attr"`
			ID       int    `xml:"portid,attr"`
			State    struct {
				State string `xml:"state,attr"`
			} `xml:"state"`
			Service struct {
				Name    string `xml:"name,attr"`
				Product string `xml:"product,attr"`
				Version string `xml:"version,attr"`
			} `xml:"service"`
		} `xml:"ports>port"`
	} `xml:"host"`
}

func benchServices() *servicesRow {
	row := &servicesRow{Profile: prof, Ports: len(serviceTruth)}
	nmap := nmapBin()
	if nmap == "" {
		addCheck("services: nmap is installed", false, "no nmap: pass -nmap, set AZHAQ_NMAP, or extract the Ubuntu .debs with dpkg -x (no sudo) and point at a script that runs it")
		return row
	}
	if !servicesLab() {
		addCheck("services: the services lab is up", false, "docker compose -f bench/services.yaml up -d did not bring every port up; ports checked with ss")
		return row
	}
	var ps []string
	for _, s := range serviceTruth {
		ps = append(ps, strconv.Itoa(s.port))
	}
	plist := strings.Join(ps, ",")
	aa := append([]string{"ports", "-host", "127.0.0.1", "-p", plist, "-json", "-silent"}, pick([]string(nil), []string{"-rate", politePort})...)
	na := append([]string{"-sV", "-Pn", "-p", plist, "-oX", "-", "127.0.0.1"}, pick([]string(nil), []string{"--max-rate", politePort})...)
	out, am := timed("services", 20*time.Minute, work, azhaq, aa...)
	row.AzhaqSecs = am.Seconds
	azSvc, azProd := map[int]string{}, map[int]string{}
	for _, l := range lines(out) {
		var o struct {
			Port    int    `json:"port"`
			Proto   string `json:"protocol"`
			Service string `json:"service"`
			Product string `json:"product"`
			Version string `json:"version"`
		}
		if json.Unmarshal([]byte(l), &o) == nil && o.Port != 0 && (o.Proto == "" || o.Proto == "tcp") {
			azSvc[o.Port] = strings.ToLower(o.Service)
			azProd[o.Port] = strings.TrimSpace(o.Product + " " + o.Version)
		}
	}
	nout, nm := timed("services", 20*time.Minute, work, nmap, na...)
	row.NmapSecs = nm.Seconds
	nmSvc, nmProd := map[int]string{}, map[int]string{}
	var doc nmapRun
	if err := xml.Unmarshal(nout, &doc); err == nil {
		for _, h := range doc.Hosts {
			for _, p := range h.Ports {
				if p.Protocol == "tcp" && p.State.State == "open" {
					nmSvc[p.ID] = strings.ToLower(p.Service.Name)
					nmProd[p.ID] = strings.TrimSpace(p.Service.Product + " " + p.Service.Version)
				}
			}
		}
	}
	has := func(got string, names []string) bool {
		for _, n := range names {
			if strings.Contains(got, n) {
				return true
			}
		}
		return false
	}
	var azBad, nmBad []string
	for _, s := range serviceTruth {
		r := serviceRow{Port: s.port, Truth: s.what, Azhaq: azSvc[s.port], Nmap: nmSvc[s.port], Product: azProd[s.port]}
		r.AzOK = has(azSvc[s.port]+" "+strings.ToLower(azProd[s.port]), s.names)
		r.NmapOK = has(nmSvc[s.port]+" "+strings.ToLower(nmProd[s.port]), s.names)
		if r.AzOK {
			row.AzhaqNamed++
		} else {
			azBad = append(azBad, fmt.Sprintf("%d %s: %q", s.port, s.what, azSvc[s.port]))
		}
		if r.NmapOK {
			row.NmapNamed++
		} else {
			nmBad = append(nmBad, fmt.Sprintf("%d %s: %q", s.port, s.what, nmSvc[s.port]))
		}
		if azProd[s.port] != "" {
			row.AzhaqVer++
		}
		if nmProd[s.port] != "" {
			row.NmapVer++
		}
		row.Rows = append(row.Rows, r)
	}
	barOne("services (nmap -sV)", row.AzhaqNamed, row.NmapNamed, row.AzhaqSecs, row.NmapSecs, "the lab's own list of what runs on each port (bench/services.yaml) and `ss` showing every port listening",
		cmdLine(azhaq, aa...)+" vs "+cmdLine("nmap", na...),
		fmt.Sprintf("%d ports; with a product and version: azhaq %d, nmap %d; azhaq missed %v; nmap missed %v; %s%s", row.Ports, row.AzhaqVer, row.NmapVer,
			clipList(azBad, 6), clipList(nmBad, 6), ratio(row.AzhaqSecs, row.NmapSecs), azErr(am)))
	addCheck("services: azhaq names ≥ 90% of the lab's TCP services", row.AzhaqNamed*10 >= row.Ports*9, "%d of %d", row.AzhaqNamed, row.Ports)

	// UDP, which nmap -sU would need root for: asked of azhaq alone.
	if !polite() {
		uo, _ := run("services", 5*time.Minute, work, azhaq, "ports", "-host", "127.0.0.1", "-p", "none", "-pu", "10161,21211,10053", "-json", "-silent")
		row.UDP = map[string]bool{}
		for _, l := range lines(uo) {
			var o struct {
				Port    int    `json:"port"`
				State   string `json:"state"`
				Service string `json:"service"`
			}
			if json.Unmarshal([]byte(l), &o) == nil && o.Port != 0 {
				row.UDP[fmt.Sprintf("%d %s %s", o.Port, o.State, o.Service)] = true
			}
		}
		_ = os.Stdout
	}
	return row
}
