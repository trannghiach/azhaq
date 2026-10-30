package main

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
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
	{17017, "mongo", []string{"mongo"}}, {11883, "mosquitto (mqtt)", []string{"mqtt"}}, {15672, "rabbitmq (amqp)", []string{"amqp", "rabbit"}},
	{21211, "memcached", []string{"memcache"}}, {12222, "openssh", []string{"ssh"}}, {10021, "ftp", []string{"ftp"}},
	{10025, "mailpit smtp", []string{"smtp"}}, {18825, "mailpit web", []string{"http"}}, {10389, "openldap", []string{"ldap"}},
	{10445, "samba", []string{"smb", "microsoft-ds", "netbios"}}, {19200, "elasticsearch", []string{"http", "elasticsearch"}}, {10053, "coredns (tcp)", []string{"domain", "dns"}},
}

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
	if up() {
		return true
	}
	// Containers are only ever started, never stopped, by the bench.
	logf("starting the services lab")
	_ = exec.Command("docker", "compose", "-f", "bench/services.yaml", "up", "-d").Run()
	for i := 0; i < 30 && !up(); i++ {
		time.Sleep(2 * time.Second)
	}
	return up()
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
