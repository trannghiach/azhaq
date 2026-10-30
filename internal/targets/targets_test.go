package targets

import (
	"slices"
	"strings"
	"testing"
)

func TestPorts(t *testing.T) {
	got, err := Ports("80,8000-8002,443,80")
	if err != nil || !slices.Equal(got, []int{80, 8000, 8001, 8002, 443}) {
		t.Errorf("got %v, %v", got, err)
	}
	for _, n := range []string{"small", "medium", "large"} {
		l, err := Ports(n)
		if err != nil || len(l) < 2 || !slices.Contains(l, 443) {
			t.Errorf("%s: %v, %v", n, l, err)
		}
	}
	s, _ := Ports("small")
	m, _ := Ports("medium")
	l, _ := Ports("large")
	if !(len(s) < len(m) && len(m) < len(l)) {
		t.Errorf("lists %d, %d, %d are not widening", len(s), len(m), len(l))
	}
	for _, bad := range []string{"0", "70000", "x", "9-3", "80-"} {
		if _, err := Ports(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestSplitPrefixes(t *testing.T) {
	rest, pf := SplitPrefixes([]string{"10.0.0.5/24", "host:80", "http://x/a/b", "2001:db8::/32", "10.0.0.1"})
	if !slices.Equal(pf, []string{"10.0.0.0/24", "2001:db8::/32"}) || !slices.Equal(rest, []string{"host:80", "http://x/a/b", "10.0.0.1"}) {
		t.Errorf("prefixes %v, rest %v", pf, rest)
	}
}

const nmapXML = `<?xml version="1.0"?>
<nmaprun scanner="nmap">
<host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/>
<hostnames><hostname name="localhost" type="user"/></hostnames>
<ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
<port protocol="tcp" portid="3001"><state state="open"/><service name="http" product="Express"/></port>
<port protocol="tcp" portid="8443"><state state="open"/><service name="http" tunnel="ssl"/></port>
<port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port>
<port protocol="tcp" portid="8080"><state state="closed"/><service name="http-proxy"/></port>
<port protocol="udp" portid="80"><state state="open"/><service name="http"/></port>
</ports></host>
<host><status state="down"/><address addr="10.0.0.9" addrtype="ipv4"/></host>
<host><status state="up"/><address addr="2001:db8::1" addrtype="ipv6"/><ports>
<port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port></ports></host>
</nmaprun>`

func TestNmapXML(t *testing.T) {
	got, err := NmapXML(strings.NewReader(nmapXML), Options{OpenOnly: true})
	want := []string{"http://127.0.0.1:3001/", "https://127.0.0.1:8443/", "https://127.0.0.1/", "http://[2001:db8::1]/"}
	if err != nil || !slices.Equal(got, want) {
		t.Errorf("got %v, %v", got, err)
	}
	got, _ = NmapXML(strings.NewReader(nmapXML), Options{OpenOnly: false, Hostnames: true, Ports: []int{8080, 3001}})
	if !slices.Equal(got, []string{"http://localhost:3001/", "http://localhost:8080/"}) {
		t.Errorf("ports and names: %v", got)
	}
	got, _ = NmapXML(strings.NewReader(nmapXML), Options{OpenOnly: true, Services: []string{"all"}, Ports: []int{22}})
	if !slices.Equal(got, []string{"http://127.0.0.1:22/"}) {
		t.Errorf("all services: %v", got)
	}
	if _, err := NmapXML(strings.NewReader("not xml"), Options{}); err == nil {
		t.Error("garbage read")
	}
}

const nessusXML = `<?xml version="1.0"?>
<NessusClientData_v2><Report name="r">
<ReportHost name="192.0.2.10"><HostProperties><tag name="host-fqdn">app.example.test</tag></HostProperties>
<ReportItem port="443" svc_name="www" protocol="tcp" pluginName="Service Detection"><plugin_output>A TLS-based web server is running on this port.</plugin_output></ReportItem>
<ReportItem port="80" svc_name="www" protocol="tcp" pluginName="Service Detection"><plugin_output>A web server is running on this port.</plugin_output></ReportItem>
<ReportItem port="22" svc_name="ssh" protocol="tcp" pluginName="SSH"><plugin_output>x</plugin_output></ReportItem>
<ReportItem port="8081" svc_name="unknown" protocol="tcp" pluginName="Service Detection"><plugin_output>A web server is running on this port.</plugin_output></ReportItem>
<ReportItem port="0" svc_name="general" protocol="tcp" pluginName="Host"><plugin_output>x</plugin_output></ReportItem>
</ReportHost></Report></NessusClientData_v2>`

func TestNessus(t *testing.T) {
	got, err := Nessus(strings.NewReader(nessusXML), Options{})
	want := []string{"http://192.0.2.10/", "http://192.0.2.10:8081/", "https://192.0.2.10/"}
	if err != nil || !slices.Equal(got, want) {
		t.Errorf("got %v, %v", got, err)
	}
	got, _ = Nessus(strings.NewReader(nessusXML), Options{Hostnames: true, Ports: []int{443}})
	if !slices.Equal(got, []string{"https://app.example.test/"}) {
		t.Errorf("names: %v", got)
	}
}

func TestExpand(t *testing.T) {
	got := Expand([]string{"10.0.0.1", "app.test:8080", "https://x/a?b=1", "[::1]"}, []int{80, 443, 3000}, false, false)
	want := []string{"http://10.0.0.1/", "https://10.0.0.1/", "10.0.0.1:3000", "app.test:8080", "https://x/a?b=1", "http://[::1]/", "https://[::1]/", "[::1]:3000"}
	if !slices.Equal(got, want) {
		t.Errorf("got %v", got)
	}
	if got := Expand([]string{"h", "h:81"}, []int{3000}, true, false); !slices.Equal(got, []string{"https://h:3000/", "https://h:81/"}) {
		t.Errorf("no-http: %v", got)
	}
	if got := Expand([]string{"h"}, nil, false, true); !slices.Equal(got, []string{"http://h/"}) {
		t.Errorf("no-https: %v", got)
	}
}
