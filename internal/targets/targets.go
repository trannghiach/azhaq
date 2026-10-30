// Package targets turns the inputs of a screenshot run that are not plain
// lines of URLs and hosts into lines that are: port lists, address ranges,
// and the web services an nmap or Nessus scan found.
package targets

import (
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// Named port lists: the ports web servers answer on, by how wide to cast.
// "small" is the two the schemes name; "medium" adds the usual alternates
// (admin panels, dev servers, proxies); "large" the long tail.
var named = map[string][]int{
	"small":  {80, 443},
	"medium": {80, 81, 443, 591, 3000, 5000, 7001, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090, 9443, 10000},
	"large": {80, 81, 88, 443, 591, 593, 832, 981, 1010, 1311, 2082, 2083, 2087, 2095, 2096, 2480, 3000, 3128, 3333,
		4243, 4443, 4567, 4711, 4712, 4993, 5000, 5104, 5108, 5280, 5281, 5601, 5800, 6543, 7000, 7001, 7396, 7474,
		7443, 8000, 8001, 8008, 8014, 8042, 8069, 8080, 8081, 8083, 8088, 8090, 8091, 8118, 8123, 8172, 8222, 8243,
		8280, 8281, 8333, 8337, 8443, 8500, 8834, 8880, 8888, 8983, 9000, 9043, 9060, 9080, 9090, 9091, 9200, 9443,
		9800, 9981, 10000, 10443, 12443, 16080, 18091, 18092, 20720, 28017},
}

// Ports reads a port list: numbers, ranges (8000-8010) and the names
// small, medium and large, separated by commas.
func Ports(spec string) ([]int, error) {
	var out []int
	seen := map[int]bool{}
	add := func(p int) {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, f := range strings.Split(spec, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if l, ok := named[strings.ToLower(f)]; ok {
			for _, p := range l {
				add(p)
			}
			continue
		}
		lo, hi, isRange := strings.Cut(f, "-")
		a, err := strconv.Atoi(lo)
		b := a
		if err == nil && isRange {
			b, err = strconv.Atoi(hi)
		}
		if err != nil || a < 1 || b > 65535 || a > b {
			return nil, fmt.Errorf("bad port %q (a number, a range such as 8000-8010, or small, medium, large)", f)
		}
		for p := a; p <= b; p++ {
			add(p)
		}
	}
	return out, nil
}

// SplitPrefixes separates the lines that are address ranges (192.0.2.0/24)
// from the rest.
func SplitPrefixes(lines []string) (rest, prefixes []string) {
	for _, l := range lines {
		if strings.Contains(l, "/") && !strings.Contains(l, "://") {
			if pf, err := netip.ParsePrefix(l); err == nil {
				prefixes = append(prefixes, pf.Masked().String())
				continue
			}
		}
		rest = append(rest, l)
	}
	return rest, prefixes
}

// Options narrow what a scan file gives.
type Options struct {
	Services  []string // service names to take; nil: the web ones; "all": every open port
	Ports     []int    // only these ports; nil: any
	Hostnames bool     // the host's name rather than its address, when the scan has one
	OpenOnly  bool     // nmap: only ports found open
}

func (o Options) port(p int) bool {
	if len(o.Ports) == 0 {
		return true
	}
	for _, x := range o.Ports {
		if x == p {
			return true
		}
	}
	return false
}

func (o Options) all() bool {
	for _, s := range o.Services {
		if strings.EqualFold(s, "all") {
			return true
		}
	}
	return false
}

// wantsService says whether a service name is taken: one of those asked for,
// or, when none were, any that is HTTP.
func (o Options) wantsService(name string) bool {
	name = strings.ToLower(name)
	if o.all() {
		return true
	}
	if len(o.Services) == 0 {
		return strings.Contains(name, "http") || name == "www"
	}
	for _, s := range o.Services {
		if strings.EqualFold(strings.TrimSpace(s), name) {
			return true
		}
	}
	return false
}

// line is the URL of a web service: the port left out when it is the scheme's.
func line(tls bool, host string, port int) string {
	scheme := "http"
	if tls {
		scheme = "https"
	}
	if ip := net.ParseIP(host); ip != nil && strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if (!tls && port == 80) || (tls && port == 443) {
		return scheme + "://" + host + "/"
	}
	return scheme + "://" + host + ":" + strconv.Itoa(port) + "/"
}

type nmapRun struct {
	Hosts []struct {
		Status struct {
			State string `xml:"state,attr"`
		} `xml:"status"`
		Addresses []struct {
			Addr string `xml:"addr,attr"`
			Type string `xml:"addrtype,attr"`
		} `xml:"address"`
		Hostnames []struct {
			Name string `xml:"name,attr"`
		} `xml:"hostnames>hostname"`
		Ports []struct {
			Protocol string `xml:"protocol,attr"`
			ID       int    `xml:"portid,attr"`
			State    struct {
				State string `xml:"state,attr"`
			} `xml:"state"`
			Service struct {
				Name   string `xml:"name,attr"`
				Tunnel string `xml:"tunnel,attr"`
			} `xml:"service"`
		} `xml:"ports>port"`
	} `xml:"host"`
}

// NmapXML reads the web services of an nmap -oX file as URL lines.
func NmapXML(r io.Reader, o Options) ([]string, error) {
	var run nmapRun
	if err := xml.NewDecoder(r).Decode(&run); err != nil {
		return nil, fmt.Errorf("not an nmap XML file: %w", err)
	}
	var out []string
	seen := map[string]bool{}
	for _, h := range run.Hosts {
		if h.Status.State != "" && h.Status.State != "up" {
			continue
		}
		host := ""
		for _, a := range h.Addresses {
			if a.Type == "ipv4" || a.Type == "ipv6" {
				host = a.Addr
				break
			}
		}
		if o.Hostnames && len(h.Hostnames) > 0 {
			host = h.Hostnames[0].Name
		}
		if host == "" {
			continue
		}
		for _, p := range h.Ports {
			if p.Protocol != "tcp" || !o.port(p.ID) || (o.OpenOnly && p.State.State != "open") {
				continue
			}
			if !o.wantsService(p.Service.Name) {
				continue
			}
			name := strings.ToLower(p.Service.Name)
			tls := p.Service.Tunnel == "ssl" || strings.HasPrefix(name, "https") || strings.Contains(name, "ssl/http")
			if o.all() && !strings.Contains(name, "http") && p.Service.Tunnel != "ssl" {
				tls = p.ID == 443 // a port of no web service: its usual scheme
			}
			l := line(tls, host, p.ID)
			if !seen[l] {
				seen[l] = true
				out = append(out, l)
			}
		}
	}
	return out, nil
}

type nessusFile struct {
	Hosts []struct {
		Name string `xml:"name,attr"`
		Tags []struct {
			Name  string `xml:"name,attr"`
			Value string `xml:",chardata"`
		} `xml:"HostProperties>tag"`
		Items []struct {
			Port       int    `xml:"port,attr"`
			Protocol   string `xml:"protocol,attr"`
			Service    string `xml:"svc_name,attr"`
			PluginName string `xml:"pluginName,attr"`
			Output     string `xml:"plugin_output"`
		} `xml:"ReportItem"`
	} `xml:"Report>ReportHost"`
}

// Nessus reads the web services of a .nessus file as URL lines: the
// items the scanner named a web service (service www, http or https, or
// "web server" in the output of its service detection).
func Nessus(r io.Reader, o Options) ([]string, error) {
	var f nessusFile
	if err := xml.NewDecoder(r).Decode(&f); err != nil {
		return nil, fmt.Errorf("not a Nessus file: %w", err)
	}
	if len(o.Services) == 0 {
		o.Services = []string{"www", "http", "https"}
	}
	var out []string
	seen := map[string]bool{}
	for _, h := range f.Hosts {
		host := h.Name
		if o.Hostnames {
			for _, t := range h.Tags {
				if t.Name == "host-fqdn" && strings.TrimSpace(t.Value) != "" {
					host = strings.TrimSpace(t.Value)
				}
			}
		}
		if host == "" {
			continue
		}
		for _, it := range h.Items {
			if it.Port == 0 || (it.Protocol != "" && it.Protocol != "tcp") || !o.port(it.Port) {
				continue
			}
			web := o.wantsService(it.Service) ||
				(strings.Contains(strings.ToLower(it.PluginName), "service detection") && strings.Contains(strings.ToLower(it.Output), "web server"))
			if !web {
				continue
			}
			out2 := strings.ToLower(it.Output)
			tls := strings.EqualFold(it.Service, "https") || strings.Contains(out2, "tls") || strings.Contains(out2, "ssl")
			l := line(tls, host, it.Port)
			if !seen[l] {
				seen[l] = true
				out = append(out, l)
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

// Expand gives each bare host, address or host:port line a URL line per
// port asked for (443 then 80 without any), over the scheme asked for;
// where both may do, the line is host:port, which the run reads as https
// with a fall back to http. Lines that are URLs are kept as they are.
func Expand(lines []string, ports []int, noHTTP, noHTTPS bool) []string {
	var out []string
	for _, l := range lines {
		if strings.Contains(l, "://") {
			out = append(out, l)
			continue
		}
		host, port, err := net.SplitHostPort(l)
		if err != nil {
			host, port = strings.Trim(l, "[]"), ""
		}
		var ps []int
		switch {
		case port != "":
			n, err := strconv.Atoi(port)
			if err != nil {
				out = append(out, l)
				continue
			}
			ps = []int{n}
		case len(ports) > 0:
			ps = ports
		default:
			ps = []int{443}
			if noHTTPS {
				ps = []int{80}
			}
		}
		for _, p := range ps {
			switch {
			case noHTTP && noHTTPS:
			case noHTTP:
				out = append(out, line(true, host, p))
			case noHTTPS:
				out = append(out, line(false, host, p))
			case p == 80:
				out = append(out, line(false, host, 80))
			case p == 443:
				out = append(out, line(true, host, 443))
			default:
				hp := net.JoinHostPort(host, strconv.Itoa(p))
				out = append(out, hp)
			}
		}
	}
	return out
}
