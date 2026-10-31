package main

// The nmap XML and greppable writers follow projectdiscovery/naabu
// pkg/runner/output_nmap.go (MIT): the element names, the DTD subset and the
// layout of the greppable line are its.

import (
	"bytes"
	"encoding/csv"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// portRow is one result of a port scan: an open port, or with -sn an
// address that is up.
type portRow struct {
	Host, IP string
	Port     int
	Proto    string // tcp or udp; empty for an address that is up
	State    string // open, open|filtered, or up
	TLS      bool
	CDN      string
	At       time.Time
	Fields   map[string]any // service, product, version, banner, title, subject_cn, subject_an
}

func (r portRow) str(k string) string { s, _ := r.Fields[k].(string); return s }

// the fields a row of -json and -csv has, in the order -csv writes them.
var portFields = []string{"host", "ip", "port", "protocol", "state", "tls", "cdn", "cdn-name", "timestamp", "service", "product", "version", "banner", "title", "subject_cn", "subject_an"}

// jsonRow is the row as -json prints it: naabu's fields (cdn is whether
// the address is a CDN's, cdn-name whose), and azhaq's service ones.
func (r portRow) jsonRow() map[string]any {
	row := map[string]any{"host": r.Host, "ip": r.IP, "protocol": r.Proto, "timestamp": r.At.UTC().Format(time.RFC3339Nano)}
	if r.State == "up" {
		delete(row, "protocol")
		row["up"] = true
		return row
	}
	row["port"] = r.Port
	if r.Proto == "tcp" {
		row["tls"] = r.TLS
		row["cdn"] = r.CDN != ""
		if r.CDN != "" {
			row["cdn-name"] = r.CDN
		}
	}
	if r.Proto == "udp" {
		row["state"] = r.State
	}
	for k, v := range r.Fields {
		row[k] = v
	}
	return row
}

// csvRow is the row's values for the columns of portFields.
func (r portRow) csvRow(cols []string) []string {
	j := r.jsonRow()
	out := make([]string, len(cols))
	for i, c := range cols {
		switch v := j[c].(type) {
		case nil:
		case []string:
			out[i] = strings.Join(v, " ")
		case []any:
			var parts []string
			for _, x := range v {
				parts = append(parts, fmt.Sprint(x))
			}
			out[i] = strings.Join(parts, " ")
		default:
			out[i] = fmt.Sprint(v)
		}
	}
	return out
}

// portOut writes the results of a port scan in the formats asked for:
// text, JSON lines or CSV as each is found, nmap XML and greppable files
// when the scan is done.
type portOut struct {
	w        *writer
	csv      bool
	exclude  map[string]bool
	xmlPath  string
	gnmapOut string
	jsonPath string // -oA's JSON lines
	quiet    bool   // the text lines are not printed: stdout holds an XML or greppable document

	mu   sync.Mutex
	rows []portRow
	keep bool
	head bool
}

// columns are the fields -csv writes: all of portFields but the excluded.
func (o *portOut) columns() []string {
	var cols []string
	for _, c := range portFields {
		if !o.exclude[c] {
			cols = append(cols, c)
		}
	}
	return cols
}

func (o *portOut) add(r portRow) {
	if o.keep {
		o.mu.Lock()
		o.rows = append(o.rows, r)
		o.mu.Unlock()
	}
	if o.quiet {
		o.w.mu.Lock()
		o.w.n++
		o.w.mu.Unlock()
		return
	}
	switch {
	case o.csv:
		o.w.record(o.columns(), r.csvRow(o.columns()))
	case o.w.json:
		row := r.jsonRow()
		for k := range o.exclude {
			delete(row, k)
		}
		o.w.obj(row)
	case r.State == "up":
		o.w.line(r.IP)
	case r.Proto == "udp":
		line := r.Host + ":" + strconv.Itoa(r.Port) + "/udp"
		if r.State != "open" {
			line += " " + r.State // a silent port is not an answering one: the state tells which
		}
		o.w.line(line)
	default:
		o.w.line(r.Host + ":" + strconv.Itoa(r.Port))
	}
}

// record writes one CSV record, the header first.
func (w *writer) record(cols, rec []string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	var b bytes.Buffer
	cw := csv.NewWriter(&b)
	if !w.headed {
		w.headed = true
		_ = cw.Write(cols)
	}
	_ = cw.Write(rec)
	cw.Flush()
	w.w.Write(b.Bytes())
	w.w.Flush()
	w.n++
}

// finish writes the files that need every result: nmap XML, greppable
// and the JSON lines of -oA.
func (o *portOut) finish(args []string, start, end time.Time) error {
	rows := append([]portRow(nil), o.rows...)
	hosts := nmapHosts(rows)
	var err error
	emit := func(path string, write func(io.Writer) error) {
		if path == "" || err != nil {
			return
		}
		if path == "-" {
			err = write(os.Stdout)
			return
		}
		if dir := filepath.Dir(path); dir != "." {
			if err = os.MkdirAll(dir, 0o755); err != nil {
				return
			}
		}
		var f *os.File
		if f, err = os.Create(path); err != nil {
			return
		}
		err = write(f)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}
	emit(o.xmlPath, func(w io.Writer) error { return writeNmapXML(w, hosts, args, start, end) })
	emit(o.gnmapOut, func(w io.Writer) error { return writeGreppable(w, hosts, start, end) })
	emit(o.jsonPath, func(w io.Writer) error {
		for _, r := range rows {
			row := r.jsonRow()
			for k := range o.exclude {
				delete(row, k)
			}
			raw, _ := jsonLine(row)
			if _, err := w.Write(raw); err != nil {
				return err
			}
		}
		return nil
	})
	return err
}

type nmapHost struct {
	ip, name string
	up       bool
	ports    []portRow
}

// nmapHosts groups rows by address, in address order, each one's ports by
// number.
func nmapHosts(rows []portRow) []nmapHost {
	by := map[string]*nmapHost{}
	for _, r := range rows {
		h := by[r.IP]
		if h == nil {
			h = &nmapHost{ip: r.IP}
			by[r.IP] = h
		}
		if r.Host != r.IP && h.name == "" {
			h.name = r.Host
		}
		h.up = true
		if r.State != "up" {
			h.ports = append(h.ports, r)
		}
	}
	out := make([]nmapHost, 0, len(by))
	for _, h := range by {
		sort.SliceStable(h.ports, func(i, j int) bool {
			if h.ports[i].Port != h.ports[j].Port {
				return h.ports[i].Port < h.ports[j].Port
			}
			return h.ports[i].Proto < h.ports[j].Proto
		})
		out = append(out, *h)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := net.ParseIP(out[i].ip), net.ParseIP(out[j].ip)
		if a == nil || b == nil {
			return out[i].ip < out[j].ip
		}
		return bytes.Compare(a.To16(), b.To16()) < 0
	})
	return out
}

// --- XML: the subset of nmap's DTD that naabu writes, enough for the
// tools that read nmap's output ---

type xmlRun struct {
	XMLName          xml.Name    `xml:"nmaprun"`
	Scanner          string      `xml:"scanner,attr"`
	Args             string      `xml:"args,attr,omitempty"`
	Start            int64       `xml:"start,attr"`
	StartStr         string      `xml:"startstr,attr"`
	Version          string      `xml:"version,attr"`
	XMLOutputVersion string      `xml:"xmloutputversion,attr"`
	ScanInfo         []xmlInfo   `xml:"scaninfo"`
	Hosts            []xmlHost   `xml:"host"`
	RunStats         xmlRunStats `xml:"runstats"`
}

type xmlInfo struct {
	Type     string `xml:"type,attr"`
	Protocol string `xml:"protocol,attr"`
}

type xmlHost struct {
	Status    xmlStatus     `xml:"status"`
	Addresses []xmlAddress  `xml:"address"`
	Hostnames *xmlHostnames `xml:"hostnames,omitempty"`
	Ports     *xmlPorts     `xml:"ports,omitempty"`
}

type xmlStatus struct {
	State  string `xml:"state,attr"`
	Reason string `xml:"reason,attr,omitempty"`
}

type xmlAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

type xmlHostnames struct {
	Hostnames []xmlHostname `xml:"hostname"`
}

type xmlHostname struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

type xmlPorts struct {
	Ports []xmlPort `xml:"port"`
}

type xmlPort struct {
	Protocol string       `xml:"protocol,attr"`
	PortID   int          `xml:"portid,attr"`
	State    xmlPortState `xml:"state"`
	Service  *xmlService  `xml:"service,omitempty"`
}

type xmlPortState struct {
	State  string `xml:"state,attr"`
	Reason string `xml:"reason,attr,omitempty"`
}

type xmlService struct {
	Name    string `xml:"name,attr,omitempty"`
	Product string `xml:"product,attr,omitempty"`
	Version string `xml:"version,attr,omitempty"`
	Tunnel  string `xml:"tunnel,attr,omitempty"`
	Method  string `xml:"method,attr,omitempty"`
	Conf    int    `xml:"conf,attr,omitempty"`
}

type xmlRunStats struct {
	Finished xmlFinished  `xml:"finished"`
	Hosts    xmlHostsStat `xml:"hosts"`
}

type xmlFinished struct {
	Time    int64  `xml:"time,attr"`
	TimeStr string `xml:"timestr,attr"`
	Elapsed string `xml:"elapsed,attr"`
	Exit    string `xml:"exit,attr"`
}

type xmlHostsStat struct {
	Up    int `xml:"up,attr"`
	Down  int `xml:"down,attr"`
	Total int `xml:"total,attr"`
}

const nmapTimeLayout = "Mon Jan 2 15:04:05 2006"

func addrType(ip string) string {
	if p := net.ParseIP(ip); p != nil && p.To4() == nil {
		return "ipv6"
	}
	return "ipv4"
}

func newXMLService(r portRow) *xmlService {
	name := r.str("service")
	if name == "" {
		return nil
	}
	s := &xmlService{Name: strings.TrimSuffix(name, "?"), Product: r.str("product"), Version: r.str("version"), Method: "probed", Conf: 10}
	if strings.HasSuffix(name, "?") {
		s.Method, s.Conf = "table", 3 // named from the port number only
	}
	if r.TLS {
		s.Tunnel = "ssl"
	}
	return s
}

func writeNmapXML(w io.Writer, hosts []nmapHost, args []string, start, end time.Time) error {
	run := xmlRun{
		Scanner:          "azhaq",
		Args:             "azhaq ports " + strings.Join(args, " "),
		Start:            start.Unix(),
		StartStr:         start.Format(nmapTimeLayout),
		Version:          version,
		XMLOutputVersion: "1.05",
		ScanInfo:         []xmlInfo{{Type: "connect", Protocol: "tcp"}},
	}
	udp := false
	for _, h := range hosts {
		xh := xmlHost{Status: xmlStatus{State: "up", Reason: "user-set"}, Addresses: []xmlAddress{{Addr: h.ip, AddrType: addrType(h.ip)}}}
		if h.name != "" {
			xh.Hostnames = &xmlHostnames{Hostnames: []xmlHostname{{Name: h.name, Type: "user"}}}
		}
		if len(h.ports) > 0 {
			xh.Status.Reason = "syn-ack"
			xp := &xmlPorts{}
			for _, p := range h.ports {
				reason := "syn-ack"
				if p.Proto == "udp" {
					udp = true
					reason = "udp-response"
					if p.State != "open" {
						reason = "no-response"
					}
				}
				xp.Ports = append(xp.Ports, xmlPort{Protocol: p.Proto, PortID: p.Port, State: xmlPortState{State: p.State, Reason: reason}, Service: newXMLService(p)})
			}
			xh.Ports = xp
		}
		run.Hosts = append(run.Hosts, xh)
	}
	if udp {
		run.ScanInfo = append(run.ScanInfo, xmlInfo{Type: "udp", Protocol: "udp"})
	}
	run.RunStats = xmlRunStats{
		Finished: xmlFinished{Time: end.Unix(), TimeStr: end.Format(nmapTimeLayout), Elapsed: fmt.Sprintf("%.2f", end.Sub(start).Seconds()), Exit: "success"},
		Hosts:    xmlHostsStat{Up: len(hosts), Total: len(hosts)},
	}
	if _, err := io.WriteString(w, xml.Header+"<!DOCTYPE nmaprun>\n"); err != nil {
		return err
	}
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(run); err != nil {
		return err
	}
	_, err := io.WriteString(w, "\n")
	return err
}

// grepSanitize strips the field separators greppable output relies on.
func grepSanitize(s string) string {
	return strings.NewReplacer("/", "|", ",", ";", "\n", " ", "\t", " ").Replace(s)
}

// writeGreppable is nmap's greppable (-oG) layout.
func writeGreppable(w io.Writer, hosts []nmapHost, start, end time.Time) error {
	if _, err := fmt.Fprintf(w, "# azhaq %s scan initiated %s\n", version, start.Format(nmapTimeLayout)); err != nil {
		return err
	}
	for _, h := range hosts {
		name := grepSanitize(h.name)
		if name == "" {
			name = h.ip
		}
		if len(h.ports) == 0 {
			if _, err := fmt.Fprintf(w, "Host: %s (%s)\tStatus: Up\n", h.ip, name); err != nil {
				return err
			}
			continue
		}
		var parts []string
		for _, p := range h.ports {
			svc := grepSanitize(strings.TrimSuffix(p.str("service"), "?"))
			ver := grepSanitize(strings.TrimSpace(p.str("product") + " " + p.str("version")))
			// portid/state/protocol/owner/service/rpc/version
			parts = append(parts, fmt.Sprintf("%d/%s/%s//%s//%s/", p.Port, p.State, p.Proto, svc, ver))
		}
		if _, err := fmt.Fprintf(w, "Host: %s (%s)\tPorts: %s\n", h.ip, name, strings.Join(parts, ", ")); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintf(w, "# azhaq done at %s -- %d IP addresses (%d hosts up) scanned\n", end.Format(nmapTimeLayout), len(hosts), len(hosts))
	return err
}
