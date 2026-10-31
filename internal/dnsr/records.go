package dnsr

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/trannghiach/azhaq/internal/normalize"
)

// Data is what a name's DNS records say, in the fields and the order dnsx
// writes them (retryabledns' DNSData): a record kind is left out when the
// name has none of it.
type Data struct {
	Host           string    `json:"host,omitempty"`
	TTL            uint32    `json:"ttl,omitempty"` // of the first record that has one
	Resolver       []string  `json:"resolver,omitempty"`
	A              []string  `json:"a,omitempty"`
	AAAA           []string  `json:"aaaa,omitempty"`
	CNAME          []string  `json:"cname,omitempty"`
	MX             []string  `json:"mx,omitempty"`
	PTR            []string  `json:"ptr,omitempty"`
	SOA            []SOA     `json:"soa,omitempty"`
	NS             []string  `json:"ns,omitempty"`
	TXT            []string  `json:"txt,omitempty"`
	SRV            []string  `json:"srv,omitempty"`
	CAA            []string  `json:"caa,omitempty"`
	AllRecords     []string  `json:"all,omitempty"`
	Raw            string    `json:"raw,omitempty"`
	HasInternalIPs bool      `json:"has_internal_ips,omitempty"`
	InternalIPs    []string  `json:"internal_ips,omitempty"`
	StatusCode     string    `json:"status_code,omitempty"`
	StatusCodeRaw  int       `json:"status_code_raw,omitempty"`
	TraceData      *Chain    `json:"trace,omitempty"`
	AXFRData       *Chain    `json:"axfr,omitempty"`
	Timestamp      time.Time `json:"timestamp,omitempty"`
	HostsFile      bool      `json:"hosts_file,omitempty"`
	Failures       []Failure `json:"-"`
	answered       bool      // some resolver answered
	rcodes         map[uint16]int
}

// Chain is a list of answers under a host: the steps of a trace, or the
// servers that transferred a zone.
type Chain struct {
	Host string  `json:"host,omitempty"`
	Data []*Data `json:"chain,omitempty"`
}

// SOA is a start-of-authority record.
type SOA struct {
	Name    string `json:"name,omitempty"`
	NS      string `json:"ns,omitempty"`
	Mbox    string `json:"mailbox,omitempty"`
	Serial  uint32 `json:"serial,omitempty"`
	Refresh uint32 `json:"refresh,omitempty"`
	Retry   uint32 `json:"retry,omitempty"`
	Expire  uint32 `json:"expire,omitempty"`
	Minttl  uint32 `json:"minttl,omitempty"`
}

// Failure is a question no resolver answered.
type Failure struct {
	Type string
	Err  error
}

// Answered says whether any resolver answered, whatever the code.
func (d *Data) Answered() bool { return d.answered }

// Rcode is the code of the answer to the question of type qtype, and
// whether there was one.
func (d *Data) Rcode(qtype uint16) (int, bool) {
	c, ok := d.rcodes[qtype]
	return c, ok
}

// Has says whether the name has a record of the kind (as dns type).
func (d *Data) Has(qtype uint16) bool {
	switch qtype {
	case dns.TypeA:
		return len(d.A) > 0
	case dns.TypeAAAA:
		return len(d.AAAA) > 0
	case dns.TypeCNAME:
		return len(d.CNAME) > 0
	case dns.TypeMX:
		return len(d.MX) > 0
	case dns.TypePTR:
		return len(d.PTR) > 0
	case dns.TypeSOA:
		return len(d.SOA) > 0
	case dns.TypeNS:
		return len(d.NS) > 0
	case dns.TypeTXT:
		return len(d.TXT) > 0
	case dns.TypeSRV:
		return len(d.SRV) > 0
	case dns.TypeCAA:
		return len(d.CAA) > 0
	}
	return false
}

// Any says whether the name has a record of any kind.
func (d *Data) Any() bool {
	for _, t := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeCNAME, dns.TypeMX, dns.TypePTR, dns.TypeSOA, dns.TypeNS, dns.TypeTXT, dns.TypeSRV, dns.TypeCAA} {
		if d.Has(t) {
			return true
		}
	}
	return false
}

// LookupOptions say what Lookup asks.
type LookupOptions struct {
	Types []uint16 // A when empty
	Raw   bool     // keep the dig-style text of each answer in Data.Raw
	Hosts *Hosts   // answers from a hosts file come first, and A and AAAA are not asked for them
}

// Lookup asks for the record types of host, one question each, as dnsx
// does, and merges the answers. A question is retried on other resolvers
// when it times out or is answered SERVFAIL or REFUSED; an A question that
// gets no address is put to a second resolver once (see resolve). It never
// returns nil: Answered says whether anyone replied, Failures the
// questions that got no answer at all.
func (p *Pool) Lookup(ctx context.Context, host string, o LookupOptions) *Data {
	d := &Data{Host: host, rcodes: map[uint16]int{}}
	types := o.Types
	if len(types) == 0 {
		types = []uint16{dns.TypeA}
	}
	fromHosts := map[uint16]bool{}
	if o.Hosts != nil {
		for _, ip := range o.Hosts.Lookup(host) {
			if v4 := net.ParseIP(ip).To4(); v4 != nil {
				d.A = append(d.A, ip)
				fromHosts[dns.TypeA] = true
			} else {
				d.AAAA = append(d.AAAA, ip)
				fromHosts[dns.TypeAAAA] = true
			}
			d.HostsFile = true
		}
		if d.HostsFile {
			d.answered = true
			d.Timestamp = time.Now()
		}
	}
	for _, qt := range types {
		if fromHosts[qt] {
			continue
		}
		name := dns.Fqdn(host)
		if qt == dns.TypePTR {
			if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
				rev, err := dns.ReverseAddr(ip.String())
				if err != nil {
					d.Failures = append(d.Failures, Failure{dns.TypeToString[qt], err})
					continue
				}
				name = rev
			}
		}
		q := question(name, qt)
		m, from, err := p.query(ctx, q, "")
		if m == nil {
			if err == nil {
				err = errors.New("no answer")
			}
			d.Failures = append(d.Failures, Failure{dns.TypeToString[qt], err})
			continue
		}
		if err == nil && qt == dns.TypeA && !hasAnswer(m, dns.TypeA) && !bulk(ctx) && p.confirms(strings.TrimSuffix(host, ".")) {
			// One resolver's NXDOMAIN or empty answer is not the name dead:
			// see resolve.
			if m2, _, err2 := p.query(ctx, q, from); err2 == nil && m2.Rcode == dns.RcodeSuccess && hasAnswer(m2, dns.TypeA) {
				m = m2
			}
		}
		d.add(m, from, qt, o.Raw)
		if err != nil {
			d.Failures = append(d.Failures, Failure{dns.TypeToString[qt], err})
		}
	}
	d.dedupe()
	return d
}

func hasAnswer(m *dns.Msg, qtype uint16) bool {
	for _, rr := range m.Answer {
		if rr.Header().Rrtype == qtype {
			return true
		}
	}
	return false
}

// add merges one response.
func (d *Data) add(m *dns.Msg, from string, qtype uint16, raw bool) {
	d.parse(m.Answer)
	d.answered = true
	d.rcodes[qtype] = m.Rcode
	d.StatusCode = dns.RcodeToString[m.Rcode]
	d.StatusCodeRaw = m.Rcode
	d.Timestamp = time.Now()
	if from != "" {
		d.Resolver = append(d.Resolver, from)
	}
	if raw {
		d.Raw += m.String()
	}
}

// parse reads records as dnsx does: names without their final dot, the
// host of an MX, NS, PTR or SRV (not its numbers), a CAA's value, the
// strings of a TXT joined.
func (d *Data) parse(rrs []dns.RR) {
	for _, rr := range rrs {
		if d.TTL == 0 && rr.Header().Ttl > 0 {
			d.TTL = rr.Header().Ttl
		}
		switch r := rr.(type) {
		case *dns.A:
			d.A = append(d.A, r.A.String())
			d.internal(r.A)
		case *dns.AAAA:
			d.AAAA = append(d.AAAA, r.AAAA.String())
			d.internal(r.AAAA)
		case *dns.CNAME:
			d.CNAME = append(d.CNAME, trimDot(r.Target))
		case *dns.NS:
			d.NS = append(d.NS, trimDot(r.Ns))
		case *dns.MX:
			d.MX = append(d.MX, trimDot(r.Mx))
		case *dns.PTR:
			d.PTR = append(d.PTR, trimDot(r.Ptr))
		case *dns.SOA:
			d.SOA = append(d.SOA, SOA{Name: trimDot(r.Hdr.Name), NS: trimDot(r.Ns), Mbox: trimDot(r.Mbox),
				Serial: r.Serial, Refresh: r.Refresh, Retry: r.Retry, Expire: r.Expire, Minttl: r.Minttl})
		case *dns.TXT:
			d.TXT = append(d.TXT, strings.Join(r.Txt, ""))
		case *dns.SRV:
			d.SRV = append(d.SRV, trimDot(r.Target))
		case *dns.CAA:
			d.CAA = append(d.CAA, r.Value)
		}
		d.AllRecords = append(d.AllRecords, rr.String())
	}
}

func trimDot(s string) string { return strings.TrimRight(s, ".") }

// internal marks an address in a private, loopback, link-local, documentation
// or multicast range, as dnsx does.
func (d *Data) internal(ip net.IP) {
	if internalNets.contains(ip) {
		d.HasInternalIPs = true
		d.InternalIPs = append(d.InternalIPs, ip.String())
	}
}

type nets []*net.IPNet

func (n nets) contains(ip net.IP) bool {
	for _, x := range n {
		if x.Contains(ip) {
			return true
		}
	}
	return false
}

// internalNets are the ranges dnsx marks: its lists, unchanged.
var internalNets = func() nets {
	var out nets
	for _, c := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
		"192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15",
		"198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
		"::1/128", "64:ff9b::/96", "100::/64", "2001::/32", "2001:10::/28", "2001:20::/28",
		"2001:db8::/32", "2002::/16", "fc00::/7", "fe80::/10", "ff00::/8",
	} {
		if _, n, err := net.ParseCIDR(c); err == nil {
			out = append(out, n)
		}
	}
	return out
}()

func dedupe[T comparable](xs []T) []T {
	if len(xs) < 2 {
		return xs
	}
	seen := make(map[T]bool, len(xs))
	out := xs[:0:0]
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

func (d *Data) dedupe() {
	d.Resolver = dedupe(d.Resolver)
	d.A = dedupe(d.A)
	d.AAAA = dedupe(d.AAAA)
	d.CNAME = dedupe(d.CNAME)
	d.MX = dedupe(d.MX)
	d.PTR = dedupe(d.PTR)
	d.NS = dedupe(d.NS)
	d.TXT = dedupe(d.TXT)
	d.SRV = dedupe(d.SRV)
	d.SOA = dedupe(d.SOA)
	d.CAA = dedupe(d.CAA)
	d.AllRecords = dedupe(d.AllRecords)
}

// Hosts is a hosts file, name → addresses.
type Hosts struct {
	byName map[string][]string
}

var (
	systemHostsOnce sync.Once
	systemHosts     *Hosts
)

// HostsPath is the system hosts file.
var HostsPath = "/etc/hosts"

// SystemHosts reads the hosts file once.
func SystemHosts() *Hosts {
	systemHostsOnce.Do(func() {
		raw, _ := os.ReadFile(HostsPath)
		systemHosts = ParseHosts(string(raw))
	})
	return systemHosts
}

// ParseHosts reads the lines of a hosts file: an address, then names.
func ParseHosts(text string) *Hosts {
	h := &Hosts{byName: map[string][]string{}}
	for _, line := range strings.Split(text, "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		f := strings.Fields(line)
		if len(f) < 2 || net.ParseIP(f[0]) == nil {
			continue
		}
		for _, n := range f[1:] {
			n = normalize.Hostname(n)
			h.byName[n] = append(h.byName[n], net.ParseIP(f[0]).String())
		}
	}
	return h
}

// Lookup is the addresses a name has in the file.
func (h *Hosts) Lookup(name string) []string {
	if h == nil {
		return nil
	}
	return h.byName[normalize.Hostname(name)]
}

// Transfer asks each server, over TCP, for the whole zone of domain, and
// returns what the ones that agreed sent, one Data each, with the servers
// that did not and why.
func (p *Pool) Transfer(ctx context.Context, domain string, servers []string) (*Chain, []Failure) {
	out := &Chain{Host: domain}
	var fails []Failure
	for _, srv := range servers {
		d, err := p.transfer(ctx, domain, srv)
		if err != nil {
			fails = append(fails, Failure{srv, err})
			continue
		}
		out.Data = append(out.Data, d)
	}
	return out, fails
}

func (p *Pool) transfer(ctx context.Context, domain, server string) (*Data, error) {
	ctx, cancel := context.WithTimeout(ctx, 4*p.timeout)
	defer cancel()
	rrs, err := p.x.Transfer(ctx, domain, server)
	if err != nil {
		return nil, err
	}
	if len(rrs) == 0 {
		return nil, fmt.Errorf("%s sent no records", server)
	}
	d := &Data{Host: domain, rcodes: map[uint16]int{}, answered: true, Timestamp: time.Now(), Resolver: []string{server}}
	d.parse(rrs)
	d.dedupe()
	return d, nil
}

// ServerStatus is how one resolver answered a health check.
type ServerStatus struct {
	Server string
	Status string // the response code
	Took   time.Duration
	Err    error
}

// Check asks every resolver, one at a time and once, for the A record of
// name.
func (p *Pool) Check(ctx context.Context, name string) []ServerStatus {
	var out []ServerStatus
	for _, s := range p.servers {
		q := question(name, dns.TypeA)
		begin := time.Now()
		in, err := p.exchange(ctx, q, s)
		st := ServerStatus{Server: s, Took: time.Since(begin).Round(time.Millisecond), Err: err}
		if err == nil {
			st.Status = dns.RcodeToString[in.Rcode]
		}
		out = append(out, st)
	}
	return out
}
