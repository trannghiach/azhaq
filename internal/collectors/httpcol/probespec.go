package httpcol

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/trannghiach/azhaq/internal/fetch"
)

// Spec is what azhaq probe asks of azhaq-http beyond a run's own probe:
// httpx's flags. A collector without one answers as before.
type Spec struct {
	// Follow reports the final answer of a redirect chain (-fr): status,
	// content type, server and location are the last hop's.
	Follow       bool `json:"follow,omitempty"`
	MaxRedirects int  `json:"max_redirects,omitempty"` // -maxr
	// Bare are the names given without a scheme or a port: only those are
	// asked on the web ports. A name that only comes from a URL or a
	// host:port given is not (httpx asks what it is given, nothing more).
	Bare []string `json:"bare,omitempty"`
	// TargetRate paces the services asked (-rl, as httpx): the first
	// request to each waits its turn, the ones that follow it do not.
	TargetRate float64 `json:"target_rate,omitempty"`
	SameHost   bool    `json:"same_host,omitempty"` // -fhr
	// NoFallback asks for both schemes of an input with none (-nf) and
	// reports each that answers.
	NoFallback bool `json:"no_fallback,omitempty"`
	// Ports are the web ports tried on each name (-p), each with the scheme
	// it was given, or none for both.
	Ports []PortSpec `json:"ports,omitempty"`
	// Paths are asked of every target in place of its own path (-path).
	Paths []string `json:"paths,omitempty"`
	// Methods are sent to every target (-x); empty is GET. Body is the body
	// that goes with them (-body); Raw is a request file's request (-rr).
	Methods []string    `json:"methods,omitempty"`
	Body    string      `json:"body,omitempty"`
	Raw     *RawRequest `json:"raw,omitempty"`

	TLS      bool      `json:"tls,omitempty"`      // -tls-grab: certificate data
	JARM     bool      `json:"jarm,omitempty"`     // -jarm: ten handshakes a host
	Hashes   []string  `json:"hashes,omitempty"`   // -hash
	Preview  int       `json:"preview,omitempty"`  // -bp: characters of the body
	Extract  []Extract `json:"extract,omitempty"`  // -er and -ep
	HTTP2    bool      `json:"http2,omitempty"`    // -http2: one more request each
	Pipeline bool      `json:"pipeline,omitempty"` // -pipeline
	VHost    bool      `json:"vhost,omitempty"`    // -vhost
	NoDecode bool      `json:"no_decode,omitempty"`
	// Evidence keeps each answer for matchers and raw output.
	Evidence bool `json:"evidence,omitempty"`

	TLSProbe bool `json:"tls_probe,omitempty"` // -tls-probe: probe the names of the certificate
	CSPProbe bool `json:"csp_probe,omitempty"` // -csp-probe: probe the names of the CSP
	EFQDN    bool `json:"efqdn,omitempty"`     // -efqdn: names in the body and the CSP
	CPE      bool `json:"cpe,omitempty"`       // -cpe: products by title, body and favicon
	WP       bool `json:"wp,omitempty"`        // -wp: WordPress plugins and themes
	KB       bool `json:"kb,omitempty"`        // -kb: the kind of page
	// PerHost holds what a target line asked for beyond its host: a virtual
	// host to send as Host, an address to connect to (-vi, JSON target
	// lines), by the host of the URL asked.
	PerHost map[string]HostOpt `json:"per_host,omitempty"`
	// AllIPs sends the request to every address of a name (-pa).
	AllIPs bool `json:"all_ips,omitempty"`
	// Exclude is httpx's -e: "cdn" leaves out ports other than 80 and 443
	// of addresses of a CDN, "private-ips" the private and loopback ones;
	// ExcludePorts and ExcludeRe leave out ports and URLs.
	Exclude      []string `json:"exclude,omitempty"`
	ExcludePorts []int    `json:"exclude_ports,omitempty"`
	ExcludeNets  []string `json:"exclude_nets,omitempty"`
	ExcludeRe    []string `json:"exclude_re,omitempty"`

	Proxy       string `json:"proxy,omitempty"`           // -proxy
	RespectHSTS bool   `json:"respect_hsts,omitempty"`    // -rhsts
	AutoReferer bool   `json:"auto_referer,omitempty"`    // -auto-referer
	RandomAgent bool   `json:"random_agent,omitempty"`    // -random-agent
	ReadLimit   int    `json:"read_limit,omitempty"`      // -rstr
	MaxHostErrs int    `json:"max_host_errors,omitempty"` // -maxhr
	SNI         string `json:"sni,omitempty"`             // -sni
	Retries     int    `json:"retries,omitempty"`         // -retries
	TimeoutMS   int64  `json:"timeout_ms,omitempty"`      // -req-timeout
	MinTLS10    bool   `json:"min_tls10,omitempty"`       // httpx accepts TLS 1.0
	excludeRe   []*regexp.Regexp
	extract     []*regexp.Regexp
}

// Apply sets the request settings every fetch of the run reads, and
// compiles the patterns. It follows fetch.Reset.
func (s *Spec) Apply() error {
	fetch.NoFollow = !s.Follow
	if s.MaxRedirects > 0 {
		// As httpx counts: -maxr N stops at the Nth redirect, so N-1 are followed.
		fetch.MaxRedirects = s.MaxRedirects - 1
	}
	fetch.SameHostOnly = s.SameHost
	fetch.KeepRaw = true // the head is hashed, matched and tested for a websocket
	fetch.NoAccept = true
	fetch.NoReuse = true
	fetch.SNI = s.SNI
	fetch.RespectHSTS, fetch.AutoReferer, fetch.RandomAgent, fetch.ReadLimit = s.RespectHSTS, s.AutoReferer, s.RandomAgent, s.ReadLimit
	if s.MaxHostErrs != 0 {
		fetch.OriginTrips = max(s.MaxHostErrs, 0)
	}
	if s.Proxy != "" {
		u, err := url.Parse(s.Proxy)
		if err != nil || u.Host == "" || u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "socks5" {
			return fmt.Errorf("-proxy wants http://, https:// or socks5:// and a host, got %q", s.Proxy)
		}
		fetch.ProxyURL = u
	}
	fetch.Retries = s.Retries
	fetch.RequestTimeout = time.Duration(s.TimeoutMS) * time.Millisecond
	if s.MinTLS10 {
		fetch.TLSMin = tls.VersionTLS10
	}
	s.extract = s.extract[:0]
	for _, p := range s.Extract {
		re, err := regexp.Compile(p.Pattern)
		if err != nil {
			return fmt.Errorf("-er: %w", err)
		}
		s.extract = append(s.extract, re)
	}
	s.excludeRe = s.excludeRe[:0]
	for _, p := range s.ExcludeRe {
		re, err := regexp.Compile(p)
		if err != nil {
			return fmt.Errorf("-e: %w", err)
		}
		s.excludeRe = append(s.excludeRe, re)
	}
	return nil
}

// HostOpt is what a target line pins for one host.
type HostOpt struct {
	VHosts []string `json:"vhosts,omitempty"`
	IP     string   `json:"ip,omitempty"`
}

// Extract is a pattern of -er (named by itself) or -ep (named by the preset).
type Extract struct {
	Name    string `json:"name"`
	Pattern string `json:"pattern"`
}

// PortSpec is a web port of -p, with its scheme when one was given.
type PortSpec struct {
	Port   int    `json:"port"`
	Scheme string `json:"scheme,omitempty"` // "", "http" or "https"
}

// ParsePorts reads httpx's -p syntax: ports and ranges, comma-separated,
// each list or entry optionally led by http: or https: (http:80,https:443,
// 8000-8100).
func ParsePorts(raw string) ([]PortSpec, error) {
	var out []PortSpec
	seen := map[PortSpec]bool{}
	add := func(p PortSpec) {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		scheme := ""
		if s, rest, ok := strings.Cut(item, ":"); ok {
			switch strings.ToLower(s) {
			case "http", "https":
				scheme, item = strings.ToLower(s), rest
			default:
				return nil, fmt.Errorf("bad port %q: a scheme is http: or https:", item)
			}
		}
		lo, hi := item, item
		if a, b, ok := strings.Cut(item, "-"); ok {
			lo, hi = a, b
		}
		from, err1 := strconv.Atoi(strings.TrimSpace(lo))
		to, err2 := strconv.Atoi(strings.TrimSpace(hi))
		if err1 != nil || err2 != nil || from < 1 || to > 65535 || from > to {
			return nil, fmt.Errorf("bad port %q", item)
		}
		for p := from; p <= to; p++ {
			add(PortSpec{Port: p, Scheme: scheme})
		}
	}
	return out, nil
}

// RawRequest is a request read from a file (-rr).
type RawRequest struct {
	Method string      `json:"method"`
	Path   string      `json:"path"`
	Host   string      `json:"host,omitempty"`
	Header http.Header `json:"header,omitempty"`
	Body   []byte      `json:"body,omitempty"`
}

// ParseRawRequest reads one HTTP request in wire form: a request line,
// headers, a blank line and a body. The Host header names the target when
// no other does.
func ParseRawRequest(data []byte) (*RawRequest, error) {
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	head, body, _ := strings.Cut(text, "\n\n")
	r := bufio.NewReader(strings.NewReader(strings.ReplaceAll(head, "\n", "\r\n") + "\r\n\r\n"))
	tp := textproto.NewReader(r)
	line, err := tp.ReadLine()
	if err != nil {
		return nil, fmt.Errorf("no request line")
	}
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return nil, fmt.Errorf("bad request line %q", line)
	}
	hdr, err := tp.ReadMIMEHeader()
	if err != nil && len(hdr) == 0 {
		return nil, fmt.Errorf("bad headers: %w", err)
	}
	rr := &RawRequest{Method: strings.ToUpper(parts[0]), Path: parts[1], Header: http.Header(hdr), Body: []byte(strings.TrimRight(body, "\n"))}
	if len(body) > 0 && strings.HasSuffix(text, "\n") && !strings.HasSuffix(body, "\n\n") {
		rr.Body = []byte(strings.TrimSuffix(body, "\n"))
	}
	rr.Host = rr.Header.Get("Host")
	rr.Header.Del("Host")
	if _, _, err := net.SplitHostPort(rr.Host); err != nil && rr.Host != "" {
		rr.Host = strings.TrimSpace(rr.Host)
	}
	return rr, nil
}

// Evidence is one answer as it came, for what a row does not hold: the
// matchers and the raw output read it.
type Evidence struct {
	Method  string
	Request []byte // the request as sent
	Head    string // the response's status line and headers
	Body    []byte // the response's body, as sent
	Data    []byte // the body in UTF-8
	URL     string // the URL asked
	Final   string // where a followed redirect ended
	Hops    []fetch.Hop
	Chain   []fetch.RawHop
	Elapsed time.Duration
}

var names sync.Map // observation source → []string of names to probe next

// TakeNames is the names an answer led to (-tls-probe, -csp-probe), and
// forgets them.
func TakeNames(source string) []string {
	v, ok := names.LoadAndDelete(source)
	if !ok {
		return nil
	}
	return v.([]string)
}

// evidence is the answers kept for the observations not yet printed. Two
// inputs that reach one URL each keep it, so it is counted: the last of
// them to take it frees it.
var (
	evidenceMu sync.Mutex
	evidence   = map[string]*evidenceSlot{} // observation source → the answer
)

type evidenceSlot struct {
	ev   *Evidence
	left int
}

func keepEvidence(source string, ev *Evidence) {
	evidenceMu.Lock()
	defer evidenceMu.Unlock()
	if s := evidence[source]; s != nil {
		s.ev, s.left = ev, s.left+1
		return
	}
	evidence[source] = &evidenceSlot{ev: ev, left: 1}
}

// TakeEvidence is the answer kept for the observation with this source;
// it is forgotten when each who kept it has taken it.
func TakeEvidence(source string) (*Evidence, bool) {
	evidenceMu.Lock()
	defer evidenceMu.Unlock()
	s := evidence[source]
	if s == nil {
		return nil, false
	}
	if s.left--; s.left <= 0 {
		delete(evidence, source)
	}
	return s.ev, true
}
