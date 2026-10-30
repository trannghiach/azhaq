// Package portscan finds open TCP ports with full connects (no raw
// sockets, no root) at a set rate, reads what a service says first, and
// asks one that says nothing whether it speaks HTTP or TLS.
package portscan

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/trannghiach/azhaq/internal/ledger"
	"github.com/trannghiach/azhaq/internal/limit"
)

// Top lists are nmap's most frequent TCP ports, as naabu ships them (MIT).
const (
	top100  = "7,9,13,21-23,25-26,37,53,79-81,88,106,110-111,113,119,135,139,143-144,179,199,389,427,443-445,465,513-515,543-544,548,554,587,631,646,873,990,993,995,1025-1029,1110,1433,1720,1723,1755,1900,2000-2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000-6001,6646,7070,8000,8008-8009,8080-8081,8443,8888,9100,9999-10000,32768,49152-49157"
	top1000 = "1,3-4,6-7,9,13,17,19-26,30,32-33,37,42-43,49,53,70,79-85,88-90,99-100,106,109-111,113,119,125,135,139,143-144,146,161,163,179,199,211-212,222,254-256,259,264,280,301,306,311,340,366,389,406-407,416-417,425,427,443-445,458,464-465,481,497,500,512-515,524,541,543-545,548,554-555,563,587,593,616-617,625,631,636,646,648,666-668,683,687,691,700,705,711,714,720,722,726,749,765,777,783,787,800-801,808,843,873,880,888,898,900-903,911-912,981,987,990,992-993,995,999-1002,1007,1009-1011,1021-1100,1102,1104-1108,1110-1114,1117,1119,1121-1124,1126,1130-1132,1137-1138,1141,1145,1147-1149,1151-1152,1154,1163-1166,1169,1174-1175,1183,1185-1187,1192,1198-1199,1201,1213,1216-1218,1233-1234,1236,1244,1247-1248,1259,1271-1272,1277,1287,1296,1300-1301,1309-1311,1322,1328,1334,1352,1417,1433-1434,1443,1455,1461,1494,1500-1501,1503,1521,1524,1533,1556,1580,1583,1594,1600,1641,1658,1666,1687-1688,1700,1717-1721,1723,1755,1761,1782-1783,1801,1805,1812,1839-1840,1862-1864,1875,1900,1914,1935,1947,1971-1972,1974,1984,1998-2010,2013,2020-2022,2030,2033-2035,2038,2040-2043,2045-2049,2065,2068,2099-2100,2103,2105-2107,2111,2119,2121,2126,2135,2144,2160-2161,2170,2179,2190-2191,2196,2200,2222,2251,2260,2288,2301,2323,2366,2381-2383,2393-2394,2399,2401,2492,2500,2522,2525,2557,2601-2602,2604-2605,2607-2608,2638,2701-2702,2710,2717-2718,2725,2800,2809,2811,2869,2875,2909-2910,2920,2967-2968,2998,3000-3001,3003,3005-3007,3011,3013,3017,3030-3031,3052,3071,3077,3128,3168,3211,3221,3260-3261,3268-3269,3283,3300-3301,3306,3322-3325,3333,3351,3367,3369-3372,3389-3390,3404,3476,3493,3517,3527,3546,3551,3580,3659,3689-3690,3703,3737,3766,3784,3800-3801,3809,3814,3826-3828,3851,3869,3871,3878,3880,3889,3905,3914,3918,3920,3945,3971,3986,3995,3998,4000-4006,4045,4111,4125-4126,4129,4224,4242,4279,4321,4343,4443-4446,4449,4550,4567,4662,4848,4899-4900,4998,5000-5004,5009,5030,5033,5050-5051,5054,5060-5061,5080,5087,5100-5102,5120,5190,5200,5214,5221-5222,5225-5226,5269,5280,5298,5357,5405,5414,5431-5432,5440,5500,5510,5544,5550,5555,5560,5566,5631,5633,5666,5678-5679,5718,5730,5800-5802,5810-5811,5815,5822,5825,5850,5859,5862,5877,5900-5904,5906-5907,5910-5911,5915,5922,5925,5950,5952,5959-5963,5987-5989,5998-6007,6009,6025,6059,6100-6101,6106,6112,6123,6129,6156,6346,6389,6502,6510,6543,6547,6565-6567,6580,6646,6666-6669,6689,6692,6699,6779,6788-6789,6792,6839,6881,6901,6969,7000-7002,7004,7007,7019,7025,7070,7100,7103,7106,7200-7201,7402,7435,7443,7496,7512,7625,7627,7676,7741,7777-7778,7800,7911,7920-7921,7937-7938,7999-8002,8007-8011,8021-8022,8031,8042,8045,8080-8090,8093,8099-8100,8180-8181,8192-8194,8200,8222,8254,8290-8292,8300,8333,8383,8400,8402,8443,8500,8600,8649,8651-8652,8654,8701,8800,8873,8888,8899,8994,9000-9003,9009-9011,9040,9050,9071,9080-9081,9090-9091,9099-9103,9110-9111,9200,9207,9220,9290,9415,9418,9485,9500,9502-9503,9535,9575,9593-9595,9618,9666,9876-9878,9898,9900,9917,9929,9943-9944,9968,9998-10004,10009-10010,10012,10024-10025,10082,10180,10215,10243,10566,10616-10617,10621,10626,10628-10629,10778,11110-11111,11967,12000,12174,12265,12345,13456,13722,13782-13783,14000,14238,14441-14442,15000,15002-15004,15660,15742,16000-16001,16012,16016,16018,16080,16113,16992-16993,17877,17988,18040,18101,18988,19101,19283,19315,19350,19780,19801,19842,20000,20005,20031,20221-20222,20828,21571,22939,23502,24444,24800,25734-25735,26214,27000,27352-27353,27355-27356,27715,28201,30000,30718,30951,31038,31337,32768-32785,33354,33899,34571-34573,35500,38292,40193,40911,41511,42510,44176,44442-44443,44501,45100,48080,49152-49161,49163,49165,49167,49175-49176,49400,49999-50003,50006,50300,50389,50500,50636,50800,51103,51493,52673,52822,52848,52869,54045,54328,55055-55056,55555,55600,56737-56738,57294,57797,58080,60020,60443,61532,61900,62078,63331,64623,64680,65000,65129,65389"
)

// Ports parses a comma-separated list whose parts are each a name
// (top-100, top-1000, full), a port or a range: "top-100,8888-8890". "none"
// alone is no ports; an empty spec is top-100.
func Ports(spec string) ([]int, error) {
	return parseList(spec, top100, func(w string) (string, bool) {
		switch w {
		case "top-100", "top100":
			return top100, true
		case "top-1000", "top1000":
			return top1000, true
		case "full", "all":
			return "1-65535", true
		}
		return "", false
	}, "TCP takes top-100, top-1000 or full", map[string]string{"top": "the UDP list", "top-udp": "the UDP list"})
}

// parseList reads a port spec for Ports and UDPPorts: def stands for an
// empty spec, name expands a list name, and other names the lists of the
// other protocol, so a mistake between the two says what to use.
func parseList(spec, def string, name func(string) (string, bool), takes string, other map[string]string) ([]int, error) {
	spec = strings.ToLower(strings.TrimSpace(spec))
	switch spec {
	case "":
		spec = def
	case "none":
		return nil, nil
	}
	seen := map[int]bool{}
	var out []int
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if list, ok := name(part); ok {
			part = list
		} else if what, ok := other[part]; ok {
			return nil, fmt.Errorf("bad port %q: %s (%s is %s)", part, takes, part, what)
		}
		for _, r := range strings.Split(part, ",") {
			lo, hi, isRange := strings.Cut(r, "-")
			a, err := strconv.Atoi(lo)
			if err != nil {
				return nil, fmt.Errorf("bad port %q", r)
			}
			b := a
			if isRange {
				if b, err = strconv.Atoi(hi); err != nil {
					return nil, fmt.Errorf("bad port range %q", r)
				}
			}
			if a < 1 || b > 65535 || a > b {
				return nil, fmt.Errorf("bad port range %q", r)
			}
			for p := a; p <= b; p++ {
				if !seen[p] {
					seen[p] = true
					out = append(out, p)
				}
			}
		}
	}
	sort.Ints(out)
	return out, nil
}

// Open is one open port and what its service said, if anything. A
// service that speaks TLS gives the names of its certificate: the
// subject's common name and its alternative names, as httpx calls them.
type Open struct {
	Port      int      `json:"port"`
	Service   string   `json:"service,omitempty"`
	Banner    string   `json:"banner,omitempty"`
	Product   string   `json:"product,omitempty"`
	Title     string   `json:"title,omitempty"` // the HTML title of GET /, when the answer names no product
	Version   string   `json:"version,omitempty"`
	TLS       bool     `json:"tls,omitempty"`
	SubjectCN string   `json:"subject_cn,omitempty"`
	SubjectAN []string `json:"subject_an,omitempty"`

	again bool // a server-first port that said nothing: asked once more after the pass
}

// Scanner connects to ports at a set total rate.
type Scanner struct {
	Rate    float64       // connection attempts per second, all hosts together; 0 means 1000 (naabu's), loopback unpaced
	Workers int           // connects in flight; 0 means 100
	Timeout time.Duration // per connect; 0 means 1.5 s
	Banner  time.Duration // how long to wait for a service to speak (and, with Timeout, for the answer to a probe); 0 means 1.5 s; <0 skips both
	// Take, when set, is asked before each connect, the TLS probe's
	// included; an error stops the scan and is returned (the run's
	// request budget is spent).
	Take func() error
	// UserAgent goes on the HTTP probe: a CDN's bot manager may hold a
	// request without a browser's open.
	UserAgent string

	once      sync.Once
	limiter   *limit.Limiter
	loopPaced bool

	mu      sync.Mutex
	unnamed map[string]int // per address: open ports no probe could name
	skipped map[string]int // per address: ports not run down the ladder after that
	stop    error          // the budget error a probe of a service met
}

func (s *Scanner) init() {
	s.once.Do(func() {
		s.loopPaced = s.Rate > 0
		if s.Rate <= 0 {
			s.Rate = 1000
		}
		if s.Workers <= 0 {
			s.Workers = 100
		}
		if s.Timeout <= 0 {
			s.Timeout = 1500 * time.Millisecond
		}
		if s.Banner == 0 {
			s.Banner = 1500 * time.Millisecond
		}
		s.limiter = limit.New(s.Rate, max(1, int(s.Rate/10)))
	})
}

// Scan connects to each port of ip and returns the open ones.
func (s *Scanner) Scan(ctx context.Context, host, ip string, ports []int) ([]Open, error) {
	r, err := s.ScanEach(ctx, host, ip, ports)
	return r.Open, err
}

// Report is what one address's scan found.
type Report struct {
	Open []Open
	// Silent are the ports that neither accepted nor refused a connect
	// (a timeout, an ICMP unreachable): filtered, or dropped on the way.
	Silent []int
	// Unprobed counts the open ports whose protocol was not asked for
	// after several others on the address could not be named.
	Unprobed int
}

// ScanEach connects to each port of ip and says which are open and
// which never answered. host is the name the probes of silent ports ask
// for (the Host header, the TLS server name); empty, ip. A port that did
// not answer is asked once more after the others, when few did not: a
// loaded or lossy host drops a SYN now and then, while a firewall that
// drops nearly everything would only double the scan. A port whose
// service greets first and said nothing gets a second connection too.
func (s *Scanner) ScanEach(ctx context.Context, host, ip string, ports []int) (Report, error) {
	s.init()
	var r Report
	var err error
	r.Open, r.Silent, err = s.pass(ctx, host, ip, ports)
	if err == nil && len(r.Silent) > 0 && len(r.Silent) <= max(retryFloor, len(ports)/10) {
		var again []Open
		again, r.Silent, err = s.pass(ctx, host, ip, r.Silent)
		r.Open = append(r.Open, again...)
	}
	if err == nil {
		err = s.secondLook(ctx, host, ip, r.Open)
	}
	sort.Slice(r.Open, func(i, j int) bool { return r.Open[i].Port < r.Open[j].Port })
	sort.Ints(r.Silent)
	s.mu.Lock()
	r.Unprobed = s.skipped[ip]
	if err == nil {
		err = s.stop
	}
	s.mu.Unlock()
	return r, err
}

// wait paces a connect. This machine's loopback is not paced unless a rate
// was given: no network to spare (a full scan of 127.0.0.1 took 218 s at 300/s).
func (s *Scanner) wait(ctx context.Context, ip string) error {
	if a := net.ParseIP(ip); a != nil && a.IsLoopback() && !s.loopPaced {
		return ctx.Err()
	}
	return s.limiter.Wait(ctx, "")
}

// retryFloor: up to this many silent ports are asked again whatever
// share of the scan they are.
const retryFloor = 64

// pass connects once to each port, at the scanner's rate.
func (s *Scanner) pass(ctx context.Context, host, ip string, ports []int) (open []Open, silent []int, err error) {
	var mu sync.Mutex
	sem := make(chan struct{}, s.Workers)
	var wg sync.WaitGroup
	var stop error
	for _, p := range ports {
		if err := s.wait(ctx, ip); err != nil {
			break
		}
		if s.Take != nil {
			if stop = s.Take(); stop != nil {
				break
			}
		}
		select {
		case <-ctx.Done():
		case sem <- struct{}{}:
		}
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }()
			o, state := s.probe(ctx, host, ip, p)
			mu.Lock()
			switch state {
			case portOpen:
				open = append(open, o)
			case portSilent:
				silent = append(silent, p)
			}
			mu.Unlock()
		}(p)
	}
	wg.Wait()
	if stop != nil {
		return open, silent, stop
	}
	return open, silent, ctx.Err()
}

type portState int

const (
	portClosed portState = iota // refused: nothing listens
	portOpen
	portSilent // no answer either way
)

func (s *Scanner) probe(ctx context.Context, host, ip string, port int) (Open, portState) {
	d := net.Dialer{Timeout: s.Timeout}
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	ledger.TCP(ctx, host, addr)
	t0 := time.Now()
	conn, err := d.DialContext(ctx, "tcp", addr)
	rtt := time.Since(t0)
	if err != nil {
		if errors.Is(err, syscall.ECONNREFUSED) || ctx.Err() != nil {
			return Open{}, portClosed
		}
		return Open{}, portSilent
	}
	defer conn.Close()
	o := Open{Port: port}
	if s.Banner > 0 {
		_ = conn.SetReadDeadline(time.Now().Add(s.Banner))
		buf := make([]byte, 512)
		n, err := conn.Read(buf)
		var ne net.Error
		var silentGreeter bool
		if n == 0 && errors.As(err, &ne) && ne.Timeout() && speaksFirst(port) {
			// sshd, an FTP or mail server greets first, late when
			// loaded: wait for it rather than ask it HTTP.
			_ = conn.SetReadDeadline(time.Now().Add(s.Timeout + s.Banner))
			n, err = conn.Read(buf)
			silentGreeter = n == 0 && errors.As(err, &ne) && ne.Timeout()
		}
		o.Banner = printable(buf[:n])
		s.greeted(&o, buf[:n])
		if n > 0 && o.Product == "" && bannerService(o.Banner) == "ftp-or-smtp" {
			s.settle220(conn, &o)
		}
		// Still open after the wait, the service waits to be asked. One
		// that closed the connection says nothing to anyone (tcpwrapped).
		if n == 0 && errors.As(err, &ne) && ne.Timeout() && !rawData(port) {
			s.identify(ctx, &o, conn, host, ip, rtt)
		} else if n == 0 && err != nil && !errors.As(err, &ne) && !speaksFirst(port) {
			// Accepted and closed with nothing said: a TCP wrapper or an
			// access list answers so, to anyone it does not know.
			o.Service = "tcpwrapped"
		}
		// Nothing, not even an answer to the HEAD: sshd drops or delays
		// its greeting when many connects arrive at once.
		o.again = silentGreeter && o.Banner == "" && o.Service == ""
	}
	if o.Service == "" {
		o.Service = guess(port, o.Banner)
	}
	return o, portOpen
}

// secondLook connects once more to each server-first port that said
// nothing, and waits longer for its greeting. Each connect is paced,
// counted and recorded like any other; what the first one found stands
// when this one hears nothing either.
func (s *Scanner) secondLook(ctx context.Context, host, ip string, open []Open) error {
	sem := make(chan struct{}, s.Workers)
	var wg sync.WaitGroup
	var stop error
	for i := range open {
		if !open[i].again {
			continue
		}
		open[i].again = false
		if stop != nil || ctx.Err() != nil {
			continue // the flag is still cleared for the rest
		}
		if s.wait(ctx, ip) != nil {
			continue
		}
		if s.Take != nil {
			if stop = s.Take(); stop != nil {
				continue
			}
		}
		select {
		case <-ctx.Done():
		case sem <- struct{}{}:
		}
		if ctx.Err() != nil {
			continue
		}
		wg.Add(1)
		go func(o *Open) {
			defer wg.Done()
			defer func() { <-sem }()
			s.greetAgain(ctx, host, ip, o)
		}(&open[i])
	}
	wg.Wait()
	if stop != nil {
		return stop
	}
	return ctx.Err()
}

func (s *Scanner) greetAgain(ctx context.Context, host, ip string, o *Open) {
	addr := net.JoinHostPort(ip, strconv.Itoa(o.Port))
	ledger.TCP(ctx, host, addr)
	conn, err := (&net.Dialer{Timeout: s.Timeout}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(s.Timeout + 2*s.Banner))
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	if n == 0 {
		return
	}
	o.Banner = printable(buf[:n])
	s.greeted(o, buf[:n])
	if g := guess(o.Port, o.Banner); g != "" && (o.Service == "" || strings.HasSuffix(o.Service, "?")) {
		o.Service = g
	}
}

// speaksFirst: ports whose usual service greets before it is asked.
var speaksFirst = func(port int) bool {
	switch port {
	case 21, 22, 23, 25, 110, 143, 587, 2222, 3306, 5900:
		return true
	}
	return false
}

// rawData: ports that take whatever they are sent as a job (JetDirect
// printing on 9100–9107, as nmap leaves them out of its probes): asking
// them anything would print it.
func rawData(port int) bool { return port >= 9100 && port <= 9107 }

// ask sends HEAD / and returns the head of the answer, if any.
func (s *Scanner) ask(conn net.Conn, host string, port, defaultPort int) []byte {
	switch {
	case port != defaultPort:
		host = net.JoinHostPort(host, strconv.Itoa(port))
	case strings.Contains(host, ":"):
		host = "[" + host + "]"
	}
	req := "HEAD / HTTP/1.0\r\nHost: " + host + "\r\n"
	if s.UserAgent != "" {
		req += "User-Agent: " + s.UserAgent + "\r\n"
	}
	// The time of a connect and of a banner: a remote server's answer
	// takes a round trip more than its silence.
	return s.talk(conn, []byte(req+"Accept: */*\r\n\r\n"), headFrame, s.Timeout+s.Banner)
}

// headFrame ends the read of an HTTP head at its blank line, and lets any
// other answer stop at a pause.
func headFrame(b []byte) int {
	if !bytes.HasPrefix(b, []byte("HTTP/")) && !bytes.HasPrefix(b, []byte("ICY ")) {
		return 0
	}
	if i := bytes.Index(b, []byte("\r\n\r\n")); i >= 0 {
		return i + 4
	}
	if len(b) >= 4096 {
		return len(b)
	}
	return len(b) + 1 // more is coming
}

// httpAnswer reads the head of an HTTP answer: its status, and what to
// show of it, the Server header or else the status line.
func httpAnswer(head []byte) (status int, banner string, ok bool) {
	if !bytes.HasPrefix(head, []byte("HTTP/")) {
		return 0, "", false
	}
	lines := strings.Split(string(head), "\n")
	first := strings.TrimSpace(lines[0])
	if f := strings.Fields(first); len(f) > 1 {
		status, _ = strconv.Atoi(f[1])
	}
	for _, l := range lines[1:] {
		k, v, found := strings.Cut(strings.TrimSpace(l), ":")
		if !found {
			break // the end of the head
		}
		if strings.EqualFold(k, "server") {
			banner = printable([]byte(strings.TrimSpace(v)))
		}
	}
	if banner == "" {
		banner = printable([]byte(first))
	}
	return status, banner, true
}

// printable keeps the first line of a text banner; a service that speaks
// binary is marked as such.
func printable(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	text := 0
	for _, c := range b {
		if c >= 0x20 && c < 0x7f || c == '\r' || c == '\n' || c == '\t' {
			text++
		}
	}
	if text*10 < len(b)*8 {
		return "(binary)"
	}
	line := strings.SplitN(string(b), "\n", 2)[0]
	var out strings.Builder
	for i := 0; i < len(line); i++ {
		if c := line[i]; c >= 0x20 && c < 0x7f {
			out.WriteByte(c)
		}
	}
	return strings.TrimSpace(out.String())
}

// Web is true for an open port worth an HTTP probe: one that said nothing
// or answered like HTTP, and is not a known non-web service.
func (o Open) Web() bool {
	switch strings.TrimSuffix(o.Service, "?") {
	case "", "http", "https", "tls", "elasticsearch", "docker", "kubernetes", "http-proxy":
		return true // tls: a handshake answered, HTTP inside it may be slow
	}
	return false
}
