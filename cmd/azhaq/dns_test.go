package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/trannghiach/azhaq/internal/dnsr"
)

// dnsLab is a zone with every record type, a reverse zone and a zone
// transfer, on loopback (UDP and TCP). asked counts the questions.
type dnsLab struct {
	addr  string
	asked atomic.Int64
}

func nowMs() int64 { return time.Now().UnixMilli() }

func startLab(t *testing.T) *dnsLab {
	t.Helper()
	lab := &dnsLab{}
	var pc net.PacketConn
	var ln net.Listener
	for i := 0; ; i++ {
		var err error
		if pc, err = net.ListenPacket("udp", "127.0.0.1:0"); err != nil {
			t.Skipf("no UDP: %v", err)
		}
		if ln, err = net.Listen("tcp", pc.LocalAddr().String()); err == nil {
			break
		}
		pc.Close() // the TCP port of this UDP port is taken: try another
		if i == 20 {
			t.Skipf("no TCP: %v", err)
		}
	}
	h := dns.HandlerFunc(lab.handle)
	us, ts := &dns.Server{PacketConn: pc, Handler: h}, &dns.Server{Listener: ln, Handler: h}
	go func() { _ = us.ActivateAndServe() }()
	go func() { _ = ts.ActivateAndServe() }()
	t.Cleanup(func() { _ = us.Shutdown(); _ = ts.Shutdown() })
	lab.addr = pc.LocalAddr().String()
	return lab
}

// labZoneMu guards labZone: a test adds names while earlier labs' servers
// may still answer.
var labZoneMu sync.RWMutex

var labZone = map[string][]string{
	"lab.zz.":           {"A 192.0.2.1", "NS ns.lab.zz.", "MX 10 mail.lab.zz.", `TXT "v=spf1 -all"`, "SOA ns.lab.zz. h.lab.zz. 5 1 2 3 4", `CAA 0 issue "ca.test"`},
	"ns.lab.zz.":        {"A 127.0.0.1"},
	"www.lab.zz.":       {"A 192.0.2.1"},
	"api.lab.zz.":       {"CNAME www.lab.zz."},
	"v6.lab.zz.":        {"AAAA 2001:db8::1"},
	"dual.lab.zz.":      {"A 192.0.2.5", "AAAA 2001:db8::5"},
	"_dmarc.lab.zz.":    {`TXT "v=DMARC1; p=none"`},
	"_sip._tcp.lab.zz.": {"SRV 1 2 5060 www.lab.zz."},
	"real.wild.lab.zz.": {"A 192.0.2.50"},
}

func (lab *dnsLab) handle(w dns.ResponseWriter, r *dns.Msg) {
	lab.asked.Add(1)
	q := r.Question[0]
	name := strings.ToLower(q.Name)
	m := new(dns.Msg)
	m.SetReply(r)
	if q.Qtype == dns.TypeAXFR {
		if w.RemoteAddr().Network() != "tcp" || name != "lab.zz." {
			m.Rcode = dns.RcodeRefused
			_ = w.WriteMsg(m)
			return
		}
		var all []dns.RR
		for n, recs := range labZone {
			for _, rec := range recs {
				if rr, err := dns.NewRR(n + " 60 IN " + rec); err == nil {
					all = append(all, rr)
				}
			}
		}
		soa, _ := dns.NewRR("lab.zz. 60 IN SOA ns.lab.zz. h.lab.zz. 5 1 2 3 4")
		ch := make(chan *dns.Envelope, 1)
		ch <- &dns.Envelope{RR: append(append([]dns.RR{soa}, all...), soa)}
		close(ch)
		_ = new(dns.Transfer).Out(w, r, ch)
		return
	}
	if strings.HasSuffix(name, ".in-addr.arpa.") {
		if name == "7.2.0.192.in-addr.arpa." {
			rr, _ := dns.NewRR(name + " 60 IN PTR www.lab.zz.")
			m.Answer = append(m.Answer, rr)
		} else {
			m.Rcode = dns.RcodeNameError
		}
		_ = w.WriteMsg(m)
		return
	}
	switch name {
	case "servfail.lab.zz.":
		m.Rcode = dns.RcodeServerFailure
	case "refused.lab.zz.":
		m.Rcode = dns.RcodeRefused
	default:
		labZoneMu.RLock()
		recs, ok := labZone[name]
		labZoneMu.RUnlock()
		if !ok && strings.HasSuffix(name, ".wild.lab.zz.") {
			recs, ok = []string{"A 192.0.2.99"}, true
		}
		if !ok {
			m.Rcode = dns.RcodeNameError
			break
		}
		for _, rec := range recs {
			rr, err := dns.NewRR(name + " 60 IN " + rec)
			if err != nil {
				continue
			}
			if rr.Header().Rrtype == q.Qtype || rr.Header().Rrtype == dns.TypeCNAME {
				m.Answer = append(m.Answer, rr)
			}
			if c, ok := rr.(*dns.CNAME); ok && q.Qtype == dns.TypeA {
				labZoneMu.RLock()
				target := labZone[c.Target]
				labZoneMu.RUnlock()
				for _, t := range target {
					if rr, err := dns.NewRR(c.Target + " 60 IN " + t); err == nil && rr.Header().Rrtype == dns.TypeA {
						m.Answer = append(m.Answer, rr)
					}
				}
			}
		}
	}
	_ = w.WriteMsg(m)
}

// dnsOut runs azhaq dns and returns stdout lines, the summary and the exit code.
func dnsOut(t *testing.T, args ...string) ([]string, report, int) {
	t.Helper()
	out, errOut, err := captureBoth(t, func() error {
		e := run(append([]string{"dns"}, args...))
		reportError(args, e)
		return e
	})
	var rep report
	if strings.Contains(errOut, `{"type":"summary"`) {
		rep = lastReport(t, errOut)
	}
	return lines(out), rep, exitCode(err)
}

func dnsRows(t *testing.T, ls []string) map[string]map[string]any {
	t.Helper()
	out := map[string]map[string]any{}
	for _, l := range ls {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("not a row: %q", l)
		}
		out[m["host"].(string)] = m
	}
	return out
}

func writeList(t *testing.T, lines ...string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "list.txt")
	if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDNSRecordTypesAndFields(t *testing.T) {
	t.Chdir(t.TempDir())
	lab := startLab(t)
	l := writeList(t, "lab.zz", "www.lab.zz", "api.lab.zz", "v6.lab.zz", "nope.lab.zz", "_sip._tcp.lab.zz", "dual.lab.zz")
	// default: A only; a name without an A is not printed; AAAA-only v6 is not
	ls, rep, code := dnsOut(t, "-l", l, "-r", lab.addr, "-silent")
	sort.Strings(ls)
	if !reflect.DeepEqual(ls, []string{"api.lab.zz", "dual.lab.zz", "lab.zz", "www.lab.zz"}) || code != exitOK {
		t.Errorf("default: %v exit %d %+v", ls, code, rep)
	}
	// -json: a row for each name with an A (the default type), empty fields left out
	ls, _, _ = dnsOut(t, "-l", l, "-r", lab.addr, "-j")
	r := dnsRows(t, ls)
	if len(r) != 4 || r["nope.lab.zz"] != nil || r["v6.lab.zz"] != nil {
		t.Errorf("rows %d: %v", len(r), r)
	}
	// -rcode asks for the others, with their status
	ls, _, _ = dnsOut(t, "-l", l, "-r", lab.addr, "-j", "-rcode", "nxdomain")
	if nx := dnsRows(t, ls)["nope.lab.zz"]; nx["status_code"] != "NXDOMAIN" || nx["status_code_raw"] != float64(3) {
		t.Errorf("-rcode row: %v", ls)
	}
	if _, ok := r["www.lab.zz"]["aaaa"]; ok {
		t.Error("an empty aaaa is in the row")
	}
	if _, ok := r["api.lab.zz"]["cdn_name"]; ok {
		t.Error("cdn_name is in a row")
	}
	// types
	for flag, want := range map[string]string{"-mx": "mail.lab.zz", "-ns": "ns.lab.zz", "-txt": "v=spf1 -all", "-caa": "ca.test"} {
		ls, _, _ := dnsOut(t, "-d", "lab.zz", "-r", lab.addr, flag, "-j")
		r := dnsRows(t, ls)["lab.zz"]
		key := strings.TrimPrefix(flag, "-")
		if got, _ := r[key].([]any); len(got) != 1 || got[0] != want {
			t.Errorf("%s: %v", flag, r)
		}
		if _, ok := r["a"]; ok {
			t.Errorf("%s asked A too", flag)
		}
	}
	ls, _, _ = dnsOut(t, "-d", "lab.zz", "-r", lab.addr, "-soa", "-j")
	if s, _ := dnsRows(t, ls)["lab.zz"]["soa"].([]any); len(s) != 1 || s[0].(map[string]any)["serial"] != float64(5) {
		t.Errorf("soa %v", ls)
	}
	ls, _, _ = dnsOut(t, "-d", "_sip._tcp.lab.zz", "-r", lab.addr, "-srv", "-resp")
	if !reflect.DeepEqual(ls, []string{"_sip._tcp.lab.zz [SRV] [www.lab.zz]"}) {
		t.Errorf("srv: %v", ls)
	}
	// both families: dual.lab.zz has an AAAA beside its A
	ls, _, _ = dnsOut(t, "-d", "dual.lab.zz", "-r", lab.addr, "-a", "-aaaa", "-j")
	if r := dnsRows(t, ls)["dual.lab.zz"]; r["a"] == nil || r["aaaa"] == nil {
		t.Errorf("dual: %v", r)
	}
	// text forms
	ls, _, _ = dnsOut(t, "-d", "api.lab.zz", "-r", lab.addr, "-resp", "-a", "-cname")
	if !reflect.DeepEqual(ls, []string{"api.lab.zz [A] [192.0.2.1]", "api.lab.zz [CNAME] [www.lab.zz]"}) {
		t.Errorf("-resp: %v", ls)
	}
	ls, _, _ = dnsOut(t, "-d", "api.lab.zz", "-r", lab.addr, "-ro", "-cname")
	if !reflect.DeepEqual(ls, []string{"www.lab.zz"}) {
		t.Errorf("-ro: %v", ls)
	}
	ls, _, _ = dnsOut(t, "-d", "api.lab.zz", "-r", lab.addr, "-ot", "{{host}} {{a}} {{cname}} {{ip}}!")
	if !reflect.DeepEqual(ls, []string{"api.lab.zz 192.0.2.1 www.lab.zz 192.0.2.1!"}) {
		t.Errorf("-ot: %v", ls)
	}
	// -rcode
	ls, _, _ = dnsOut(t, "-l", l, "-r", lab.addr, "-rcode", "nxdomain")
	if !reflect.DeepEqual(ls, []string{"nope.lab.zz [NXDOMAIN]"}) {
		t.Errorf("-rcode: %v", ls)
	}
	// -rtf: names without an A
	ls, _, _ = dnsOut(t, "-l", writeList(t, "lab.zz", "_dmarc.lab.zz"), "-r", lab.addr, "-rtf", "a", "-a", "-txt")
	if !reflect.DeepEqual(ls, []string{"_dmarc.lab.zz"}) {
		t.Errorf("-rtf: %v", ls)
	}
	// -all asks every type but PTR for names
	ls, _, _ = dnsOut(t, "-d", "lab.zz", "-r", lab.addr, "-all", "-e", "txt,soa")
	for _, l := range ls {
		if strings.Contains(l, "[TXT]") || strings.Contains(l, "[SOA]") {
			t.Errorf("-e kept %s", l)
		}
	}
	if !strings.Contains(strings.Join(ls, "\n"), "lab.zz [MX] [mail.lab.zz]") {
		t.Errorf("-all: %v", ls)
	}
}

// A record's value is printed as the resolver sent it, in -resp, -resp-only
// and -output-template alike: a DMARC TXT keeps its DMARC1, a CAA its value's
// case, an SOA its mailbox's, a target name its capitals.
func TestDNSTextFormsKeepTheCaseOfValues(t *testing.T) {
	t.Chdir(t.TempDir())
	lab := startLab(t)
	added := map[string][]string{
		"case.lab.zz.": {`TXT "v=DMARC1; p=none; rua=mailto:DMARC@Lab.zz"`, `CAA 0 issue "CA.Test; accounturi=https://Acme.test/Acct/7"`,
			"SOA NS.Lab.ZZ. Host.Master.lab.zz. 5 1 2 3 4", "SRV 1 2 5060 Sip.Lab.ZZ.", "MX 10 Mail.Lab.ZZ.", "NS NS2.Lab.ZZ."},
		"alias.lab.zz.": {"CNAME Target.Lab.ZZ."},
	}
	for k, v := range added {
		labZoneMu.Lock()
		labZone[k] = v
		labZoneMu.Unlock()
		t.Cleanup(func() { labZoneMu.Lock(); delete(labZone, k); labZoneMu.Unlock() })
	}
	for _, tt := range []struct {
		host, flag string
		want       []string
	}{
		{"case.lab.zz", "-txt", []string{"case.lab.zz [TXT] [v=DMARC1; p=none; rua=mailto:DMARC@Lab.zz]"}},
		{"case.lab.zz", "-caa", []string{"case.lab.zz [CAA] [CA.Test; accounturi=https://Acme.test/Acct/7]"}},
		{"case.lab.zz", "-soa", []string{"case.lab.zz [SOA] [NS.Lab.ZZ]", "case.lab.zz [SOA] [Host.Master.lab.zz]"}},
		{"case.lab.zz", "-srv", []string{"case.lab.zz [SRV] [Sip.Lab.ZZ]"}},
		{"case.lab.zz", "-mx", []string{"case.lab.zz [MX] [Mail.Lab.ZZ]"}},
		{"case.lab.zz", "-ns", []string{"case.lab.zz [NS] [NS2.Lab.ZZ]"}},
		{"alias.lab.zz", "-cname", []string{"alias.lab.zz [CNAME] [Target.Lab.ZZ]"}},
	} {
		ls, _, _ := dnsOut(t, "-d", tt.host, "-r", lab.addr, tt.flag, "-resp")
		if !reflect.DeepEqual(ls, tt.want) {
			t.Errorf("%s -resp: %q, want %q", tt.flag, ls, tt.want)
		}
		var only []string
		for _, l := range tt.want {
			only = append(only, strings.TrimSuffix(l[strings.Index(l, "] [")+3:], "]"))
		}
		if ls, _, _ := dnsOut(t, "-d", tt.host, "-r", lab.addr, tt.flag, "-resp-only"); !reflect.DeepEqual(ls, only) {
			t.Errorf("%s -resp-only: %q, want %q", tt.flag, ls, only)
		}
	}
	ls, _, _ := dnsOut(t, "-d", "case.lab.zz", "-r", lab.addr, "-txt", "-ot", "{{txt}}")
	if !reflect.DeepEqual(ls, []string{"v=DMARC1; p=none; rua=mailto:DMARC@Lab.zz"}) {
		t.Errorf("-ot: %q", ls)
	}
	ls, _, _ = dnsOut(t, "-d", "case.lab.zz", "-r", lab.addr, "-txt", "-j")
	if r := dnsRows(t, ls)["case.lab.zz"]; r["txt"].([]any)[0] != "v=DMARC1; p=none; rua=mailto:DMARC@Lab.zz" {
		t.Errorf("-j: %v", r)
	}
}

func TestDNSFailuresAreSaid(t *testing.T) {
	t.Chdir(t.TempDir())
	lab := startLab(t)
	l := writeList(t, "www.lab.zz", "servfail.lab.zz", "refused.lab.zz")
	ls, _, code := dnsOut(t, "-l", l, "-r", lab.addr, "-silent", "-a")
	if !reflect.DeepEqual(ls, []string{"www.lab.zz"}) || code != exitPartial {
		t.Errorf("%v exit %d", ls, code)
	}
	_, rep, _ := dnsOut(t, "-l", l, "-r", lab.addr, "-j", "-a")
	if len(rep.Failed) != 2 || rep.Failed[0].Count != 1 || rep.Failed[1].Count != 1 {
		t.Errorf("a failure of each kind: %+v", rep.Failed)
	}
	// asked for with -rcode, they are results, not failures
	ls, _, code = dnsOut(t, "-l", l, "-r", lab.addr, "-rcode", "servfail,refused")
	sort.Strings(ls)
	if !reflect.DeepEqual(ls, []string{"refused.lab.zz [REFUSED]", "servfail.lab.zz [SERVFAIL]"}) || code != exitOK {
		t.Errorf("%v exit %d", ls, code)
	}
}

func TestDNSPTRAndCIDR(t *testing.T) {
	t.Chdir(t.TempDir())
	lab := startLab(t)
	ls, rep, _ := dnsOut(t, "-l", "192.0.2.4/30", "-ptr", "-r", lab.addr, "-j")
	if len(ls) != 1 || rep.Counts["asked"] != 4 || rep.Counts["did not resolve"] != 3 {
		t.Errorf("a /30 asks 4 addresses, one has a name: %d rows %v", len(ls), rep.Counts)
	}
	ls, _, _ = dnsOut(t, "-l", "192.0.2.6/31", "-ptr", "-r", lab.addr, "-silent")
	if !reflect.DeepEqual(ls, []string{"192.0.2.7"}) {
		t.Errorf("ptr: %v", ls)
	}
	ls, _, _ = dnsOut(t, "-d", "192.0.2.7", "-ptr", "-r", lab.addr, "-j")
	if p, _ := dnsRows(t, ls)["192.0.2.7"]["ptr"].([]any); len(p) != 1 || p[0] != "www.lab.zz" {
		t.Errorf("ptr row: %v", ls)
	}
	// without -ptr the addresses are left out, and the summary says so
	_, rep, _ = dnsOut(t, "-l", "192.0.2.0/30", "-r", lab.addr, "-silent", "-json")
	if rep.Results != 0 || len(rep.Notes) == 0 || rep.Counts["left out"] != 1 {
		t.Errorf("%+v", rep)
	}
}

func TestDNSInputForms(t *testing.T) {
	t.Chdir(t.TempDir())
	lab := startLab(t)
	ls, _, _ := dnsOut(t, "-l", "www.lab.zz,api.lab.zz", "-r", lab.addr, "-silent")
	sort.Strings(ls)
	if !reflect.DeepEqual(ls, []string{"api.lab.zz", "www.lab.zz"}) {
		t.Errorf("comma list: %v", ls)
	}
	ls, _, _ = dnsOut(t, "-l", writeList(t, "http://www.lab.zz/x", "WWW.lab.zz", "www.lab.zz:8080"), "-r", lab.addr, "-silent")
	if !reflect.DeepEqual(ls, []string{"www.lab.zz"}) {
		t.Errorf("urls: %v", ls)
	}
	// -w: a file, a comma list; labels with an underscore are asked
	w := writeList(t, "www", "_dmarc", "zzz")
	ls, rep, _ := dnsOut(t, "-d", "lab.zz", "-w", w, "-r", lab.addr, "-txt", "-j")
	if r := dnsRows(t, ls); len(r) != 1 || r["_dmarc.lab.zz"] == nil || rep.Counts["asked"] != 3 {
		t.Errorf("-w: %v %v", ls, rep.Counts)
	}
	ls, _, _ = dnsOut(t, "-d", "FUZZ.lab.zz", "-w", "www,zzz", "-r", lab.addr, "-silent")
	if !reflect.DeepEqual(ls, []string{"www.lab.zz"}) {
		t.Errorf("FUZZ: %v", ls)
	}
	ls, _, _ = dnsOut(t, "-d", "lab.zz,wild.lab.zz", "-w", "www,real", "-r", lab.addr, "-silent")
	sort.Strings(ls)
	if !reflect.DeepEqual(ls, []string{"real.wild.lab.zz", "www.lab.zz"}) {
		t.Errorf("-d list: %v", ls)
	}
	// a word that makes no name is counted, not dropped
	_, rep, _ = dnsOut(t, "-d", "lab.zz", "-w", "www,bad word", "-r", lab.addr, "-silent", "-json")
	if rep.Counts["left out"] != 1 || len(rep.Notes) == 0 {
		t.Errorf("%+v", rep)
	}
}

func TestDNSWildcards(t *testing.T) {
	t.Chdir(t.TempDir())
	lab := startLab(t)
	l := writeList(t, "x.wild.lab.zz", "real.wild.lab.zz", "www.lab.zz")
	ls, rep, _ := dnsOut(t, "-l", l, "-r", lab.addr, "-a", "-json")
	if r := dnsRows(t, ls); len(r) != 2 || r["real.wild.lab.zz"] == nil || r["www.lab.zz"] == nil || rep.Counts["wildcard answers left out"] != 1 {
		t.Errorf("%v %v", ls, rep.Counts)
	}
	ls, _, _ = dnsOut(t, "-l", l, "-r", lab.addr, "-silent", "-no-wildcard")
	if len(ls) != 3 {
		t.Errorf("-no-wildcard: %v", ls)
	}
}

// an apex name costs one question, not four.
func TestDNSAsksOnlyWhatWasAsked(t *testing.T) {
	t.Chdir(t.TempDir())
	lab := startLab(t)
	dnsOut(t, "-d", "lab.zz", "-r", lab.addr, "-silent", "-no-wildcard")
	if n := lab.asked.Load(); n != 1 {
		t.Errorf("%d questions for one apex name", n)
	}
	lab.asked.Store(0)
	dnsOut(t, "-d", "lab.zz", "-r", lab.addr, "-silent", "-mx", "-txt", "-ns")
	if n := lab.asked.Load(); n != 3 {
		t.Errorf("%d questions for three types", n)
	}
}

func TestDNSRetryAndTimeoutAreWhatDnsxMeans(t *testing.T) {
	t.Chdir(t.TempDir())
	lab := startLab(t)
	for retry, want := range map[string]int64{"1": 1, "2": 2, "4": 4} {
		lab.asked.Store(0)
		dnsOut(t, "-d", "refused.lab.zz", "-r", lab.addr, "-silent", "-retry", retry)
		if lab.asked.Load() != want {
			t.Errorf("-retry %s: %d questions", retry, lab.asked.Load())
		}
	}
	// -timeout is the wait for one answer: the run is not cut short
	l := writeList(t, "www.lab.zz", "api.lab.zz")
	_, rep, code := dnsOut(t, "-l", l, "-r", lab.addr, "-j", "-a", "-timeout", "1s")
	if code != exitOK || rep.Stopped != "" || rep.Results != 2 {
		t.Errorf("exit %d %+v", code, rep)
	}
	_, _, code = dnsOut(t, "-d", "x.test", "-retry", "-1")
	if code != exitUsage {
		t.Errorf("-retry -1: exit %d", code)
	}
}

func TestDNSResolverSpecs(t *testing.T) {
	t.Chdir(t.TempDir())
	lab := startLab(t)
	f := writeList(t, "# lab", "tcp:"+lab.addr)
	for _, spec := range []string{lab.addr, "udp:" + lab.addr, "tcp:" + lab.addr, lab.addr + "," + "tcp:" + lab.addr, f} {
		ls, _, code := dnsOut(t, "-d", "www.lab.zz", "-r", spec, "-silent")
		if !reflect.DeepEqual(ls, []string{"www.lab.zz"}) || code != exitOK {
			t.Errorf("-r %s: %v exit %d", spec, ls, code)
		}
	}
	ls, _, code := dnsOut(t, "-d", "www.lab.zz", "-resolvers", f, "-silent")
	if len(ls) != 1 || code != exitOK {
		t.Errorf("-resolvers: %v %d", ls, code)
	}
	if _, _, code := dnsOut(t, "-d", "www.lab.zz", "-r", "nofile.txt", "-silent"); code != exitUsage {
		t.Errorf("a missing file: exit %d", code)
	}
	if _, _, code := dnsOut(t, "-d", "www.lab.zz", "-r", "doh:nowhere", "-silent"); code != exitUsage {
		t.Errorf("a bad doh: exit %d", code)
	}
}

func TestDNSRateIsPerNameAcrossResolvers(t *testing.T) {
	t.Chdir(t.TempDir())
	lab := startLab(t)
	l := writeList(t, "a.lab.zz", "b.lab.zz", "c.lab.zz", "d.lab.zz", "e.lab.zz", "f.lab.zz")
	start := nowMs()
	// 3 names a second: 6 names need at least a second beyond the first burst
	dnsOut(t, "-l", l, "-r", lab.addr+",tcp:"+lab.addr, "-silent", "-rl", "3", "-t", "2")
	if d := nowMs() - start; d < 900 {
		t.Errorf("6 names at -rl 3 took %d ms", d)
	}
}

func TestDNSAppendsToO(t *testing.T) {
	t.Chdir(t.TempDir())
	lab := startLab(t)
	for i := 0; i < 2; i++ {
		dnsOut(t, "-d", "www.lab.zz", "-r", lab.addr, "-silent", "-o", "out.txt")
	}
	raw, _ := os.ReadFile("out.txt")
	if got := strings.Count(string(raw), "www.lab.zz"); got != 2 {
		t.Errorf("-o holds %d lines after two runs", got)
	}
}

func TestDNSMoreThan20000Names(t *testing.T) {
	t.Chdir(t.TempDir())
	lab := startLab(t)
	var b strings.Builder
	for i := 0; i < 21001; i++ {
		fmt.Fprintf(&b, "n%d.lab.zz\n", i)
	}
	b.WriteString("www.lab.zz\n")
	p := filepath.Join(t.TempDir(), "big.txt")
	_ = os.WriteFile(p, []byte(b.String()), 0o644)
	ls, rep, code := dnsOut(t, "-l", p, "-r", lab.addr, "-j", "-a", "-t", "200")
	if r := dnsRows(t, ls); len(r) != 1 || r["www.lab.zz"] == nil || code != exitOK || rep.Counts["asked"] != 21002 {
		t.Errorf("%v exit %d %v", ls, code, rep.Counts)
	}
	if lab.asked.Load() < 21002 {
		t.Errorf("the lab was asked %d times", lab.asked.Load())
	}
}

func TestDNSTransferIsHeldToTheScope(t *testing.T) {
	t.Chdir(t.TempDir())
	lab := startLab(t)
	// the lab is the resolver the user named: it is asked. The zone's name
	// server, ns.lab.zz at 127.0.0.1, is in the scope by name, and nothing
	// listens on its port 53.
	ls, rep, _ := dnsOut(t, "-d", "lab.zz", "-r", lab.addr, "-axfr", "-j", "-timeout", "300ms")
	r := dnsRows(t, ls)["lab.zz"]
	axfr, _ := r["axfr"].(map[string]any)
	if chain, _ := axfr["chain"].([]any); len(chain) != 1 {
		t.Fatalf("zone: %v\n%+v", ls, rep)
	}
	if !strings.Contains(strings.Join(rep.Notes, "\n"), "127.0.0.1:53 did not transfer") {
		t.Errorf("the name server that did not answer is not said: %v", rep.Notes)
	}
	// denied, it is not asked, and the summary says so
	_, rep, _ = dnsOut(t, "-d", "lab.zz", "-r", lab.addr, "-axfr", "-j", "-timeout", "300ms", "-allow", "lab.zz", "-deny", "127.0.0.1")
	n := strings.Join(rep.Notes, "\n")
	if !strings.Contains(n, "outside the scope not asked") || strings.Contains(n, "127.0.0.1:53 did not transfer") {
		t.Errorf("%v", rep.Notes)
	}
	// the text form is the records of the zone, one per line
	ls, _, _ = dnsOut(t, "-d", "lab.zz", "-r", lab.addr, "-axfr", "-silent", "-timeout", "300ms")
	if !strings.Contains(strings.Join(ls, "\n"), "www.lab.zz. 60 IN A 192.0.2.1") {
		t.Errorf("zone: %v", ls)
	}
}

// -axfr asks the same servers in text and in -json, and -json keeps the
// transfer on the row of a zone apex that has no A record. A transfer no
// server gave is a failed technique asked for: the failed list and exit 3.
func TestDNSAXFRJSONAndTextAskTheSameServers(t *testing.T) {
	t.Chdir(t.TempDir())
	lab := startLab(t)
	labZoneMu.Lock()
	old := labZone["lab.zz."]
	labZone["lab.zz."] = []string{"NS ns.lab.zz.", "SOA ns.lab.zz. h.lab.zz. 5 1 2 3 4"}
	labZoneMu.Unlock()
	t.Cleanup(func() { labZoneMu.Lock(); labZone["lab.zz."] = old; labZoneMu.Unlock() })
	args := []string{"-d", "lab.zz", "-r", lab.addr, "-axfr", "-allow", "lab.zz", "-timeout", "300ms"}
	ls, jrep, code := dnsOut(t, append(args, "-json")...)
	r := dnsRows(t, ls)["lab.zz"]
	axfr, _ := r["axfr"].(map[string]any)
	if chain, _ := axfr["chain"].([]any); len(chain) != 1 || code != exitOK {
		t.Fatalf("a transfer that worked is not on the row (exit %d): %v\n%+v", code, ls, jrep)
	}
	ts, _, _ := dnsOut(t, append(args, "-resp")...)
	if !strings.Contains(strings.Join(ts, "\n"), "ns.lab.zz. 60 IN A 127.0.0.1") {
		t.Errorf("the text form lost the zone: %v", ts)
	}
	if len(jrep.Notes) != 1 || !strings.Contains(jrep.Notes[0], "127.0.0.1:53 did not transfer") {
		t.Errorf("the notes name only the server that failed: %v", jrep.Notes)
	}
	// The lab refuses the zone of another name: every server fails.
	for _, form := range []string{"-json", "-resp"} {
		_, rep, code := dnsOut(t, "-d", "www.lab.zz", "-r", lab.addr, "-axfr", "-allow", "lab.zz", "-timeout", "300ms", form)
		if code != exitPartial {
			t.Errorf("%s: exit %d, want %d", form, code, exitPartial)
		}
		if form == "-json" && (len(rep.Failed) != 1 || !strings.Contains(rep.Failed[0].Error, "no server transferred the zone (1 asked)") || !reflect.DeepEqual(rep.Failed[0].Targets, []string{"www.lab.zz"})) {
			t.Errorf("failed %+v", rep.Failed)
		}
	}
}

func TestDNSHostsFile(t *testing.T) {
	t.Chdir(t.TempDir())
	lab := startLab(t)
	hosts := writeList(t, "192.0.2.77 mine.lab.zz")
	old := dnsr.HostsPath
	dnsr.HostsPath = hosts
	t.Cleanup(func() { dnsr.HostsPath = old })
	ls, _, _ := dnsOut(t, "-d", "mine.lab.zz", "-r", lab.addr, "-hf", "-j")
	if r := dnsRows(t, ls)["mine.lab.zz"]; r == nil || r["hosts_file"] != true {
		t.Errorf("%v", ls)
	}
}

func TestDNSKeepsTheGraphWithDB(t *testing.T) {
	t.Chdir(t.TempDir())
	lab := startLab(t)
	_, rep, code := dnsOut(t, "-d", "www.lab.zz", "-d", "nope.lab.zz", "-r", lab.addr, "-j", "-db", "g.db")
	if code != exitOK || rep.DB != "g.db" {
		t.Fatalf("exit %d %+v", code, rep)
	}
	out, _, err := captureBoth(t, func() error { return run([]string{"query", "-db", "g.db", "-type", "Hostname"}) })
	if err != nil || !strings.Contains(out, "www.lab.zz  target  live") || !strings.Contains(out, "nope.lab.zz  target  dead") {
		t.Errorf("%v\n%s", err, out)
	}
}

func TestDNSStopsWithAnExitAndSaysWhereToGoOn(t *testing.T) {
	t.Chdir(t.TempDir())
	lab := startLab(t)
	var b strings.Builder
	for i := 0; i < 3000; i++ {
		fmt.Fprintf(&b, "n%d.lab.zz\n", i)
	}
	p := filepath.Join(t.TempDir(), "n.txt")
	_ = os.WriteFile(p, []byte(b.String()), 0o644)
	_, rep, code := dnsOut(t, "-l", p, "-r", lab.addr, "-silent", "-rl", "50", "-maxtime", "0.5", "-json")
	if code != exitLimit || !strings.Contains(rep.Stopped, "-maxtime") || !strings.Contains(rep.Resume, "-start") || rep.Counts["not asked"] == 0 {
		t.Errorf("exit %d %+v", code, rep)
	}
}

func TestDNSSpecialUseNamesGoToTheSystemOnlyWithTheDefaultResolvers(t *testing.T) {
	t.Chdir(t.TempDir())
	lab := startLab(t)
	// no -r: the defaults are public resolvers, and localhost is not theirs
	ls, rep, _ := dnsOut(t, "-d", "localhost", "-json")
	if len(dnsRows(t, ls)) != 1 || len(rep.Notes) == 0 {
		t.Errorf("%v %v", ls, rep.Notes)
	}
	// -r names a resolver: everything is asked of it, as dnsx does
	_, _, _ = dnsOut(t, "-d", "x.test", "-r", lab.addr, "-silent")
	if lab.asked.Load() != 1 {
		t.Errorf("a .test name asked of the named resolver %d times", lab.asked.Load())
	}
	if !dnsr.New(dnsr.Options{}).Reserved("a.test") || dnsr.New(dnsr.Options{Resolvers: []string{lab.addr}}).Reserved("a.test") {
		t.Error("Reserved is not about the default resolvers")
	}
}

// Names that are all outside the scope are a usage error naming them,
// not an empty success.
func TestDNSAllNamesOutsideTheScope(t *testing.T) {
	_, errOut, code := cli(t, "dns", "-d", "a.test,b.test", "-allow", "127.0.0.1", "-resolvers", "127.0.0.1:9", "-json")
	if code != exitUsage || !strings.Contains(errOut, "every target is outside the scope (2 left out): a.test, b.test") {
		t.Errorf("exit %d\n%s", code, errOut)
	}
}

// A line for each record is not a name: the summary counts the lines as
// records of so many names, the way -json counts the rows.
func TestDNSSummaryCountsRecordsAndNames(t *testing.T) {
	t.Chdir(t.TempDir())
	lab := startLab(t)
	labZoneMu.Lock()
	labZone["two.lab.zz."] = []string{"A 192.0.2.7", "A 192.0.2.8"}
	labZone["one.lab.zz."] = []string{"A 192.0.2.9"}
	labZoneMu.Unlock()
	t.Cleanup(func() {
		labZoneMu.Lock()
		delete(labZone, "two.lab.zz.")
		delete(labZone, "one.lab.zz.")
		labZoneMu.Unlock()
	})
	l := writeList(t, "two.lab.zz", "one.lab.zz")
	summary := func(args ...string) ([]string, string) {
		out, errOut, err := captureBoth(t, func() error { return run(append([]string{"dns", "-l", l, "-r", lab.addr}, args...)) })
		if err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		return lines(out), errOut
	}
	ls, head := summary("-a", "-resp")
	if len(ls) != 3 || !strings.Contains(head, "3 records of 2 names") {
		t.Errorf("-resp: %d lines, summary %q", len(ls), head)
	}
	ls, head = summary("-a")
	if len(ls) != 2 || !strings.Contains(head, "2 names") || strings.Contains(head, "records") {
		t.Errorf("one line each: %d lines, summary %q", len(ls), head)
	}
	ls, rep, _ := dnsOut(t, "-l", l, "-r", lab.addr, "-a", "-resp", "-json")
	if len(ls) != 2 || rep.Results != 2 {
		t.Errorf("-json: %d rows, results %d", len(ls), rep.Results)
	}
}

// A is the default type: -w with -json prints the names that have an A and
// nothing for the NXDOMAIN, TXT-only or AAAA-only guesses; the count note
// reconciles: asked - did not resolve = results.
func TestDNSWordlistJSONPrintsOnlyTheAskedRecord(t *testing.T) {
	t.Chdir(t.TempDir())
	lab := startLab(t)
	w := writeList(t, "www", "api", "v6", "_dmarc", "zzz")
	ls, rep, code := dnsOut(t, "-d", "lab.zz", "-w", w, "-r", lab.addr, "-json")
	r := dnsRows(t, ls)
	if code != exitOK || len(r) != 2 || r["www.lab.zz"] == nil || r["api.lab.zz"] == nil {
		t.Fatalf("exit %d rows %v", code, ls)
	}
	if rep.Results != len(ls) || rep.Counts["asked"]-rep.Counts["did not resolve"] != rep.Results || rep.Counts["did not resolve"] != 3 {
		t.Errorf("results %d, rows %d, counts %v", rep.Results, len(ls), rep.Counts)
	}
	// -rcode asks for the NXDOMAIN rows
	ls, rep, _ = dnsOut(t, "-d", "lab.zz", "-w", w, "-r", lab.addr, "-json", "-rcode", "nxdomain")
	if r := dnsRows(t, ls); len(r) != 1 || r["zzz.lab.zz"] == nil || rep.Results != 1 {
		t.Errorf("-rcode: %v %+v", ls, rep.Counts)
	}
}
