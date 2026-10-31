package egress

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/trannghiach/azhaq/internal/ledger"
	"github.com/trannghiach/azhaq/internal/neterr"
)

// fakeDNS answers every A question with 192.0.2.1 and counts what it got.
func fakeDNS(t *testing.T) (addr string, got *atomic.Int32) {
	t.Helper()
	got = new(atomic.Int32)
	h := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		got.Add(1)
		m := new(dns.Msg)
		m.SetReply(r)
		if r.Question[0].Qtype == dns.TypeA {
			rr, _ := dns.NewRR(r.Question[0].Name + " 60 IN A 192.0.2.1")
			m.Answer = append(m.Answer, rr)
		}
		_ = w.WriteMsg(m)
	})
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: h}
	go srv.ActivateAndServe()
	t.Cleanup(func() { srv.Shutdown() })
	return pc.LocalAddr().String(), got
}

func TestDNSExchangeIsInTheLedgerAsADNSLine(t *testing.T) {
	Reset()
	defer Reset()
	path := filepath.Join(t.TempDir(), "l.jsonl")
	l, err := ledger.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ledger.Use(l)
	defer ledger.Use(nil)
	addr, got := fakeDNS(t)
	x := NewDNSExchanger(time.Second, "")
	q := new(dns.Msg)
	q.SetQuestion("app.example.test.", dns.TypeA)
	in, err := x.Exchange(context.Background(), q, DNSServer{Key: addr, Net: DNSUDP, Addr: addr})
	if err != nil || len(in.Answer) != 1 || got.Load() != 1 {
		t.Fatalf("%v %v, server got %d", in, err, got.Load())
	}
	l.Close()
	var es []ledger.Entry
	_ = ledger.Read(path, func(e ledger.Entry) error { es = append(es, e); return nil })
	if len(es) != 1 || es[0].Kind != "dns" || es[0].Class != "dns" || es[0].Host != "app.example.test" || es[0].Method != "A" || es[0].Target != addr {
		t.Fatalf("%+v", es)
	}
}

func TestDNSExchangeStopsAtTheKillFile(t *testing.T) {
	Reset()
	defer Reset()
	path := filepath.Join(t.TempDir(), "run.stop")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	defer SetKill(path)()
	addr, got := fakeDNS(t)
	x := NewDNSExchanger(time.Second, "")
	q := new(dns.Msg)
	q.SetQuestion("a.test.", dns.TypeA)
	if _, err := x.Exchange(context.Background(), q, DNSServer{Key: addr, Net: DNSUDP, Addr: addr}); !errors.Is(err, neterr.ErrKilled) {
		t.Fatalf("%v", err)
	}
	if _, err := x.ExchangeAt(context.Background(), q, addr); !errors.Is(err, neterr.ErrKilled) {
		t.Fatalf("%v", err)
	}
	if got.Load() != 0 {
		t.Fatalf("the server got %d queries", got.Load())
	}
}

func TestCheckDNSProxyTakesSocks5Only(t *testing.T) {
	if err := CheckDNSProxy("socks5://127.0.0.1:1080"); err != nil {
		t.Error(err)
	}
	if err := CheckDNSProxy("http://127.0.0.1:8080"); err == nil || !strings.Contains(err.Error(), "socks5") {
		t.Errorf("an http proxy: %v", err)
	}
}
