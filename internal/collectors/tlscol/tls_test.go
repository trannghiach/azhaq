package tlscol

import (
	"crypto/tls"
	"crypto/x509"
	"testing"
	"time"

	"github.com/trannghiach/azhaq/internal/types"
)

func TestSANHintsStayOnSite(t *testing.T) {
	col := &Collector{}
	cert := &x509.Certificate{
		DNSNames: []string{
			"api.example.test",
			"www.example.test",
			"dead.traefik.default",
			"cdn.other.test",
		},
		NotAfter: time.Now().Add(time.Hour),
	}
	meta, err := col.emitState("www.example.test", tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}, func(types.Observation) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(meta.NextHints) != 1 || meta.NextHints[0].Key() != "api.example.test" {
		t.Fatalf("hints %+v", meta.NextHints)
	}
}
