package fingerprint

import (
	"bytes"
	"encoding/base64"
	"net"
	"net/http"
	"strconv"
	"testing"
)

// A 1×1 PNG.
var png1x1, _ = base64.StdEncoding.DecodeString("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGNgYGD4DwABBAEAwS2OUAAAAABJRU5ErkJggg==")

func TestFaviconMatchesShodanEncoding(t *testing.T) {
	got, ok := Favicon(png1x1)
	if !ok {
		t.Fatal("png not hashed")
	}
	// Shodan's recipe, spelled out: base64 with a newline after every 76
	// characters and one at the end, then signed MurmurHash3.
	shodan := func(data []byte) string {
		enc := base64.StdEncoding.EncodeToString(data)
		var b bytes.Buffer
		for i := 0; i < len(enc); i++ {
			b.WriteByte(enc[i])
			if i%76 == 75 && i != len(enc)-1 {
				b.WriteByte('\n')
			}
		}
		b.WriteByte('\n')
		return strconv.Itoa(int(int32(murmur3hash(b.Bytes()))))
	}
	if got != shodan(png1x1) {
		t.Errorf("favicon %s, want %s", got, shodan(png1x1))
	}
	// 152 base64 characters: exactly two lines.
	exact := append(bytes.Clone(png1x1), make([]byte, 114-len(png1x1))...)
	if got, _ := Favicon(exact); got != shodan(exact) {
		t.Errorf("two-line favicon %s, want %s", got, shodan(exact))
	}
	if _, ok := Favicon([]byte("<html>not found</html>")); ok {
		t.Error("an HTML error page was hashed as a favicon")
	}
}

func TestMurmur3Vectors(t *testing.T) {
	for in, want := range map[string]uint32{
		"": 0, "hello": 0x248bfa47, "Hello, world!": 3224780355,
		"The quick brown fox jumps over the lazy dog": 776992547,
	} {
		if got := murmur3hash([]byte(in)); got != want {
			t.Errorf("%q: %d, want %d", in, got, want)
		}
	}
}

func TestTechAndNetwork(t *testing.T) {
	h := http.Header{"Server": {"nginx/1.18.0"}}
	got := Tech(h, []byte(`<html><head><script src="/wp-includes/js/jquery/jquery.min.js?ver=3.6.0"></script><meta name="generator" content="WordPress 6.4"></head></html>`))
	has := map[string]bool{}
	for _, x := range got {
		has[x] = true
	}
	if !has["Nginx:1.18.0"] || !has["WordPress:6.4"] {
		t.Errorf("tech %v", got)
	}
	if name, kind := Network(net.ParseIP("104.16.0.1")); name != "cloudflare" || kind == "" {
		t.Errorf("cloudflare range: %q %q", name, kind)
	}
	if name, _ := Network(net.ParseIP("192.0.2.1")); name != "" {
		t.Errorf("documentation range matched %q", name)
	}
	if name, _ := NetworkByName("d111111abcdef8.cloudfront.net"); name == "" {
		t.Error("cloudfront CNAME not recognised")
	}
}

func TestStats(t *testing.T) {
	if w, l := Stats([]byte("a b c\nd e\n")); w != 4 || l != 2 {
		t.Errorf("words %d lines %d", w, l)
	}
	if w, l := Stats(nil); w != 0 || l != 0 {
		t.Errorf("empty: %d %d", w, l)
	}
}
