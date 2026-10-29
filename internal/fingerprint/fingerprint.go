// Package fingerprint names what answers a request: technologies from
// headers and body (wappalyzergo), CDN, WAF and cloud ranges (cdncheck's),
// and the Shodan-style favicon hash. All data is embedded; nothing here
// sends a request.
package fingerprint

import (
	"bytes"
	"encoding/base64"
	"net"
	"net/http"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/trannghiach/azhaq/internal/cdnranges"
	"github.com/trannghiach/azhaq/internal/wappalyzer"
)

var (
	techOnce sync.Once
	techDB   *wappalyzer.Wappalyze
)

func tech() *wappalyzer.Wappalyze {
	techOnce.Do(func() {
		// Loading parses every pattern to find its literals, which
		// allocates far more than it keeps; collecting often while it runs
		// keeps the process's peak memory near what stays.
		old := debug.SetGCPercent(10)
		techDB, _ = wappalyzer.New()
		debug.SetGCPercent(old)
	})
	return techDB
}

// Tech lists the technologies a response shows, sorted, each as "Name" or
// "Name:version" the way wappalyzer reports them.
func Tech(h http.Header, body []byte) []string {
	db := tech()
	if db == nil {
		return nil
	}
	found := db.Fingerprint(h, body)
	out := make([]string, 0, len(found))
	for t := range found {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// Network says whether ip is in a known CDN, WAF or cloud range: the
// provider name and "cdn", "waf" or "cloud", or empty strings.
func Network(ip net.IP) (name, kind string) {
	if ip == nil {
		return "", ""
	}
	ok, name, kind, err := cdnranges.Check(ip)
	if err != nil || !ok {
		return "", ""
	}
	return name, kind
}

// NetworkByName checks CNAME targets against known CDN and WAF suffixes
// (*.cloudfront.net, *.akamaiedge.net, …).
func NetworkByName(names ...string) (name, kind string) {
	var clean []string
	for _, n := range names {
		if n = strings.TrimSuffix(strings.TrimSpace(n), "."); n != "" {
			clean = append(clean, n)
		}
	}
	if len(clean) == 0 {
		return "", ""
	}
	ok, name, kind, err := cdnranges.CheckSuffix(clean...)
	if err != nil || !ok {
		return "", ""
	}
	return name, kind
}

// Favicon returns the hash Shodan indexes as http.favicon.hash: MurmurHash3
// (32-bit, seed 0) of the base64 encoding with a newline every 76
// characters and at the end. Data that is not an image has no hash.
func Favicon(data []byte) (string, bool) {
	if len(data) == 0 || !strings.HasPrefix(http.DetectContentType(data), "image/") {
		return "", false
	}
	enc := base64.StdEncoding.EncodeToString(data)
	var b bytes.Buffer
	for len(enc) > 76 {
		b.WriteString(enc[:76])
		b.WriteByte('\n')
		enc = enc[76:]
	}
	b.WriteString(enc)
	b.WriteByte('\n')
	return strconv.Itoa(int(int32(murmur3hash(b.Bytes())))), true
}

// Stats are httpx's word and line counts: spaces plus one, and newlines
// in the trimmed body plus one.
func Stats(body []byte) (words, lines int) {
	if len(body) == 0 {
		return 0, 0
	}
	return bytes.Count(body, []byte{' '}) + 1, bytes.Count(bytes.TrimSpace(body), []byte{'\n'}) + 1
}
