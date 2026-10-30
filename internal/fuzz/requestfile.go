package fuzz

import (
	"bufio"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
)

// ParseRequestFile reads a raw HTTP request (Burp's "copy to file") as ffuf's
// -request does: the request line, the headers up to a blank line (Content-Length
// dropped, as it is worked out again), the body. The URL is the protocol and the
// Host header with the path; a request line that holds a whole URL is used as it
// is, and its host becomes the Host header. The URL is empty when the file
// names no host: -u says where it goes.
func ParseRequestFile(path, proto string) (Template, error) {
	f, err := os.Open(path)
	if err != nil {
		return Template{}, fmt.Errorf("could not open request file: %v", err)
	}
	defer f.Close()
	r := bufio.NewReader(f)
	line, err := r.ReadString('\n')
	if err != nil && line == "" {
		return Template{}, fmt.Errorf("could not read request: %v", err)
	}
	parts := strings.Split(strings.TrimRight(line, "\r\n"), " ")
	if len(parts) < 3 {
		return Template{}, fmt.Errorf("malformed request line %q: want METHOD PATH HTTP/1.1", strings.TrimSpace(line))
	}
	t := Template{Method: parts[0]}
	host := ""
	for {
		l, err := r.ReadString('\n')
		l = strings.TrimSpace(l)
		if err != nil || l == "" {
			break
		}
		name, value, ok := strings.Cut(l, ":")
		if !ok || strings.EqualFold(strings.TrimSpace(name), "content-length") {
			continue
		}
		name, value = strings.TrimSpace(name), strings.TrimSpace(value)
		if strings.EqualFold(name, "host") {
			host = value
		}
		t = t.WithHeader(name, value)
	}
	switch {
	case strings.HasPrefix(parts[1], "http"):
		u, err := url.Parse(parts[1])
		if err != nil {
			return Template{}, fmt.Errorf("could not parse the request URL: %v", err)
		}
		t.URL = parts[1]
		t = t.WithHeader("Host", u.Host)
	case host == "":
		// no place to send it: -u must say
	default:
		t.URL = proto + "://" + host + parts[1]
	}
	body, err := io.ReadAll(r)
	if err != nil {
		return Template{}, fmt.Errorf("could not read the request body: %v", err)
	}
	t.Data = string(body)
	if strings.HasSuffix(t.Data, "\r\n") {
		t.Data = t.Data[:len(t.Data)-2]
	} else {
		t.Data = strings.TrimSuffix(t.Data, "\n")
	}
	return t, nil
}
