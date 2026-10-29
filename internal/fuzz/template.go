package fuzz

import (
	"fmt"
	"net/textproto"
	"strings"
)

// Header is one request header; its name and value may hold keywords.
type Header struct{ Name, Value string }

// Template is the request every input is put into.
type Template struct {
	Method  string
	URL     string
	Headers []Header
	Data    string
}

// Request is a template with its keywords replaced.
type Request struct {
	Method   string
	URL      string
	Headers  []Header // names in canonical form, one per name
	Data     string
	Input    map[string]string
	Position int // 1-based place in the job's inputs
}

// Has says whether keyword appears in the method, URL, a header or the body.
func (t Template) Has(keyword string) bool {
	if strings.Contains(t.Method, keyword) || strings.Contains(t.URL, keyword) || strings.Contains(t.Data, keyword) {
		return true
	}
	for _, h := range t.Headers {
		if strings.Contains(h.Name, keyword) || strings.Contains(h.Value, keyword) {
			return true
		}
	}
	return false
}

// Expand puts each input value where its keyword stands.
func (t Template) Expand(in map[string]string) Request {
	pairs := make([]string, 0, 2*len(in))
	for k, v := range in {
		pairs = append(pairs, k, v)
	}
	r := strings.NewReplacer(pairs...)
	if len(pairs) == 0 {
		r = strings.NewReplacer()
	}
	req := Request{Method: r.Replace(t.Method), URL: r.Replace(t.URL), Data: r.Replace(t.Data), Input: in}
	seen := map[string]int{}
	for _, h := range t.Headers {
		name := textproto.CanonicalMIMEHeaderKey(r.Replace(h.Name))
		hv := Header{name, r.Replace(h.Value)}
		if i, ok := seen[name]; ok {
			req.Headers[i] = hv // one value per name, the last given, as ffuf
			continue
		}
		seen[name] = len(req.Headers)
		req.Headers = append(req.Headers, hv)
	}
	return req
}

// NewTemplate is what the command line says: a method (POST when there is
// data and none was given, as in ffuf), the URL, headers as "Name: value"
// and cookies, which are one Cookie header.
func NewTemplate(method, rawURL, data string, headers, cookies []string) (Template, error) {
	t := Template{Method: strings.TrimSpace(method), URL: rawURL, Data: data}
	if t.Method == "" {
		t.Method = "GET"
		if data != "" {
			t.Method = "POST"
		}
	}
	for _, raw := range headers {
		name, value, ok := strings.Cut(raw, ":")
		if !ok || strings.TrimSpace(name) == "" {
			return Template{}, fmt.Errorf("-H %q: want \"Name: value\"", raw)
		}
		t.Headers = append(t.Headers, Header{strings.TrimSpace(name), strings.TrimSpace(value)})
	}
	if len(cookies) > 0 {
		t.Headers = append(t.Headers, Header{"Cookie", strings.Join(cookies, "; ")})
	}
	return t, nil
}
