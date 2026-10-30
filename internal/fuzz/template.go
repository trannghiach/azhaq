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

// WithHeader sets a header: it replaces the one of the same name (as a name
// is written in a request file, in any case) or is added.
func (t Template) WithHeader(name, value string) Template {
	hs := append([]Header(nil), t.Headers...)
	for i, h := range hs {
		if textproto.CanonicalMIMEHeaderKey(h.Name) == textproto.CanonicalMIMEHeaderKey(name) {
			hs[i] = Header{name, value}
			return Template{t.Method, t.URL, hs, t.Data}
		}
	}
	return Template{t.Method, t.URL, append(hs, Header{name, value}), t.Data}
}

// SniperMark is what -mode sniper takes as the start and end of a place a
// word goes: §word§.
const SniperMark = "§"

// SniperTemplates are the requests of -mode sniper: one for each pair of
// marks in the method, URL, body and headers (names, then values), with the
// keyword FUZZ where that pair stood and the other marks removed, as ffuf
// does. A field with an odd number of marks has none.
func SniperTemplates(t Template) []Template {
	var out []Template
	scrub := func(c Template) Template {
		c.Method = strings.ReplaceAll(c.Method, SniperMark, "")
		c.URL = strings.ReplaceAll(c.URL, SniperMark, "")
		c.Data = strings.ReplaceAll(c.Data, SniperMark, "")
		hs := make([]Header, len(c.Headers))
		for i, h := range c.Headers {
			if strings.Count(h.Name, SniperMark)%2 == 0 {
				h.Name = strings.ReplaceAll(h.Name, SniperMark, "")
			}
			if strings.Count(h.Value, SniperMark)%2 == 0 {
				h.Value = strings.ReplaceAll(h.Value, SniperMark, "")
			}
			hs[i] = h
		}
		c.Headers = hs
		return c
	}
	field := func(s string, put func(c *Template, v string)) {
		for _, v := range sniperInject(s) {
			c := t
			c.Headers = append([]Header(nil), t.Headers...)
			put(&c, v)
			out = append(out, scrub(c))
		}
	}
	field(t.Method, func(c *Template, v string) { c.Method = v })
	field(t.URL, func(c *Template, v string) { c.URL = v })
	field(t.Data, func(c *Template, v string) { c.Data = v })
	for i := range t.Headers {
		i := i
		field(t.Headers[i].Name, func(c *Template, v string) { c.Headers[i].Name = v })
		field(t.Headers[i].Value, func(c *Template, v string) { c.Headers[i].Value = v })
	}
	return out
}

// sniperInject gives s once for each pair of marks, that pair and what is
// between replaced by FUZZ; nothing for an odd number of marks.
func sniperInject(s string) []string {
	if n := strings.Count(s, SniperMark); n == 0 || n%2 != 0 {
		return nil
	}
	runes := []rune(s)
	var marks []int
	for i, r := range runes {
		if string(r) == SniperMark {
			marks = append(marks, i)
		}
	}
	var out []string
	for i := 0; i+1 < len(marks); i += 2 {
		out = append(out, string(runes[:marks[i]])+"FUZZ"+string(runes[marks[i+1]+1:]))
	}
	return out
}

// HasSniperMarks says the template has at least one pair of marks, and
// every field that has any has an even number.
func HasSniperMarks(t Template) (bool, error) {
	any := false
	check := func(what, s string) error {
		switch n := strings.Count(s, SniperMark); {
		case n == 0:
		case n%2 != 0:
			return fmt.Errorf("the %s has an odd number of %s marks: they come in pairs", what, SniperMark)
		default:
			any = true
		}
		return nil
	}
	for what, s := range map[string]string{"method": t.Method, "URL": t.URL, "body": t.Data} {
		if err := check(what, s); err != nil {
			return false, err
		}
	}
	for _, h := range t.Headers {
		if err := check("header "+h.Name, h.Name); err != nil {
			return false, err
		}
		if err := check("header "+h.Name, h.Value); err != nil {
			return false, err
		}
	}
	return any, nil
}
