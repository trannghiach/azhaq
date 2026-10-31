package paramcol

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/trannghiach/azhaq/internal/fetch"
)

// placeholder marks where an -include template takes the names.
const placeholder = "$arjun$"

// newRequest is the request carrying q: in the query for GET, otherwise in
// a form, JSON or XML body.
func (s *search) newRequest(base *url.URL, q []pair) (*http.Request, error) {
	if len(s.fixed) > 0 {
		q = append(append(make([]pair, 0, len(s.fixed)+len(q)), s.fixed...), q...)
	}
	var req *http.Request
	var err error
	switch s.method {
	case POST, JSON, XML:
		var body []byte
		ctype := "application/x-www-form-urlencoded"
		switch s.method {
		case POST:
			body = formBody(s.include, q)
		case JSON:
			body, ctype = jsonBody(s.include, q), "application/json"
		case XML:
			body, ctype = xmlBody(s.include, q), "application/xml"
		}
		req, err = http.NewRequestWithContext(s.ctx, http.MethodPost, base.String(), bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", ctype)
	default:
		u := *base
		var b strings.Builder
		b.WriteString(u.RawQuery)
		if s.include != "" {
			if b.Len() > 0 {
				b.WriteByte('&')
			}
			b.WriteString(strings.TrimPrefix(s.include, "?"))
		}
		for _, p := range q {
			if b.Len() > 0 {
				b.WriteByte('&')
			}
			b.WriteString(url.QueryEscape(p.name) + "=" + url.QueryEscape(p.value))
		}
		u.RawQuery = b.String()
		req, err = http.NewRequestWithContext(s.ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return nil, err
		}
	}
	fetch.ApplyHeaders(req)
	for _, h := range s.header {
		if k, v, ok := strings.Cut(h, ":"); ok {
			req.Header.Set(strings.TrimSpace(k), strings.TrimSpace(v))
		}
	}
	return req, nil
}

// weight is the bytes a pair adds to a request.
func (s *search) weight(p pair) int {
	switch s.method {
	case JSON:
		return len(p.name) + len(p.value) + 6
	case XML:
		return 2*len(p.name) + len(p.value) + 5
	}
	return len(url.QueryEscape(p.name)) + len(p.value) + 2
}

func formBody(include string, q []pair) []byte {
	var b bytes.Buffer
	b.WriteString(strings.TrimPrefix(include, "?"))
	for _, p := range q {
		if b.Len() > 0 {
			b.WriteByte('&')
		}
		b.WriteString(url.QueryEscape(p.name) + "=" + url.QueryEscape(p.value))
	}
	return b.Bytes()
}

func jsonStr(s string) string {
	raw, _ := json.Marshal(s)
	return string(raw)
}

// jsonBody is the object with q's names as string members; include is
// members to keep (an object, which the names are added to) or a template
// with $arjun$ where the names go.
func jsonBody(include string, q []pair) []byte {
	var m strings.Builder
	for i, p := range q {
		if i > 0 {
			m.WriteByte(',')
		}
		m.WriteString(jsonStr(p.name) + ":" + jsonStr(p.value))
	}
	inc := strings.TrimSpace(include)
	switch {
	case inc == "":
		return []byte("{" + m.String() + "}")
	case strings.Contains(inc, placeholder):
		return []byte(strings.Replace(inc, placeholder, m.String(), 1))
	case strings.HasPrefix(inc, "{") && strings.HasSuffix(inc, "}"):
		inner := strings.TrimSpace(inc[1 : len(inc)-1])
		if inner == "" {
			return []byte("{" + m.String() + "}")
		}
		return []byte("{" + inner + "," + m.String() + "}")
	}
	return []byte("{" + m.String() + "}")
}

var xmlNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]*$`)

// xmlName says name can be an element: letters, digits, "_", "-" and ".",
// not starting with a digit or with "xml".
func xmlName(name string) bool {
	return xmlNameRE.MatchString(name) && !strings.HasPrefix(strings.ToLower(name), "xml")
}

func xmlEscape(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// xmlBody is a document with q's names as elements: inside include's last
// closing tag, in place of $arjun$, or in a <root>.
func xmlBody(include string, q []pair) []byte {
	var m strings.Builder
	for _, p := range q {
		if !xmlName(p.name) {
			continue
		}
		m.WriteString("<" + p.name + ">" + xmlEscape(p.value) + "</" + p.name + ">")
	}
	inc := strings.TrimSpace(include)
	switch {
	case inc == "":
		return []byte(`<?xml version="1.0" encoding="UTF-8"?><root>` + m.String() + `</root>`)
	case strings.Contains(inc, placeholder):
		return []byte(strings.Replace(inc, placeholder, m.String(), 1))
	}
	if i := strings.LastIndex(inc, "</"); i >= 0 {
		return []byte(inc[:i] + m.String() + inc[i:])
	}
	return []byte(`<?xml version="1.0" encoding="UTF-8"?><root>` + inc + m.String() + `</root>`)
}

var (
	jsonKeyRE = regexp.MustCompile(`"([^"\\]{1,64})"\s*:`)
	xmlTagRE  = regexp.MustCompile(`<([A-Za-z_][A-Za-z0-9_.-]*)[\s>/]`)
)

// includedNames are the names a request already carries: a query's, a
// form's, a JSON object's top-level keys, an XML document's elements.
func includedNames(method, include string) []string {
	include = strings.TrimSpace(include)
	if include == "" {
		return nil
	}
	var out []string
	switch method {
	case JSON:
		var m map[string]json.RawMessage
		if json.Unmarshal([]byte(include), &m) == nil {
			for k := range m {
				out = append(out, k)
			}
			return out
		}
		for _, m := range jsonKeyRE.FindAllStringSubmatch(include, -1) {
			out = append(out, m[1])
		}
	case XML:
		for _, m := range xmlTagRE.FindAllStringSubmatch(include, -1) {
			out = append(out, m[1])
		}
	default:
		vals, _ := url.ParseQuery(strings.TrimPrefix(include, "?"))
		for k := range vals {
			out = append(out, k)
		}
	}
	return out
}
