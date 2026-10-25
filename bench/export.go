package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net/url"
	"strings"
	"time"
)

// graph is what `azhaq export` prints, parsed.
type graph struct {
	rows []row
	obs  []obs
}

type row struct {
	Entity struct {
		Type string `json:"type"`
		Key  string `json:"key"`
	} `json:"entity"`
	Scope    string `json:"scope"`
	Coverage string `json:"coverage"`
	Role     string `json:"role"`
	Template string `json:"template"`
	Forms    []struct {
		Method string   `json:"method"`
		Action string   `json:"action"`
		Fields []string `json:"fields"`
	} `json:"forms"`
}

type obs struct {
	Collector  string          `json:"collector"`
	Kind       string          `json:"kind"`
	Payload    json.RawMessage `json:"payload"`
	ObservedAt time.Time       `json:"observed_at"`
}

func readExport(out []byte) graph {
	var g graph
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for sc.Scan() {
		var line struct {
			Kind        string          `json:"kind"`
			Observation json.RawMessage `json:"observation"`
		}
		if json.Unmarshal(sc.Bytes(), &line) != nil {
			continue
		}
		switch line.Kind {
		case "entity":
			var r row
			if json.Unmarshal(sc.Bytes(), &r) == nil {
				g.rows = append(g.rows, r)
			}
		case "observation":
			var o obs
			if json.Unmarshal(line.Observation, &o) == nil {
				g.obs = append(g.obs, o)
			}
		}
	}
	return g
}

func (g graph) urls() []string {
	var out []string
	for _, r := range g.rows {
		if r.Entity.Type == "URL" {
			out = append(out, r.Entity.Key)
		}
	}
	return out
}

// httpFacts maps a URL to what azhaq-http recorded for it.
func (g graph) httpFacts() map[string]map[string]any {
	out := map[string]map[string]any{}
	for _, o := range g.obs {
		if o.Collector != "azhaq-http" {
			continue
		}
		var p map[string]any
		if json.Unmarshal(o.Payload, &p) != nil {
			continue
		}
		if u, _ := p["url"].(string); u != "" {
			out[u] = p
		}
	}
	return out
}

func (g graph) payloads(collector string) []map[string]any {
	var out []map[string]any
	for _, o := range g.obs {
		if o.Collector != collector {
			continue
		}
		var p map[string]any
		if json.Unmarshal(o.Payload, &p) == nil {
			out = append(out, p)
		}
	}
	return out
}

// route is a URL's path without query or trailing slash, the unit routes
// are counted in.
func route(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	p := strings.TrimSuffix(u.Path, "/")
	if p == "" {
		p = "/"
	}
	return p
}

// routes keeps the routes of URLs on origin, skipping static assets.
func routes(urls []string, origin string) map[string]bool {
	out := map[string]bool{}
	for _, raw := range urls {
		if !strings.HasPrefix(raw, origin) {
			continue
		}
		r := route(raw)
		if r == "" || asset(r) {
			continue
		}
		out[r] = true
	}
	return out
}

func asset(path string) bool {
	p := strings.ToLower(path)
	for _, ext := range []string{".js", ".mjs", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".woff", ".woff2", ".ttf", ".map"} {
		if strings.HasSuffix(p, ext) {
			return true
		}
	}
	return false
}

func lines(out []byte) []string {
	var res []string
	for _, l := range strings.Split(string(out), "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			res = append(res, l)
		}
	}
	return res
}
