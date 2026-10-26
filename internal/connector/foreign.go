package connector

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"github.com/trannghiach/azhaq/internal/normalize"
	"github.com/trannghiach/azhaq/types"
)

// Formats ReadAny understands besides connector facts, by the fields of
// their JSON lines.
const (
	FormatFacts     = "azhaq facts"
	FormatExport    = "azhaq export"
	FormatSubfinder = "subfinder"
	FormatDNSX      = "dnsx"
	FormatHTTPX     = "httpx"
	FormatKatana    = "katana"
	FormatNaabu     = "naabu"
	FormatFFUF      = "ffuf"
	FormatNuclei    = "nuclei"
	FormatURLs      = "urls"
	FormatLines     = "plain lines"
)

// ReadAny reads facts from what the usual recon tools write: connector
// facts, Azhaq's own export, subfinder, dnsx, httpx, katana, naabu,
// nuclei and gau JSON lines, ffuf's JSON report, or plain lines of URLs,
// hostnames and addresses. It returns the facts and, for each format
// seen, how many lines were read as it.
func ReadAny(raw []byte) ([]Fact, map[string]int, error) {
	formats := map[string]int{}
	trimmed := bytes.TrimSpace(raw)
	if bytes.HasPrefix(trimmed, []byte("{")) && !bytes.Contains(trimmed, []byte("\n{")) {
		var report struct {
			Results []map[string]any `json:"results"`
		}
		err := json.Unmarshal(trimmed, &report)
		if err == nil && report.Results == nil && bytes.Count(trimmed, []byte("\n")) > 0 {
			return nil, nil, fmt.Errorf("one JSON document, not JSON lines: ingest reads tools' line-by-line output (and ffuf's report)")
		}
		if err == nil && report.Results != nil {
			var out []Fact
			for _, r := range report.Results {
				out = append(out, ffufFacts(r)...)
			}
			formats[FormatFFUF] = len(report.Results)
			return out, formats, nil
		}
	}
	var out []Fact
	exported := map[string][2]string{} // export entity id → type, key
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 64*1024), 8<<20)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, "{") {
			f, ok := plainFact(line)
			if !ok {
				return nil, nil, fmt.Errorf("line %d: not JSON, and not a URL, hostname or address: %q", lineNo, clip(line))
			}
			formats[FormatLines]++
			out = append(out, f)
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			return nil, nil, fmt.Errorf("line %d: %w", lineNo, err)
		}
		facts, format, err := lineFacts([]byte(line), m, exported)
		if err != nil {
			return nil, nil, fmt.Errorf("line %d: %w", lineNo, err)
		}
		formats[format]++
		out = append(out, facts...)
	}
	return out, formats, sc.Err()
}

func lineFacts(raw []byte, m map[string]any, exported map[string][2]string) ([]Fact, string, error) {
	str := func(k string) string { s, _ := m[k].(string); return s }
	has := func(k string) bool { _, ok := m[k]; return ok }
	switch {
	case has("kind") && (has("entity") || has("edge") || isExportObservation(m)):
		return exportFacts(m, exported), FormatExport, nil
	case has("kind"):
		f, err := DecodeLine(raw)
		if err == nil {
			err = CheckLine(f, raw)
		}
		return []Fact{f}, FormatFacts, err
	case has("template-id") && has("matched-at"):
		info, _ := m["info"].(map[string]any)
		target := str("matched-at")
		payload := map[string]any{"url": target, "template": str("template-id"), "name": info["name"], "severity": info["severity"]}
		return []Fact{observation(urlOrHost(target), "nuclei", "finding", payload)}, FormatNuclei, nil
	case has("request") && has("timestamp"):
		req, _ := m["request"].(map[string]any)
		endpoint, _ := req["endpoint"].(string)
		payload := map[string]any{"url": endpoint, "via": "katana"}
		if resp, ok := m["response"].(map[string]any); ok {
			if st, ok := resp["status_code"].(float64); ok {
				payload["status"] = int(st)
			}
		}
		if mm, _ := req["method"].(string); mm != "" && mm != "GET" {
			payload["methods"] = []string{mm}
		}
		return urlFacts(endpoint, "katana", payload), FormatKatana, nil
	case has("url") && (has("status_code") || has("webserver") || has("tech")):
		return httpxFacts(m), FormatHTTPX, nil
	case has("host") && has("port") && !has("url"):
		host, ip := str("host"), str("ip")
		port := fmt.Sprint(m["port"])
		if host == "" {
			host = ip
		}
		payload := map[string]any{"host": host, "ip": ip, "open": []string{port}, "services": []map[string]any{{"port": m["port"]}}, "via": "naabu"}
		return []Fact{observation(hostSeed(host), "naabu", "ports", payload)}, FormatNaabu, nil
	case has("host") && (has("a") || has("aaaa") || has("cname")) && !has("url"):
		host := str("host")
		ips := append(strings2(m["a"]), strings2(m["aaaa"])...)
		payload := map[string]any{"fqdn": host, "ips": ips, "via": "dnsx"}
		if cn := strings2(m["cname"]); len(cn) > 0 {
			payload["cname"], payload["cnames"] = cn[0], cn
		}
		if len(ips) > 0 {
			payload["result"] = "ok"
		}
		return []Fact{observation(hostSeed(host), "dnsx", "dns", payload)}, FormatDNSX, nil
	case has("host") && !has("url"):
		host := str("host")
		payload := map[string]any{"fqdn": host, "source": str("source"), "input": str("input"), "via": "subfinder"}
		return []Fact{observation(hostSeed(host), "subfinder", "hostname", payload)}, FormatSubfinder, nil
	case has("url"):
		u := str("url")
		return urlFacts(u, "urls", map[string]any{"url": u, "via": "list"}), FormatURLs, nil
	}
	return nil, "", fmt.Errorf("a JSON line Azhaq does not know: no kind, url, host or endpoint field")
}

func isExportObservation(m map[string]any) bool {
	o, ok := m["observation"].(map[string]any)
	if !ok {
		return false
	}
	_, ok = o["entity_id"]
	return ok
}

// exportFacts turns azhaq export's lines back into facts: entities as
// they are, observations onto the entity their line named earlier.
func exportFacts(m map[string]any, exported map[string][2]string) []Fact {
	switch m["kind"] {
	case "entity":
		e, _ := m["entity"].(map[string]any)
		id, _ := e["id"].(string)
		t, _ := e["type"].(string)
		key, _ := e["key"].(string)
		if key == "" {
			return nil
		}
		exported[id] = [2]string{t, key}
		return []Fact{{Kind: "entity", EntityType: types.SeedType(t), EntityKey: key}}
	case "observation":
		o, _ := m["observation"].(map[string]any)
		id, _ := o["entity_id"].(string)
		ent, ok := exported[id]
		if !ok {
			return nil
		}
		payload, _ := json.Marshal(o["payload"])
		col, _ := o["collector"].(string)
		kind, _ := o["kind"].(string)
		src, _ := o["source"].(string)
		return []Fact{{Kind: "observation", EntityType: types.SeedType(ent[0]), EntityKey: ent[1], Collector: col, ObsKind: kind, Source: src, Payload: payload, Confidence: 0.8}}
	}
	return nil // edges: the facts rebuild them
}

func httpxFacts(m map[string]any) []Fact {
	u, _ := m["url"].(string)
	payload := map[string]any{"url": u, "via": "httpx"}
	if st, ok := m["status_code"].(float64); ok {
		payload["status"] = int(st)
	}
	for from, to := range map[string]string{"title": "title", "webserver": "server", "content_type": "content_type", "tech": "tech", "final_url": "final_url", "favicon": "favicon"} {
		if v, ok := m[from]; ok {
			payload[to] = v
		}
	}
	ip, _ := m["host_ip"].(string)
	if ip == "" {
		if h, _ := m["host"].(string); net.ParseIP(h) != nil {
			ip = h
		}
	}
	if ip != "" {
		payload["ip"] = ip
	}
	facts := []Fact{observation(urlSeed(u), "httpx", "application", payload)}
	host := normalize.HostFromURL(u)
	if a := strings2(m["a"]); len(a) > 0 && host != "" && net.ParseIP(host) == nil {
		facts = append(facts, observation(hostSeed(host), "httpx", "dns", map[string]any{"fqdn": host, "ips": a, "result": "ok", "via": "httpx"}))
	}
	return facts
}

func ffufFacts(r map[string]any) []Fact {
	u, _ := r["url"].(string)
	payload := map[string]any{"url": u, "via": "ffuf"}
	for _, k := range []string{"status", "length", "words", "lines"} {
		if v, ok := r[k].(float64); ok {
			payload[k] = int(v)
		}
	}
	if loc, _ := r["redirectlocation"].(string); loc != "" {
		payload["location"] = loc
	}
	return urlFacts(u, "ffuf", payload)
}

// urlFacts records a URL a tool reported: an observation on the URL, so
// the map shows how it answered.
func urlFacts(u, collector string, payload map[string]any) []Fact {
	if _, err := normalize.URL(u); err != nil {
		return nil
	}
	kind := "url"
	if _, answered := payload["status"]; answered {
		kind = "application"
	}
	return []Fact{observation(urlSeed(u), collector, kind, payload)}
}

func observation(s types.Seed, collector, kind string, payload map[string]any) Fact {
	raw, _ := json.Marshal(payload)
	return Fact{Kind: "observation", EntityType: s.Type, EntityKey: s.Key(), Collector: collector, ObsKind: kind, Source: collector, Payload: raw, Confidence: 0.8}
}

// plainFact reads one line of a plain list: a URL, a hostname or an
// address.
func plainFact(line string) (Fact, bool) {
	line = strings.TrimSpace(line)
	switch {
	case strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://"):
		if u, err := normalize.URL(line); err == nil {
			return Fact{Kind: "entity", EntityType: types.TypeURL, EntityKey: u}, true
		}
	case net.ParseIP(line) != nil:
		return Fact{Kind: "entity", EntityType: types.TypeIPAddress, EntityKey: net.ParseIP(line).String()}, true
	default:
		if h := normalize.Hostname(line); h != "" && strings.Contains(h, ".") && !strings.ContainsAny(h, " /:@") {
			return Fact{Kind: "entity", EntityType: types.TypeHostname, EntityKey: h}, true
		}
	}
	return Fact{}, false
}

func urlSeed(u string) types.Seed {
	if n, err := normalize.URL(u); err == nil {
		u = n
	}
	return types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": u}}
}

func hostSeed(h string) types.Seed {
	if ip := net.ParseIP(h); ip != nil {
		return types.Seed{Type: types.TypeIPAddress, Keys: map[string]string{"ip": ip.String()}}
	}
	return types.Seed{Type: types.TypeHostname, Keys: map[string]string{"fqdn": normalize.Hostname(h)}}
}

func urlOrHost(target string) types.Seed {
	if strings.Contains(target, "://") {
		return urlSeed(target)
	}
	h, _, err := net.SplitHostPort(target)
	if err != nil {
		h = target
	}
	return hostSeed(h)
}

func strings2(v any) []string {
	xs, _ := v.([]any)
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		if s, ok := x.(string); ok && s != "" {
			out = append(out, s)
		}
	}
	return out
}

func clip(s string) string {
	if len(s) > 80 {
		return s[:80] + "…"
	}
	return s
}
