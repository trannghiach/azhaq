package connector

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"mime"
	"mime/multipart"
	"net"
	"net/url"
	"slices"
	"strings"
	"time"

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
			Config  struct {
				Method string `json:"method"`
			} `json:"config"`
		}
		err := json.Unmarshal(trimmed, &report)
		if err == nil && report.Results == nil && bytes.Count(trimmed, []byte("\n")) > 0 {
			return nil, nil, fmt.Errorf("one JSON document, not JSON lines: ingest reads tools' line-by-line output (and ffuf's report)")
		}
		if err == nil && report.Results != nil {
			var out []Fact
			for _, r := range report.Results {
				out = append(out, ffufFacts(r, report.Config.Method)...)
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
		return katanaFacts(m), FormatKatana, nil
	case has("url") && (has("status_code") || has("webserver") || has("tech")):
		return httpxFacts(m), FormatHTTPX, nil
	case has("url") && has("status") && has("redirectlocation"):
		return ffufFacts(m, ""), FormatFFUF, nil // ffuf -json: one result per line
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

// httpxFacts reads one httpx line as the answer azhaq-http records for a
// URL, under azhaq-http's field names: the map, probe rows and exports
// (targets, burp) read it as their own.
func httpxFacts(m map[string]any) []Fact {
	u, err := normalize.URL(text(m["url"]))
	if err != nil {
		return nil
	}
	if failed, _ := m["failed"].(bool); failed {
		// -probe lists what did not answer: requested, no answer, as
		// azhaq-http records a failure.
		msg := text(m["error"])
		if msg == "" {
			msg = "no answer"
		}
		return []Fact{observation(urlSeed(u), "httpx", "error", map[string]any{"url": u, "error": msg, "via": "httpx"})}
	}
	payload := map[string]any{"url": u, "via": "httpx"}
	if st, ok := m["status_code"].(float64); ok {
		payload["status"] = int(st)
	}
	// With -fr, status_code is where the redirects ended; Azhaq's status
	// is the first answer and final_status the last.
	if chain := ints(m["chain_status_codes"]); len(chain) > 1 {
		payload["status"], payload["final_status"] = chain[0], chain[len(chain)-1]
	}
	for from, to := range map[string]string{"title": "title", "webserver": "server", "content_type": "content_type", "tech": "tech", "favicon": "favicon", "location": "location", "cdn_name": "cdn", "cdn_type": "cdn_type"} {
		if v, ok := m[from]; ok {
			payload[to] = v
		}
	}
	for from, to := range map[string]string{"content_length": "length", "words": "words", "lines": "lines"} {
		if v, ok := m[from].(float64); ok {
			payload[to] = int(v)
		}
	}
	if f, err := normalize.URL(text(m["final_url"])); err == nil {
		payload["final_url"] = f
	}
	if d, err := time.ParseDuration(text(m["time"])); err == nil {
		payload["ms"] = d.Milliseconds()
	}
	ip := text(m["host_ip"])
	if h := text(m["host"]); ip == "" && net.ParseIP(h) != nil {
		ip = h // httpx before host_ip wrote the address as host
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

// katanaFacts reads one katana line: the request and its answer, the
// forms katana read on the page (-fx) and the requests its scripts sent
// (-xhr).
func katanaFacts(m map[string]any) []Fact {
	req, _ := m["request"].(map[string]any)
	resp, _ := m["response"].(map[string]any)
	out := requestFacts(req, resp)
	if len(out) == 0 {
		return nil
	}
	page := out[0].EntityKey
	forms, _ := resp["forms"].([]any)
	for _, x := range forms {
		f, _ := x.(map[string]any)
		action, ok := page, true
		if a := text(f["action"]); a != "" {
			action, ok = resolve(page, a)
		}
		method := strings.ToUpper(text(f["method"]))
		if method == "" {
			method = "GET"
		}
		if ok {
			out = append(out, observation(urlSeed(page), "katana", "form", map[string]any{"method": method, "action": action, "fields": strings2(f["parameters"]), "via": "katana"}))
		}
	}
	xhr, _ := resp["xhr_requests"].([]any)
	for _, x := range xhr {
		r, _ := x.(map[string]any)
		out = append(out, requestFacts(r, nil)...)
	}
	return out
}

// requestFacts reads a request katana sent or saw sent. The answer to a
// GET is the URL's answer, as azhaq-http records one. A request with
// another method says what the route takes (the method, its query and
// body fields), as a call in a script does: no GET was sent, so it is not
// the URL's answer.
func requestFacts(req, resp map[string]any) []Fact {
	u, err := normalize.URL(text(req["endpoint"]))
	if err != nil {
		return nil
	}
	if method := strings.ToUpper(text(req["method"])); method != "" && method != "GET" {
		op := map[string]any{"method": method}
		row := map[string]any{"url": u, "via": "katana", "methods": []string{method}}
		if q := queryNames(u); len(q) > 0 {
			op["query"], row["params"] = q, q
		}
		if names, media := bodyFields(text(req["body"]), header(req, "content-type")); len(names) > 0 {
			op["body"], op["body_type"], row["body"] = names, media, names
		}
		row["ops"] = []any{op}
		return []Fact{observation(urlSeed(u), "katana", "url", row)}
	}
	payload := map[string]any{"url": u, "via": "katana"}
	st, _ := resp["status_code"].(float64)
	if st <= 0 {
		return []Fact{observation(urlSeed(u), "katana", "url", payload)}
	}
	payload["status"] = int(st)
	for from, to := range map[string]string{"content-type": "content_type", "server": "server", "location": "location"} {
		if v := header(resp, from); v != "" {
			payload[to] = v
		}
	}
	if tech := strings2(resp["technologies"]); len(tech) > 0 {
		payload["tech"] = tech
	}
	if n, ok := resp["content_length"].(float64); ok {
		payload["length"] = int(n)
	} else if body, ok := resp["body"].(string); ok {
		payload["length"] = len(body)
	}
	return []Fact{observation(urlSeed(u), "katana", "application", payload)}
}

// ffufFacts reads one ffuf result. A hit asked with GET is the URL's
// answer, as azhaq-http records one; asked with another method (-X), it
// says the route takes that method.
func ffufFacts(r map[string]any, method string) []Fact {
	u, err := normalize.URL(text(r["url"]))
	if err != nil {
		return nil
	}
	if method = strings.ToUpper(method); method != "" && method != "GET" {
		row := map[string]any{"url": u, "via": "ffuf", "methods": []string{method}, "ops": []any{map[string]any{"method": method}}}
		return []Fact{observation(urlSeed(u), "ffuf", "url", row)}
	}
	payload := map[string]any{"url": u, "via": "ffuf"}
	for _, k := range []string{"status", "length", "words", "lines"} {
		if v, ok := r[k].(float64); ok {
			payload[k] = int(v)
		}
	}
	if ct := text(r["content-type"]); ct != "" {
		payload["content_type"] = ct
	}
	if loc := text(r["redirectlocation"]); loc != "" {
		payload["location"] = loc
	}
	if ns, ok := r["duration"].(float64); ok {
		payload["ms"] = int64(ns) / int64(time.Millisecond)
	}
	kind := "url"
	if st, _ := payload["status"].(int); st > 0 {
		kind = "application"
	}
	return []Fact{observation(urlSeed(u), "ffuf", kind, payload)}
}

// urlFacts records a URL a tool listed: an observation on the URL.
func urlFacts(u, collector string, payload map[string]any) []Fact {
	if _, err := normalize.URL(u); err != nil {
		return nil
	}
	return []Fact{observation(urlSeed(u), collector, "url", payload)}
}

// header is a header of katana's request or response, whatever case it
// wrote the name in (content-type, Content-Type; content_type before 1.0).
func header(m map[string]any, name string) string {
	h, _ := m["headers"].(map[string]any)
	for k, v := range h {
		if strings.EqualFold(strings.ReplaceAll(k, "_", "-"), name) {
			return text(v)
		}
	}
	return ""
}

// bodyFields are the field names a request body sends: a JSON object's
// keys, or a form's names (urlencoded or multipart, as katana fills one).
func bodyFields(body, contentType string) ([]string, string) {
	media, params, _ := mime.ParseMediaType(contentType)
	var obj map[string]any
	switch {
	case strings.TrimSpace(body) == "":
	case json.Unmarshal([]byte(body), &obj) == nil:
		if media == "" {
			media = "application/json"
		}
		return slices.Sorted(maps.Keys(obj)), media
	case media == "multipart/form-data" && params["boundary"] != "":
		var names []string
		r := multipart.NewReader(strings.NewReader(body), params["boundary"])
		for {
			p, err := r.NextPart()
			if err != nil {
				break
			}
			if n := p.FormName(); n != "" && !slices.Contains(names, n) {
				names = append(names, n)
			}
		}
		slices.Sort(names)
		return names, media
	case (media == "" || media == "application/x-www-form-urlencoded") && strings.Contains(body, "="):
		if q, err := url.ParseQuery(strings.TrimSpace(body)); err == nil {
			return slices.Sorted(maps.Keys(q)), "application/x-www-form-urlencoded"
		}
	}
	return nil, ""
}

func queryNames(u string) []string {
	p, err := url.Parse(u)
	if err != nil || p.RawQuery == "" {
		return nil
	}
	return slices.Sorted(maps.Keys(p.Query()))
}

// resolve makes a form's action absolute against the page it is on.
func resolve(page, ref string) (string, bool) {
	base, err := url.Parse(page)
	if err != nil {
		return "", false
	}
	r, err := url.Parse(strings.TrimSpace(ref))
	if err != nil {
		return "", false
	}
	u, err := normalize.URL(base.ResolveReference(r).String())
	return u, err == nil && (strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://"))
}

func text(v any) string {
	s, _ := v.(string)
	return s
}

func ints(v any) []int {
	xs, _ := v.([]any)
	var out []int
	for _, x := range xs {
		if n, ok := x.(float64); ok {
			out = append(out, int(n))
		}
	}
	return out
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
