package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// probeRow compares Azhaq's probing with httpx on the same host list:
// live names of the benchmark domains, ginandjuice.shop and the local apps.
type probeRow struct {
	Hosts         int      `json:"hosts"`
	AzhaqAnswered int      `json:"azhaq_answered"`
	HttpxAnswered int      `json:"httpx_answered"`
	Shared        int      `json:"shared"`
	Status        int      `json:"status_agree"`
	Title         int      `json:"title_agree"`
	Tech          int      `json:"tech_agree"`
	All           int      `json:"all_agree"`
	FaviconBoth   int      `json:"favicon_both"`
	FaviconAgree  int      `json:"favicon_agree"`
	CDNHttpx      int      `json:"cdn_httpx"`
	CDNAgree      int      `json:"cdn_agree"`
	AzhaqSeconds  float64  `json:"azhaq_seconds"`
	HttpxSeconds  float64  `json:"httpx_seconds"`
	Disagree      []string `json:"disagree,omitempty"`
}

// probeDomains may receive GET requests from the bench: public bug bounty
// programs and Acunetix's test zone. Live names of any other benchmark
// domain are left out of the probe list.
var probeDomains = []string{"hackerone.com", "tesla.com", "vulnweb.com"}

// liveHosts collects the names dnsx resolved in the domain benchmark.
var liveHosts []string

// Both tools get the same concurrency and User-Agent. With its default
// random browser User-Agent, httpx got Akamai's "Access Denied" page on
// about 85 tesla.com hosts that served Azhaq the real page; the same
// header for both keeps the comparison about parsing, not bot rules.
const (
	probeConcurrency = "16"
	probeAgent       = "azhaq-bench/1 (+https://github.com/trannghiach/azhaq)"
)

type probeResult struct {
	scheme, status, title, favicon, cdn string
	tech                                []string
}

func benchProbe(local []string) *probeRow {
	dir, _ := filepath.Abs(filepath.Join(work, "probe"))
	must(os.MkdirAll(dir, 0o755))
	hosts := map[string]bool{"ginandjuice.shop": true}
	for _, h := range local {
		hosts[h] = true
	}
	for _, h := range liveHosts {
		for _, d := range probeDomains {
			if inDomain(h, d) {
				hosts[h] = true
			}
		}
	}
	list := filepath.Join(dir, "hosts.txt")
	must(os.WriteFile(list, []byte(strings.Join(sortedKeys(hosts), "\n")+"\n"), 0o644))
	row := &probeRow{Hosts: len(hosts)}
	logf("probing %d hosts", len(hosts))

	db := filepath.Join(dir, "probe-"+time.Now().Format("150405")+".db")
	_, m := run("probe", 20*time.Minute, dir, azhaq, "run", "-list", list, "-probe", "-parallel", probeConcurrency,
		"-header", "User-Agent: "+probeAgent, "-db", db, "-json")
	row.AzhaqSeconds = m.Seconds
	az := azhaqProbes(db, hosts)

	out, hm := run("probe", 20*time.Minute, dir, ref("httpx"), "-l", list, "-silent", "-json", "-fr", "-td", "-cdn", "-favicon",
		"-title", "-sc", "-t", probeConcurrency, "-rl", "50", "-timeout", "10", "-H", "User-Agent: "+probeAgent, "-no-color")
	row.HttpxSeconds = hm.Seconds
	hx := httpxProbes(out, hosts)

	row.AzhaqAnswered, row.HttpxAnswered = len(az), len(hx)
	for _, h := range sortedKeys(hostKeys(hx)) {
		x := hx[h]
		a, ok := az[h]
		if !ok {
			row.note("%s: httpx %s %s, azhaq no answer", h, x.scheme, x.status)
			continue
		}
		row.Shared++
		st, ti, te := a.status == x.status, a.title == x.title, strings.Join(a.tech, ",") == strings.Join(x.tech, ",")
		if st {
			row.Status++
		}
		if ti {
			row.Title++
		}
		if te {
			row.Tech++
		}
		if st && ti && te {
			row.All++
		} else {
			row.note("%s: status %s/%s title %q/%q tech %v/%v", h, a.status, x.status, a.title, x.title, a.tech, x.tech)
		}
		if a.favicon != "" && x.favicon != "" {
			row.FaviconBoth++
			if a.favicon == x.favicon {
				row.FaviconAgree++
			}
		}
		if x.cdn != "" {
			row.CDNHttpx++
			if a.cdn == x.cdn {
				row.CDNAgree++
			}
		}
	}
	addCheck("probe: answers ≥ 95% of the hosts httpx answers", row.HttpxAnswered > 0 && float64(row.Shared) >= 0.95*float64(row.HttpxAnswered),
		"azhaq %d, httpx %d, shared %d of %d hosts", row.AzhaqAnswered, row.HttpxAnswered, row.Shared, row.Hosts)
	addCheck("probe: status, title and tech agree with httpx on ≥ 95% of shared hosts", row.Shared > 0 && float64(row.All) >= 0.95*float64(row.Shared),
		"all three %d/%d (status %d, title %d, tech %d)", row.All, row.Shared, row.Status, row.Title, row.Tech)
	addCheck("probe: within 2× httpx's time", row.AzhaqSeconds <= 2*row.HttpxSeconds+1,
		"azhaq %.1fs, httpx %.1fs, %s requests in flight each", row.AzhaqSeconds, row.HttpxSeconds, probeConcurrency)
	return row
}

func (r *probeRow) note(format string, a ...any) {
	if len(r.Disagree) < 25 {
		r.Disagree = append(r.Disagree, fmt.Sprintf(format, a...))
	}
}

// azhaqProbes reads the front page of each listed host from a probe run,
// preferring HTTPS as both tools try it first.
func azhaqProbes(db string, hosts map[string]bool) map[string]probeResult {
	exp, _ := runOut(azhaq, "export", "-db", db)
	g := readExport(exp)
	cdn := map[string]string{}
	for _, p := range g.payloads("azhaq-dns") {
		if name, _ := p["cdn"].(string); name != "" {
			cdn[str(p["fqdn"])] = name
		}
	}
	out := map[string]probeResult{}
	for _, p := range g.payloads("azhaq-http") {
		u, err := url.Parse(str(p["url"]))
		if err != nil || !hosts[u.Host] || (u.Path != "/" && u.Path != "") {
			continue
		}
		if prev, ok := out[u.Host]; ok && prev.scheme == "https" {
			continue
		}
		status := p["final_status"]
		if status == nil {
			status = p["status"]
		}
		var tech []string
		if xs, ok := p["tech"].([]any); ok {
			for _, x := range xs {
				tech = append(tech, str(x))
			}
		}
		sort.Strings(tech)
		out[u.Host] = probeResult{
			scheme: u.Scheme, status: str(status), title: squash(str(p["title"])),
			favicon: str(p["favicon"]), cdn: cdn[u.Hostname()], tech: tech,
		}
	}
	return out
}

func httpxProbes(out []byte, hosts map[string]bool) map[string]probeResult {
	res := map[string]probeResult{}
	for _, l := range lines(out) {
		var x struct {
			URL     string   `json:"url"`
			Status  int      `json:"status_code"`
			Title   string   `json:"title"`
			Tech    []string `json:"tech"`
			Favicon string   `json:"favicon"`
			CDNName string   `json:"cdn_name"`
		}
		if json.Unmarshal([]byte(l), &x) != nil {
			continue
		}
		u, err := url.Parse(x.URL)
		if err != nil || !hosts[u.Host] {
			continue
		}
		sort.Strings(x.Tech)
		res[u.Host] = probeResult{
			scheme: u.Scheme, status: fmt.Sprint(x.Status), title: squash(x.Title),
			favicon: x.Favicon, cdn: x.CDNName, tech: x.Tech,
		}
	}
	return res
}

func hostKeys(m map[string]probeResult) map[string]bool {
	out := map[string]bool{}
	for k := range m {
		out[k] = true
	}
	return out
}

func str(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case float64:
		return fmt.Sprint(int64(x))
	default:
		return fmt.Sprint(x)
	}
}

func squash(s string) string { return strings.Join(strings.Fields(s), " ") }
