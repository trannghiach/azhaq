package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/trannghiach/azhaq/internal/normalize"
)

// probeRow compares Azhaq's probing with httpx on the same host list: the
// local apps, a fleet of servers the bench starts, and three public test
// sites at 5 requests per second.
type probeRow struct {
	Profile       string   `json:"profile,omitempty"`
	Hosts         int      `json:"hosts"`
	AzhaqAnswered int      `json:"azhaq_answered"`
	HttpxAnswered int      `json:"httpx_answered"`
	AzhaqOK       int      `json:"azhaq_confirmed"` // answers an independent GET agrees with
	HttpxOK       int      `json:"httpx_confirmed"`
	Shared        int      `json:"shared"`
	Offsite       int      `json:"offsite"` // httpx -fr left the host's site: only the redirect's status compared
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
	PublicAzhaq   int      `json:"public_azhaq"`
	PublicHttpx   int      `json:"public_httpx"`
	PublicAzSecs  float64  `json:"public_azhaq_seconds"`
	PublicHxSecs  float64  `json:"public_httpx_seconds"`
	Disagree      []string `json:"disagree,omitempty"`
	Accounting    string   `json:"accounting,omitempty"`
}

// publicSites may receive GET requests from the bench at 5 per second.
var publicSites = []string{"ginandjuice.shop", "testphp.vulnweb.com", "demo.testfire.net"}

// The same User-Agent for both tools: with its default random browser one,
// httpx got Akamai's "Access Denied" page where azhaq got the real page,
// which makes the comparison about bot rules, not parsing.
const probeAgent = "azhaq-bench/1 (+https://github.com/trannghiach/azhaq)"

type probeResult struct {
	scheme, status, title, favicon, cdn string
	tech                                []string
	// offsite: httpx -fr followed a redirect out of the host's site (a CDN,
	// an identity provider). Azhaq records such a redirect and does not
	// report the third party's page as the host's, so only the redirect's
	// own status is compared.
	offsite     bool
	firstStatus string
}

// fleet starts n local web servers of different kinds and returns their
// host:port; every server keeps the bench's own log of what it served.
func fleet(n int) (hosts []string, stop func()) {
	var srvs []*http.Server
	for i := 0; i < n; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		must(err)
		i := i
		srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Path == "/favicon.ico":
				w.Header().Set("Content-Type", "image/x-icon")
				w.Write([]byte{0, 0, 1, 0, 1, 0, byte(i), 0})
			case i%10 == 1 && r.URL.Path == "/": // redirects to a page of the same host
				http.Redirect(w, r, "/landing", http.StatusMovedPermanently)
			case i%10 == 2: // no front page
				http.NotFound(w, r)
			case i%10 == 3: // slow
				time.Sleep(600 * time.Millisecond)
				fmt.Fprintf(w, "<title>Fleet %d</title>slow", i)
			default:
				if i%10 == 4 {
					w.Header().Set("X-Powered-By", "Express")
				}
				fmt.Fprintf(w, "<html><title>Fleet %d %s</title><body>host %d</body></html>", i, r.URL.Path, i)
			}
		})}
		go srv.Serve(ln)
		srvs = append(srvs, srv)
		hosts = append(hosts, ln.Addr().String())
	}
	return hosts, func() {
		for _, s := range srvs {
			_ = s.Close()
		}
	}
}

// confirmHTTP asks the host itself: a GET of the front page, redirects
// followed or not, gives the status the tool reported.
func confirmHTTP(host, scheme, status string) bool {
	if scheme == "" {
		scheme = "http"
	}
	for _, follow := range []bool{false, true} {
		cli := &http.Client{Timeout: 15 * time.Second}
		if !follow {
			cli.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		}
		resp, err := cli.Get(scheme + "://" + host + "/")
		if err != nil {
			continue
		}
		resp.Body.Close()
		if fmt.Sprint(resp.StatusCode) == status {
			return true
		}
	}
	return false
}

func benchProbe(local []string) *probeRow {
	dir, _ := filepath.Abs(filepath.Join(work, "probe"))
	must(os.MkdirAll(dir, 0o755))
	fl, stop := fleet(100)
	defer stop()
	hosts := map[string]bool{}
	for _, h := range append(append([]string{"127.0.0.1:5013", "127.0.0.1:5020", "127.0.0.1:5030", "127.0.0.1:18825", "127.0.0.1:19200"}, local...), fl...) {
		hosts[h] = true
	}
	list := filepath.Join(dir, "hosts.txt")
	must(os.WriteFile(list, []byte(strings.Join(sortedKeys(hosts), "\n")+"\n"), 0o644))
	pub := filepath.Join(dir, "public.txt")
	must(os.WriteFile(pub, []byte(strings.Join(publicSites, "\n")+"\n"), 0o644))
	row := &probeRow{Profile: prof, Hosts: len(hosts)}
	logf("probing %d hosts", len(hosts))

	// httpx follows redirects with -fr; azhaq probe is asked to as well when it
	// has the flag (its older default is to follow).
	azFollow := []string(nil)
	if helpHas("probe", "-fr") {
		azFollow = []string{"-fr"}
	}
	azFlags := append([]string{"-json", "-silent", "-favicon"}, azFollow...)
	hxFlags := []string{"-silent", "-json", "-fr", "-td", "-cdn", "-favicon", "-title", "-sc", "-no-color"}
	if polite() {
		azFlags = append(azFlags, "-rate", politeHTTP)
		hxFlags = append(hxFlags, "-rl", politeHTTP)
	}
	aa := append([]string{"probe", "-l", list}, azFlags...)
	ha := append([]string{"-l", list}, hxFlags...)
	out, m := timed("probe", 20*time.Minute, dir, azhaq, aa...)
	row.AzhaqSeconds = m.Seconds
	az := httpxProbes(out, hosts)
	out, hm := timed("probe", 20*time.Minute, dir, ref("httpx"), ha...)
	row.HttpxSeconds = hm.Seconds
	hx := httpxProbes(out, hosts)

	row.AzhaqAnswered, row.HttpxAnswered = len(az), len(hx)
	for h, r := range az {
		if confirmHTTP(h, r.scheme, r.status) || (r.offsite && confirmHTTP(h, r.scheme, r.firstStatus)) {
			row.AzhaqOK++
		}
	}
	for h, r := range hx {
		if confirmHTTP(h, r.scheme, r.status) || (r.offsite && confirmHTTP(h, r.scheme, r.firstStatus)) {
			row.HttpxOK++
		}
	}
	for _, h := range sortedKeys(hostKeys(hx)) {
		x := hx[h]
		a, ok := az[h]
		if !ok {
			row.note("%s: httpx %s %s, azhaq no answer", h, x.scheme, x.status)
			continue
		}
		row.Shared++
		st, ti, te := a.status == x.status, a.title == x.title, strings.Join(a.tech, ",") == strings.Join(x.tech, ",")
		if x.offsite {
			st, ti, te = a.status == x.firstStatus, true, true
			row.Offsite++
		}
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
	cmds := cmdLine(azhaq, aa...) + " vs " + cmdLine("httpx", ha...)
	barOne("probe", row.AzhaqOK, row.HttpxOK, row.AzhaqSeconds, row.HttpxSeconds, "a GET to the host itself giving the status the tool reported", cmds,
		fmt.Sprintf("%s; %d hosts (5 apps, the services lab's web ports, %d local servers); answered azhaq %d, httpx %d, shared %d; %s%s", share(row.Shared, row.HttpxAnswered),
			row.Hosts, len(fl), row.AzhaqAnswered, row.HttpxAnswered, row.Shared, ratio(row.AzhaqSeconds, row.HttpxSeconds), azErr(m)))
	addCheck("probe: status, title and tech agree with httpx on ≥ 95% of shared hosts", row.Shared > 0 && float64(row.All) >= 0.95*float64(row.Shared),
		"all three %d/%d (status %d, title %d, tech %d; %d redirects out of the site compared by their own status)", row.All, row.Shared, row.Status, row.Title, row.Tech, row.Offsite)

	// Three public test sites, always at 5 requests per second.
	pa := []string{"probe", "-l", pub, "-json", "-silent", "-rate", politeHTTP, "-header", "User-Agent: " + probeAgent}
	if !helpHas("probe", "-header") {
		pa = []string{"probe", "-l", pub, "-json", "-silent", "-rate", politeHTTP, "-H", "User-Agent: " + probeAgent}
	}
	pa = append(pa, azFollow...)
	ph := []string{"-l", pub, "-silent", "-json", "-fr", "-title", "-sc", "-rl", politeHTTP, "-t", "1", "-H", "User-Agent: " + probeAgent, "-no-color"}
	pset := map[string]bool{}
	for _, p := range publicSites {
		pset[p] = true
	}
	out, pm := run("public", 10*time.Minute, dir, azhaq, pa...)
	row.PublicAzSecs = pm.Seconds
	pz := httpxProbes(out, pset)
	out, phm := run("public", 10*time.Minute, dir, ref("httpx"), ph...)
	row.PublicHxSecs = phm.Seconds
	px := httpxProbes(out, pset)
	row.PublicAzhaq, row.PublicHttpx = len(pz), len(px)
	pokA, pokH := 0, 0
	for h, r := range pz {
		if confirmHTTP(h, r.scheme, r.status) || r.offsite {
			pokA++
		}
	}
	for h, r := range px {
		if confirmHTTP(h, r.scheme, r.status) || r.offsite {
			pokH++
		}
	}
	barOne("probe public sites (5/s)", pokA, pokH, row.PublicAzSecs, row.PublicHxSecs, "a GET to the site giving the status the tool reported (a redirect out of the site counts)",
		cmdLine(azhaq, pa...)+" vs "+cmdLine("httpx", ph...), fmt.Sprintf("%v; one run each%s", publicSites, azErr(pm)))
	if !polite() {
		row.probeAccounting(dir, fl)
	}
	return row
}

func (r *probeRow) note(format string, a ...any) {
	if len(r.Disagree) < 25 {
		r.Disagree = append(r.Disagree, fmt.Sprintf(format, a...))
	}
}

// probeAccounting: every input of a probe run is a row, a failure or a
// skip, never nothing: rows + failed + skipped == the distinct inputs. The
// list holds a live host, a redirect to another input, a closed port, a
// port that does not speak HTTP, a name that does not resolve and a repeat.
func (r *probeRow) probeAccounting(dir string, fl []string) {
	red := httptest.NewServer(http.RedirectHandler("http://"+fl[0]+"/", http.StatusFound))
	defer red.Close()
	raw, _ := net.Listen("tcp", "127.0.0.1:0")
	go func() {
		for {
			c, err := raw.Accept()
			if err != nil {
				return
			}
			c.Write([]byte("\x00\x01binary"))
			c.Close()
		}
	}()
	defer raw.Close()
	closed := fmt.Sprintf("127.0.0.1:%d", freePorts(1)[0])
	inputs := []string{fl[0], strings.TrimPrefix(red.URL, "http://"), closed, raw.Addr().String(), "azhaq-bench-nx.invalid", fl[0], "http://" + fl[5] + "/landing"}
	f := filepath.Join(dir, "accounting.txt")
	must(os.WriteFile(f, []byte(strings.Join(inputs, "\n")+"\n"), 0o644))
	res := azExec(dir, 5*time.Minute, "probe", "-l", f, "-json")
	want := map[string]bool{}
	for _, in := range inputs {
		want[hostPortKey(in)] = true
	}
	handled := map[string]bool{}
	rows := 0
	for _, l := range lines([]byte(res.stdout)) {
		var o struct {
			Input string `json:"input"`
			URL   string `json:"url"`
		}
		if json.Unmarshal([]byte(l), &o) == nil && (o.Input != "" || o.URL != "") {
			rows++
			handled[hostPortKey(o.Input)] = true
		}
	}
	accounted := 0
	for _, l := range strings.Split(res.stderr, "\n") {
		var sum map[string]any
		if json.Unmarshal([]byte(strings.TrimSpace(l)), &sum) == nil && sum["type"] == "summary" {
			for _, k := range []string{"unreachable", "failed", "skipped"} {
				collectTargets(sum[k], func(t string) {
					if want[hostPortKey(t)] && !handled[hostPortKey(t)] {
						accounted++
					}
					handled[hostPortKey(t)] = true
				})
			}
		}
	}
	var missing []string
	for k := range want {
		if !handled[k] {
			missing = append(missing, k)
		}
	}
	sort.Strings(missing)
	r.Accounting = fmt.Sprintf("%d distinct inputs: %d rows, %d failed or skipped in the summary, unaccounted %v", len(want), rows, accounted, missing)
	addCheck("probe: every input is a row, a failure or a skip (rows + failed + skipped == inputs)", len(missing) == 0,
		"%s (exit %d; azhaq probe -l LIST -json; the list holds a live host, a redirect to another input, a closed port, a raw TCP port, a name that does not resolve, a repeat, a URL)", r.Accounting, res.exit)
}

// hostPortKey is host:port of an input that may be a URL or a bare name.
func hostPortKey(in string) string {
	if !strings.Contains(in, "://") {
		in = "http://" + in
	}
	u, err := url.Parse(in)
	if err != nil {
		return in
	}
	port := u.Port()
	if port == "" || port == "80" || port == "443" {
		return u.Hostname()
	}
	return u.Hostname() + ":" + port
}

// collectTargets calls f with every string under v that names a target: a
// string, a list of them, or objects with target(s).
func collectTargets(v any, f func(string)) {
	switch x := v.(type) {
	case string:
		f(x)
	case []any:
		for _, e := range x {
			collectTargets(e, f)
		}
	case map[string]any:
		for k, e := range x {
			if k == "targets" || k == "target" || k == "input" || k == "inputs" || k == "url" {
				collectTargets(e, f)
			}
		}
	}
}

func httpxProbes(out []byte, hosts map[string]bool) map[string]probeResult {
	res := map[string]probeResult{}
	for _, l := range lines(out) {
		var x struct {
			URL      string   `json:"url"`
			Status   int      `json:"status_code"`
			Title    string   `json:"title"`
			Tech     []string `json:"tech"`
			Favicon  string   `json:"favicon"`
			CDNName  string   `json:"cdn_name"`
			FinalURL string   `json:"final_url"`
			Chain    []int    `json:"chain_status_codes"`
		}
		if json.Unmarshal([]byte(l), &x) != nil {
			continue
		}
		u, err := url.Parse(x.URL)
		if err != nil || !hosts[u.Host] {
			continue
		}
		sort.Strings(x.Tech)
		r := probeResult{
			scheme: u.Scheme, status: fmt.Sprint(x.Status), title: squash(x.Title),
			favicon: x.Favicon, cdn: x.CDNName, tech: x.Tech,
		}
		if f, err := url.Parse(x.FinalURL); err == nil && f.Hostname() != "" && len(x.Chain) > 0 &&
			normalize.RegistrableDomain(f.Hostname()) != normalize.RegistrableDomain(u.Hostname()) {
			r.offsite, r.firstStatus = true, fmt.Sprint(x.Chain[0])
		}
		res[u.Host] = r
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
