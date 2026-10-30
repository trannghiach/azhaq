package main

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/trannghiach/azhaq/engine"
	"github.com/trannghiach/azhaq/internal/collectors/asncol"
	"github.com/trannghiach/azhaq/internal/collectors/httpcol"
	"github.com/trannghiach/azhaq/internal/normalize"
)

// probeTarget is one target as given, and the lines it became.
type probeTarget struct {
	given string
	lines []string
}

// probeInputs reads the targets of probe: -u (comma lists), -l (a file,
// stdin, or a glob) and stdin, and expands what httpx expands: wildcard and
// dotted names, address ranges, AS numbers, and an address with -p ports.
func probeInputs(urls []string, list string, pf *probeFlags, ports []httpcol.PortSpec, maxIPs int, rep *report) ([]probeTarget, map[string]httpcol.HostOpt, error) {
	var raw []string
	if strings.EqualFold(pf.im, "burp") {
		var err error
		if raw, err = burpURLs(urls, list); err != nil {
			return nil, nil, err
		}
		urls, list = nil, ""
	} else if pf.im != "" {
		return nil, nil, usagef("-im: want burp, got %q", pf.im)
	}
	for _, u := range urls {
		for _, p := range strings.Split(u, ",") {
			if p = strings.TrimSpace(p); p != "" {
				raw = append(raw, p)
			}
		}
	}
	switch {
	case list == "-":
		lines, err := readLines(os.Stdin)
		if err != nil {
			return nil, nil, err
		}
		raw = append(raw, lines...)
	case list != "":
		files := []string{list}
		if _, err := os.Stat(list); err != nil && strings.ContainsAny(list, "*?[") {
			if files, err = filepath.Glob(list); err != nil || len(files) == 0 {
				return nil, nil, usagef("-l %s: no file matches", list)
			}
		}
		for _, f := range files {
			lines, err := loadLines(f)
			if err != nil {
				return nil, nil, err
			}
			raw = append(raw, lines...)
		}
	case len(raw) == 0 && !pf.noStdin && stdinPiped():
		lines, err := readLines(os.Stdin)
		if err != nil {
			return nil, nil, err
		}
		raw = append(raw, lines...)
	}
	perHost := map[string]httpcol.HostOpt{}
	budget, cut := maxIPs, 0
	var out []probeTarget
	seen := map[string]bool{}
	add := func(t probeTarget) {
		if !seen[t.given] {
			seen[t.given] = true
			out = append(out, t)
		}
	}
	for _, t := range raw {
		switch {
		case strings.HasPrefix(t, "{"):
			// A line of nuclei's format pins a host to an address.
			var j struct {
				Target string `json:"target"`
				IP     string `json:"ip"`
			}
			if err := json.Unmarshal([]byte(t), &j); err != nil || j.Target == "" {
				return nil, nil, usagef("a target line that starts with { is JSON with a target and an ip: %q", t)
			}
			add(probeTarget{given: t, lines: []string{j.Target}})
			h := strings.ToLower(normalize.HostFromURL(j.Target))
			if h == "" {
				h = strings.ToLower(strings.Trim(strings.SplitN(j.Target, ":", 2)[0], "[]"))
			}
			if net.ParseIP(j.IP) == nil {
				return nil, nil, usagef("the ip of %q is not an address", t)
			}
			opt := perHost[h]
			opt.IP = j.IP
			perHost[h] = opt
			continue
		case pf.vi:
			// -vi: vhost,ip sends the request to the ip with the vhost as Host.
			vh, ip, ok := strings.Cut(t, ",")
			if !ok || net.ParseIP(strings.TrimSpace(ip)) == nil || strings.TrimSpace(vh) == "" {
				return nil, nil, usagef("-vi wants lines of vhost,ip, got %q", t)
			}
			ip, vh = strings.TrimSpace(ip), strings.TrimSpace(vh)
			add(probeTarget{given: t, lines: portLines(ip, ports)})
			opt := perHost[strings.ToLower(ip)]
			opt.VHosts = append(opt.VHosts, vh)
			perHost[strings.ToLower(ip)] = opt
			continue
		}
		t = strings.TrimPrefix(strings.TrimPrefix(t, "*."), ".") // *.example.com and .example.com are example.com
		switch {
		case strings.Contains(t, "://") || strings.ContainsAny(t, " ?#@"):
			add(probeTarget{given: t, lines: []string{t}})
		case strings.HasPrefix(strings.ToUpper(t), "AS") && isASN(t):
			asn, _ := asncol.NormalizeASN(t)
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			prefixes, _, err := asncol.NewASN(nil).Announced(ctx, asn)
			cancel()
			if err != nil {
				rep.Failed = append(rep.Failed, engine.Failure{Collector: "azhaq-asn", Error: err.Error(), Retryable: true, Count: 1, Targets: []string{t}})
				continue
			}
			for _, p := range prefixes {
				if pfx, err := netip.ParsePrefix(p); err == nil && pfx.Addr().Is4() {
					for _, ip := range expandPrefix(pfx, &budget, &cut) {
						add(probeTarget{given: ip, lines: portLines(ip, ports)})
					}
				}
			}
		case strings.Contains(t, "/"):
			pfx, err := netip.ParsePrefix(t)
			if err != nil {
				return nil, nil, usagef("%q is not an address range such as 192.0.2.0/24", t)
			}
			for _, ip := range expandPrefix(pfx.Masked(), &budget, &cut) {
				add(probeTarget{given: ip, lines: portLines(ip, ports)})
			}
		default:
			add(probeTarget{given: t, lines: portLines(t, ports)})
		}
	}
	if cut > 0 {
		rep.Notes = append(rep.Notes, fmt.Sprintf("%d addresses of the ranges were not probed: -max-ips %d", cut, maxIPs))
	}
	return out, perHost, nil
}

// burpURLs reads the URLs of the items of Burp XML exports: -l files, or
// stdin for -. Only the URL of an item is taken: a request is GET unless -x
// says otherwise.
func burpURLs(urls []string, list string) ([]string, error) {
	var files []string
	if list != "" {
		files = append(files, list)
	}
	files = append(files, urls...)
	if len(files) == 0 {
		return nil, usagef("-im burp reads the Burp XML file given with -l")
	}
	var out []string
	for _, f := range files {
		var data []byte
		var err error
		if f == "-" {
			data, err = io.ReadAll(os.Stdin)
		} else {
			data, err = os.ReadFile(f)
		}
		if err != nil {
			return nil, err
		}
		var doc struct {
			Items []struct {
				URL string `xml:"url"`
			} `xml:"item"`
		}
		if err := xml.Unmarshal(data, &doc); err != nil {
			return nil, usagef("-im burp: %s: %v", f, err)
		}
		for _, it := range doc.Items {
			if u := strings.TrimSpace(it.URL); u != "" {
				out = append(out, u)
			}
		}
	}
	return out, nil
}

func isASN(s string) bool {
	_, ok := asncol.NormalizeASN(s)
	return ok
}

// expandPrefix lists the addresses of a prefix that the budget allows;
// what it cannot take is counted in cut.
func expandPrefix(pfx netip.Prefix, budget, cut *int) []string {
	var out []string
	bits := 32 - pfx.Bits()
	if !pfx.Addr().Is4() {
		bits = 128 - pfx.Bits()
	}
	size := 1 << min(bits, 30)
	if bits > 30 {
		size = 1 << 30
	}
	take := min(size, max(*budget, 0))
	*budget -= take
	*cut += size - take
	a := pfx.Addr()
	for i := 0; i < take; i++ {
		out = append(out, a.String())
		a = a.Next()
	}
	return out
}

// portLines is the lines an address with no port of its own becomes under
// -p: one per port, led by the scheme when the port had one. A name stays
// as it is: the collector asks its ports once it resolves.
func portLines(t string, ports []httpcol.PortSpec) []string {
	ip := net.ParseIP(strings.Trim(t, "[]"))
	if len(ports) == 0 || ip == nil || strings.HasPrefix(t, "[") && strings.Contains(t, "]:") {
		return []string{t}
	}
	var out []string
	for _, p := range ports {
		hp := net.JoinHostPort(ip.String(), strconv.Itoa(p.Port))
		switch p.Scheme {
		case "http":
			out = append(out, "http://"+hp+"/")
		case "https":
			out = append(out, "https://"+hp+"/")
		default:
			out = append(out, hp)
		}
	}
	return out
}
