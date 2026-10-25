// Package scopefile reads a bug bounty program's scope into allow and deny
// rules and the targets to start from. It understands HackerOne's scope
// CSV export, the program lists of bounty-targets-data (HackerOne,
// Bugcrowd, Intigriti, YesWeHack), a Burp project options file, and plain
// lines ("!host" or "-host" excludes).
package scopefile

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Scope is what a run takes from a program's scope.
type Scope struct {
	Program string   `json:"program,omitempty"`
	Allow   []string `json:"allow"`   // scope.Rules entries
	Deny    []string `json:"deny"`    // scope.Rules entries
	Domains []string `json:"domains"` // wildcards: enumerate their subdomains
	Targets []string `json:"targets"` // hosts, URLs and addresses to probe as given
	Skipped []string `json:"skipped,omitempty"`
}

// Platforms are the bounty-targets-data lists, refreshed there every 30 minutes.
var Platforms = map[string]string{
	"hackerone": "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/hackerone_data.json",
	"bugcrowd":  "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/bugcrowd_data.json",
	"intigriti": "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/intigriti_data.json",
	"yeswehack": "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/yeswehack_data.json",
}

// Fetch downloads a platform's program list.
func Fetch(ctx context.Context, platform string) ([]byte, error) {
	u, ok := Platforms[strings.ToLower(platform)]
	if !ok {
		return nil, fmt.Errorf("unknown platform %q (hackerone, bugcrowd, intigriti, yeswehack)", platform)
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", u, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 128<<20))
}

// Parse reads data in any supported format. program picks one program from
// a list (its handle, name or URL); a single program needs none.
func Parse(data []byte, program string) (Scope, error) {
	trimmed := bytes.TrimSpace(data)
	var b builder
	switch {
	case len(trimmed) > 0 && trimmed[0] == '[':
		if err := b.programs(trimmed, program); err != nil {
			return Scope{}, err
		}
	case len(trimmed) > 0 && trimmed[0] == '{':
		if err := b.burp(trimmed); err != nil {
			return Scope{}, err
		}
	case looksCSV(trimmed):
		if err := b.hackeroneCSV(trimmed); err != nil {
			return Scope{}, err
		}
	default:
		for _, line := range strings.Split(string(trimmed), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if strings.HasPrefix(line, "!") || strings.HasPrefix(line, "-") {
				b.add(strings.TrimSpace(line[1:]), "", false)
			} else {
				b.add(line, "", true)
			}
		}
	}
	s := b.scope()
	if len(s.Allow) == 0 {
		return s, fmt.Errorf("no in-scope web targets found")
	}
	return s, nil
}

func looksCSV(data []byte) bool {
	first := strings.ToLower(strings.SplitN(string(data), "\n", 2)[0])
	return strings.Contains(first, "identifier") && strings.Contains(first, ",")
}

type builder struct {
	program                       string
	allow, deny, domains, targets map[string]bool
	skipped                       []string
}

func (b *builder) init() {
	if b.allow == nil {
		b.allow, b.deny, b.domains, b.targets = map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	}
}

var (
	webTypes   = regexp.MustCompile(`(?i)^(url|wildcard|domain|ip_address|cidr|website|api|web-application|web_application|iprange|ip-address|ip_range|other_web|)$`)
	tldWild    = regexp.MustCompile(`\*\s*$|\.\*($|\.)`)
	hostLike   = regexp.MustCompile(`^(\*\.)?[a-z0-9_-]+(\.[a-z0-9_-]+)+$`)
	leadingAny = regexp.MustCompile(`^(\*|%)\.?`)
)

// add records one identifier of the given platform type.
func (b *builder) add(raw, kind string, in bool) {
	b.init()
	if !webTypes.MatchString(strings.TrimSpace(kind)) {
		b.skipped = append(b.skipped, raw+" ("+kind+")")
		return
	}
	for _, id := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' }) {
		b.one(strings.TrimSpace(id), in)
	}
}

func (b *builder) one(id string, in bool) {
	if id == "" {
		return
	}
	lower := strings.ToLower(id)
	if _, n, err := net.ParseCIDR(lower); err == nil {
		b.rule(n.String(), in)
		return
	}
	if ip := net.ParseIP(lower); ip != nil {
		b.rule(ip.String(), in)
		if in {
			b.targets[ip.String()] = true
		}
		return
	}
	target := lower
	if strings.Contains(lower, "://") {
		u, err := url.Parse(lower)
		if err != nil || u.Hostname() == "" {
			b.skipped = append(b.skipped, id)
			return
		}
		target = lower
		lower = u.Hostname()
	} else if i := strings.IndexAny(lower, "/:"); i > 0 {
		lower = lower[:i]
	}
	if strings.Count(lower, "*") > 1 || tldWild.MatchString(lower) || (strings.Contains(lower, "*") && !strings.HasPrefix(lower, "*.")) {
		b.skipped = append(b.skipped, id+" (wildcard outside the leftmost label)")
		return
	}
	if !hostLike.MatchString(lower) {
		b.skipped = append(b.skipped, id)
		return
	}
	if strings.HasPrefix(lower, "*.") {
		domain := leadingAny.ReplaceAllString(lower, "")
		b.rule("*."+domain, in)
		if in {
			b.domains[domain] = true
		}
		return
	}
	b.rule("="+lower, in)
	if in {
		if !strings.Contains(target, "://") && strings.Contains(target, "/") {
			target = "https://" + target
		}
		b.targets[target] = true
	}
}

func (b *builder) rule(r string, in bool) {
	if in {
		b.allow[r] = true
	} else {
		b.deny[r] = true
	}
}

func (b *builder) scope() Scope {
	b.init()
	keys := func(m map[string]bool) []string {
		out := make([]string, 0, len(m))
		for k := range m {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}
	return Scope{Program: b.program, Allow: keys(b.allow), Deny: keys(b.deny), Domains: keys(b.domains), Targets: keys(b.targets), Skipped: b.skipped}
}

// target is one scope entry in any of the platforms' shapes.
type target struct {
	AssetIdentifier       string `json:"asset_identifier"` // HackerOne
	AssetType             string `json:"asset_type"`
	EligibleForSubmission *bool  `json:"eligible_for_submission"`
	Target                string `json:"target"`   // Bugcrowd, YesWeHack
	Endpoint              string `json:"endpoint"` // Intigriti
	Type                  string `json:"type"`
}

func (t target) id() (string, string) {
	switch {
	case t.AssetIdentifier != "":
		return t.AssetIdentifier, t.AssetType
	case t.Target != "":
		return t.Target, t.Type
	default:
		return t.Endpoint, t.Type
	}
}

type program struct {
	Handle        string `json:"handle"`
	CompanyHandle string `json:"company_handle"`
	Name          string `json:"name"`
	URL           string `json:"url"`
	Targets       struct {
		InScope    []target `json:"in_scope"`
		OutOfScope []target `json:"out_of_scope"`
	} `json:"targets"`
}

func (b *builder) programs(data []byte, name string) error {
	var list []program
	if err := json.Unmarshal(data, &list); err != nil {
		return err
	}
	var pick *program
	want := strings.ToLower(strings.TrimSpace(name))
	for i, p := range list {
		if len(list) == 1 || (want != "" && (strings.ToLower(p.Handle) == want || strings.ToLower(p.Name) == want ||
			strings.TrimSuffix(strings.ToLower(p.URL), "/") == strings.TrimSuffix(want, "/") ||
			strings.HasSuffix(strings.TrimSuffix(strings.ToLower(p.URL), "/"), "/"+want))) {
			pick = &list[i]
			break
		}
	}
	if pick == nil {
		if want == "" {
			return fmt.Errorf("the list holds %d programs: name one with -program", len(list))
		}
		return fmt.Errorf("no program %q in the list", name)
	}
	b.program = pick.Name
	for _, t := range pick.Targets.InScope {
		id, kind := t.id()
		b.add(id, kind, t.EligibleForSubmission == nil || *t.EligibleForSubmission)
	}
	for _, t := range pick.Targets.OutOfScope {
		id, kind := t.id()
		b.add(id, kind, false)
	}
	return nil
}

// burp reads a Burp project options file's target scope.
func (b *builder) burp(data []byte) error {
	var f struct {
		Target struct {
			Scope struct {
				Include []struct {
					Enabled bool   `json:"enabled"`
					Host    string `json:"host"`
					Prefix  string `json:"prefix"`
				} `json:"include"`
				Exclude []struct {
					Enabled bool   `json:"enabled"`
					Host    string `json:"host"`
					Prefix  string `json:"prefix"`
				} `json:"exclude"`
			} `json:"scope"`
		} `json:"target"`
	}
	if err := json.Unmarshal(data, &f); err != nil {
		return err
	}
	for _, e := range f.Target.Scope.Include {
		if e.Enabled {
			b.add(burpHost(e.Host, e.Prefix), "", true)
		}
	}
	for _, e := range f.Target.Scope.Exclude {
		if e.Enabled {
			b.add(burpHost(e.Host, e.Prefix), "", false)
		}
	}
	return nil
}

// burpHost turns Burp's host regex back into a name: ^api\.example\.com$
// is api.example.com, ^.*\.example\.com$ is *.example.com.
func burpHost(host, prefix string) string {
	if prefix != "" {
		return prefix
	}
	h := strings.TrimSuffix(strings.TrimPrefix(host, "^"), "$")
	for _, wild := range []string{`.*\.`, `(.*\.)?`, `([^.]+\.)*`, `.+\.`} {
		if strings.HasPrefix(h, wild) {
			h = "*." + strings.TrimPrefix(h, wild)
		}
	}
	return strings.ReplaceAll(h, `\.`, ".")
}

// hackeroneCSV reads the CSV a program's scope page exports.
func (b *builder) hackeroneCSV(data []byte) error {
	r := csv.NewReader(bytes.NewReader(data))
	r.FieldsPerRecord = -1
	rows, err := r.ReadAll()
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return nil
	}
	col := map[string]int{}
	for i, h := range rows[0] {
		col[strings.ToLower(strings.TrimSpace(h))] = i
	}
	idCol, ok := col["identifier"]
	if !ok {
		return fmt.Errorf("no identifier column")
	}
	get := func(row []string, name string) string {
		if i, ok := col[name]; ok && i < len(row) {
			return strings.TrimSpace(row[i])
		}
		return ""
	}
	for _, row := range rows[1:] {
		if idCol >= len(row) {
			continue
		}
		in := !strings.EqualFold(get(row, "eligible_for_submission"), "false")
		b.add(row[idCol], get(row, "asset_type"), in)
	}
	return nil
}
