package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/trannghiach/azhaq/internal/collectors/asncol"
	"github.com/trannghiach/azhaq/internal/portscan"
	"github.com/trannghiach/azhaq/store"
	"github.com/trannghiach/azhaq/types"
)

// msDuration is a time given as a Go duration (1500ms, 2s) or as a bare
// number of milliseconds, as naabu takes its timeouts.
type msDuration time.Duration

func (d *msDuration) String() string { return time.Duration(*d).String() }

func (d *msDuration) Set(s string) error {
	if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
		*d = msDuration(time.Duration(n) * time.Millisecond)
		return nil
	}
	v, err := time.ParseDuration(strings.TrimSpace(s))
	if err != nil {
		return err
	}
	*d = msDuration(v)
	return nil
}

// timingTemplates is what -T0..-T5 sets, where the flag was not given: nmap's names,
// naabu's numbers. T3 is what a scan does without it.
var timingTemplates = map[int]struct {
	rate    float64
	timeout time.Duration
	retries int // more passes over the silent ports; -1 is the default policy
}{
	0: {10, 5 * time.Second, 0},
	1: {100, 4 * time.Second, 0},
	2: {400, 3 * time.Second, 1},
	3: {0, 0, -1},
	4: {10000, 700 * time.Millisecond, 1},
	5: {30000, 500 * time.Millisecond, 0},
}

var timingArg = regexp.MustCompile(`^--?T([0-5])$`)

// cmdPorts is naabu (connect scan): host:port per open port, as each host
// is scanned. The hosts given are the scope.
func cmdPorts(args []string) error {
	// nmap's -T4, and a bare number for -timeout, which is the run's limit.
	args = slices.Clone(args)
	for i, a := range args {
		if m := timingArg.FindStringSubmatch(a); m != nil {
			args[i] = "-T=" + m[1]
		}
		if a == "-timeout" || a == "--timeout" || strings.HasPrefix(a, "-timeout=") || strings.HasPrefix(a, "--timeout=") {
			v := strings.TrimPrefix(strings.TrimPrefix(a, "-"), "-")
			v = strings.TrimPrefix(v, "timeout")
			v = strings.TrimPrefix(v, "=")
			if v == "" && i+1 < len(args) {
				v = args[i+1]
			}
			if _, err := strconv.Atoi(v); err == nil {
				return usagef("-timeout is how long the run may take (90s, 5m); the wait for one connect is -connect-timeout (%s is %s ms there)", v, v)
			}
		}
	}
	fs := newFlags("ports")
	var c common
	c.register(fs)
	fs.BoolVar(&c.json, "j", false, "same as -json")
	var hosts stringsFlag
	fs.Var(&hosts, "host", "hosts, addresses, CIDR ranges, AS numbers or host:port, comma-separated and repeatable")
	list := fs.String("l", "", "file of targets (- for stdin)")
	noStdin := fs.Bool("no-stdin", false, "do not read targets from stdin when none is given")
	spec := fs.String("p", "top-100", "ports: top-100, top-1000, full, - (all), none, or a list of ports, ranges and these names, such as 22,80,8000-8100 or top-100,8888; u:53 is a UDP port")
	topPorts := fs.String("tp", "", "the most common TCP ports: 100, 1000 or full (added to -p)")
	portsFile := fs.String("pf", "", "file of ports, one spec a line (added to -p)")
	exclPorts := fs.String("ep", "", "ports not to scan: a list or a file")
	udp := fs.Bool("udp", false, "also ask the common UDP ports (25: dns, ntp, snmp, ssdp, mdns, ...)")
	udpSpec := fs.String("pu", "", "UDP ports to ask: top, full or a list of ports, ranges and these names, such as 53,123,1-1024 or top,5354 (implies -udp)")
	exclHosts := fs.String("eh", "", "hosts, addresses or ranges not to scan, comma-separated (same as -deny)")
	exclFile := fs.String("ef", "", "file of hosts, addresses and ranges not to scan")
	resolvers := fs.String("resolvers", "", "DNS resolvers: a list such as 1.1.1.1,8.8.8.8:53 or a file, one a line (default: public resolvers)")
	fs.StringVar(resolvers, "r", "", "same as -resolvers")
	ipv := fs.String("iv", "", "the address families of a name to scan: 4 or 6 (default both)")
	allIPs := fs.Bool("sa", false, "scan every address of a name, not the first two of each family")
	var connect msDuration
	fs.Var(&connect, "connect-timeout", "wait this long for one port to accept or refuse a connect: 1500, 1500ms or 2s (default 1.5s; -timeout is the run's limit)")
	retries := fs.Int("retries", -1, "more passes over the ports that neither accepted nor refused: n passes over all of them, 0 none (default: one, when few did not answer)")
	fs.IntVar(retries, "max-retries", -1, "same as -retries")
	workers := fs.Int("workers", 0, "connects in flight at once, over all hosts (default: as many as the rate allows, up to 20000)")
	fs.IntVar(workers, "c", 0, "same as -workers")
	minRate := fs.Float64("min-rate", 0, "connects per second at least: raises -rate to this when lower")
	tmpl := fs.Int("T", -1, "timing template, 0 (paranoid) to 5 (insane); sets -rate, -connect-timeout and -retries where they are not given; 3 is the default")
	order := fs.String("order", "random", "the order a host's ports are asked in: random (the likeliest ports first, each tier shuffled) or asc")
	seed := fs.Int64("seed", 0, "make the random port order repeat (default: a new one each run)")
	threshold := fs.Int("pts", 0, "stop asking a host after this many open ports: it answers every port (default: no limit)")
	unnamed := fs.Int("unnamed", 0, "after this many open ports of an address that no protocol probe could name, ask its other silent ports their banner only (0: 6, a guard against hosts that accept every connect; -1: no limit)")
	detect := fs.String("detect", "all", "what is asked of an open port: all (its banner, then HTTP and TLS, then one request of each protocol that waits to be asked, each on its own connection: at most 24 connects after the first), banner (what it says on the one connection) or none (connect and close, as naabu without -sV)")
	cdnFull := fs.Bool("cdn-full", false, "scan CDN and WAF addresses in full, not only ports 80, 443, 8080 and 8443")
	sn := fs.Bool("sn", false, "list the addresses that are up (a connect to 80 or 443 is accepted or refused) and scan nothing")
	wn := fs.Bool("wn", false, "scan only the addresses that are up (by -sn's test); the default scans every address")
	fs.Bool("Pn", false, "accepted: addresses are scanned without asking whether they are up, which is the default")
	fs.Bool("cdn", false, "accepted: a CDN address is marked in the output, always")
	source := fs.String("source-ip", "", "connect from this local address")
	payload := fs.String("cp", "", "send this to each open TCP port before reading what it says (\\r and \\n are CR and LF)")
	proxyFlag := fs.String("proxy", "", "connect to TCP ports through this SOCKS5 proxy (host:port); a port is then asked its banner only, and UDP is not sent")
	proxyAuth := fs.String("proxy-auth", "", "user:password for -proxy")
	fs.Bool("nc", false, "accepted: no colours are printed")
	oX := fs.String("oX", "", "write nmap XML to this file (- for stdout)")
	oG := fs.String("oG", "", "write nmap greppable output to this file (- for stdout)")
	oA := fs.String("oA", "", "write JSON lines, XML and greppable output to BASE.json, BASE.xml and BASE.gnmap")
	asCSV := fs.Bool("csv", false, "CSV output, a header line first")
	eof := fs.String("eof", "", "leave these fields out of -json, -csv and -oA's JSON, comma-separated")
	lof := fs.Bool("lof", false, "list the fields of -json and -csv, and stop")
	given := inherit(fs, "rate=port-rate", "max-requests", "dns-rate", "timeout", "v", "scope", "program", "allow", "deny", "ledger", "kill-file")
	if err := parse(fs, args); err != nil {
		return err
	}
	if *lof {
		fmt.Println(strings.Join(portFields, "\n"))
		return nil
	}
	visited := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { visited[f.Name] = true })

	tokens := append([]string(nil), hosts...)
	tokens = append(tokens, fs.Args()...)
	if *noStdin && *list == "" && len(tokens) == 0 {
		return usagef("give -host HOST, -l FILE or targets as arguments (-no-stdin is set)")
	}
	tokens, err := inputs(tokens, *list)
	if err != nil {
		return err
	}
	if len(tokens) == 0 {
		return usagef("give -host HOST, -l FILE or hosts on stdin")
	}
	tg, err := parseTargets(tokens)
	if err != nil {
		return err
	}
	rep := newReport("ports")
	rep.what = "open ports"
	for _, as := range tg.asns {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		prefixes, holder, err := asncol.NewASN(nil).Prefixes(ctx, as)
		cancel()
		if err != nil {
			return fmt.Errorf("%s: %w", as, err)
		}
		if len(prefixes) == 0 {
			rep.Notes = append(rep.Notes, as+" announces no prefix (RIPEstat)")
		}
		before := tg.addresses()
		for _, p := range prefixes {
			if _, err := tg.addPrefixString(p); err != nil {
				return err
			}
		}
		rep.Notes = append(rep.Notes, fmt.Sprintf("%s (%s): %d prefixes, %s addresses to scan (RIPEstat)", as, holder, len(prefixes), humanCount(tg.addresses()-before)))
	}

	// The ports: -p, -tp and -pf together, less -ep; a port on a target
	// stands for -p when none of them was given.
	var tcpSpec, udpPart []string
	own := visited["p"] || visited["tp"] || visited["pf"]
	add := func(s string) {
		for _, part := range strings.Split(s, ",") {
			part = strings.TrimSpace(part)
			if rest, ok := strings.CutPrefix(strings.ToLower(part), "u:"); ok {
				udpPart = append(udpPart, rest)
			} else if part != "" {
				tcpSpec = append(tcpSpec, part)
			}
		}
	}
	if visited["p"] || !(visited["tp"] || visited["pf"]) {
		add(*spec)
	}
	switch strings.ToLower(*topPorts) {
	case "":
	case "100", "1000":
		add("top-" + *topPorts)
	case "full":
		add("full")
	default:
		return usagef("-tp wants 100, 1000 or full, got %q", *topPorts)
	}
	if *portsFile != "" {
		lines, err := loadLines(*portsFile)
		if err != nil {
			return err
		}
		add(strings.Join(lines, ","))
	}
	ports, err := portscan.Ports(strings.Join(tcpSpec, ","))
	if err != nil {
		return usagef("-p: %v", err)
	}
	udps := strings.Join(udpPart, ",")
	if *udpSpec != "" {
		udps = strings.Trim(udps+","+*udpSpec, ",")
	} else if *udp && udps == "" {
		udps = "top"
	}
	var udpPorts []int
	if udps != "" {
		if udpPorts, err = portscan.UDPPorts(udps); err != nil {
			return usagef("-pu: %v", err)
		}
	}
	if *exclPorts != "" {
		ex := *exclPorts
		if _, err := os.Stat(ex); err == nil {
			lines, err := loadLines(ex)
			if err != nil {
				return err
			}
			ex = strings.Join(lines, ",")
		}
		if ports, err = portscan.Exclude(ports, ex); err != nil {
			return usagef("-ep: %v", err)
		}
		if udpPorts, err = portscan.Exclude(udpPorts, ex); err != nil {
			return usagef("-ep: %v", err)
		}
	}
	if len(ports) == 0 && len(udpPorts) == 0 && !*sn {
		return usagef("no ports to scan: -p, -tp and -pf with -ep left none")
	}

	lines, allow, err := tg.listLines()
	if err != nil {
		return err
	}
	path, rm, err := tempList(lines)
	if err != nil {
		return err
	}
	defer rm()

	tcp := "none"
	if len(ports) > 0 {
		tcp = portscan.Spec(ports)
	} else if len(udpPorts) == 0 || *sn {
		tcp = "top-100"
	}
	run := []string{"-list", path, "-max-items", "1000000000", "-passive", "-depth", "0", "-skip", skipAllBut("azhaq-ports"), "-ports", tcp}
	if len(udpPorts) > 0 {
		run = append(run, "-ports-udp", portscan.Spec(udpPorts))
	}
	if !own {
		hs := make([]string, 0, len(tg.ports))
		for h := range tg.ports {
			hs = append(hs, h)
		}
		sort.Strings(hs)
		for _, h := range hs {
			run = append(run, portsOnFlag(h, tg.ports[h])...)
		}
	}

	// Timing: a template under the flags given.
	rate, ct, retr := 0.0, time.Duration(connect), *retries
	if *tmpl >= 0 {
		t, ok := timingTemplates[*tmpl]
		if !ok {
			return usagef("-T wants 0 to 5, got %d", *tmpl)
		}
		if !visited["rate"] && t.rate > 0 {
			rate = t.rate
		}
		if !visited["connect-timeout"] {
			ct = t.timeout
		}
		if !visited["retries"] && !visited["max-retries"] {
			retr = t.retries
		}
	}
	if rate > 0 {
		run = append(run, "-port-rate", strconv.FormatFloat(rate, 'f', -1, 64))
	}
	if ct > 0 {
		run = append(run, "-port-timeout", ct.String())
	}
	if retr >= 0 {
		run = append(run, "-port-retries", strconv.Itoa(retr))
	}
	if *workers > 0 {
		run = append(run, "-port-workers", strconv.Itoa(*workers))
	}
	if *minRate > 0 {
		run = append(run, "-port-min-rate", strconv.FormatFloat(*minRate, 'f', -1, 64))
	}
	run = append(run, "-port-order", *order, "-port-detect", *detect)
	if *seed != 0 {
		run = append(run, "-port-seed", strconv.FormatInt(*seed, 10))
	}
	if *unnamed != 0 {
		run = append(run, "-port-unnamed", strconv.Itoa(*unnamed))
	}
	if *threshold > 0 {
		run = append(run, "-port-threshold", strconv.Itoa(*threshold))
	}
	if *cdnFull {
		run = append(run, "-port-cdn-full")
	}
	switch {
	case *sn:
		run = append(run, "-port-discover", "only")
	case *wn:
		run = append(run, "-port-discover", "first")
	}
	if *ipv != "" {
		run = append(run, "-port-ip", *ipv)
	}
	if *allIPs {
		run = append(run, "-port-all-ips")
	}
	if *source != "" {
		run = append(run, "-port-source-ip", *source)
	}
	if *proxyFlag != "" {
		if len(udpPorts) > 0 {
			return usagef("-proxy carries TCP only: leave out -udp and -pu")
		}
		run = append(run, "-port-proxy", *proxyFlag)
		if *proxyAuth != "" {
			run = append(run, "-port-proxy-auth", *proxyAuth)
		}
		if *detect == "all" {
			rep.Notes = append(rep.Notes, "-proxy: each port is asked its banner only (-detect banner): the service probes beyond the first connection do not go through a proxy")
		}
	}
	if *source != "" && *detect == "all" {
		rep.Notes = append(rep.Notes, "-source-ip: each port is asked its banner only (-detect banner): the service probes beyond the first connection connect from the system's address")
	}
	if *payload != "" {
		run = append(run, "-port-payload", *payload)
	}
	if *resolvers != "" {
		rf, rmr, err := resolverFile(*resolvers)
		if err != nil {
			return err
		}
		defer rmr()
		run = append(run, "-resolvers", rf)
	}
	exFile, err := exclusions(*exclFile)
	if err != nil {
		return err
	}
	for _, d := range append(strings.Split(*exclHosts, ","), exFile...) {
		if d = strings.TrimSpace(d); d != "" {
			run = append(run, "-deny", d)
		}
	}
	extra := given()
	if !hasFlag(extra, "allow", "scope") {
		// The hosts given are the scope.
		for _, a := range allow {
			run = append(run, "-allow", a)
		}
	}

	// Results.
	out := &portOut{exclude: map[string]bool{}, csv: *asCSV}
	for _, f := range strings.Split(*eof, ",") {
		if f = strings.TrimSpace(f); f != "" {
			out.exclude[f] = true
		}
	}
	if *oA != "" {
		out.xmlPath, out.gnmapOut, out.jsonPath = *oA+".xml", *oA+".gnmap", *oA+".json"
	}
	if *oX != "" {
		out.xmlPath = *oX
	}
	if *oG != "" {
		out.gnmapOut = *oG
	}
	out.keep = out.xmlPath != "" || out.gnmapOut != "" || out.jsonPath != ""
	out.quiet = out.xmlPath == "-" || out.gnmapOut == "-"
	w, err := newWriter(&c)
	if err != nil {
		return err
	}
	out.w = w
	sink := newPortsSink(out)
	start := time.Now()
	if *wn && *sn {
		return usagef("-sn lists the addresses that are up, -wn scans them: give one")
	}
	_, done, err := runPreset(&c, append(run, extra...), rep, sink.see)
	if err != nil {
		return err
	}
	defer done()
	if err := out.finish(args, start, time.Now()); err != nil {
		return err
	}
	if err := w.close(); err != nil {
		return err
	}
	sink.settle(rep, *sn)
	return rep.finish(c.json, c.silent)
}

// portsSink prints the rows of a ports run as its tasks report them, each
// port once, and keeps the counts its summary needs.
type portsSink struct {
	out        *portOut
	mu         sync.Mutex
	seen       map[string]bool
	scanned    float64 // addresses asked
	unresolved int
	silentUDP  bool // a row is open|filtered: the rows are not all open ports
}

func newPortsSink(out *portOut) *portsSink {
	return &portsSink{out: out, seen: map[string]bool{}}
}

func (k *portsSink) see(_ types.Entity, o types.Observation) { k.visit(o, true) }

// replay marks the ports an earlier run of the scan found as printed, so a
// resumed run prints only what it finds itself.
func (k *portsSink) replay(obs []types.StoredObservation) {
	for _, o := range obs {
		k.visit(o.Observation, false)
	}
}

// settle puts the sink's counts in the summary, after the rows are written.
func (k *portsSink) settle(rep *report, sn bool) {
	rep.Results = k.out.w.count()
	rep.Counts = map[string]int{"addresses": int(k.scanned)}
	if k.unresolved > 0 {
		rep.Counts["did not resolve"] = k.unresolved
	}
	if k.silentUDP {
		rep.what = "ports"
	}
	if sn {
		rep.what = "addresses up"
	}
}

// visit is see; with print false it only notes what the observation holds.
func (k *portsSink) visit(o types.Observation, print bool) {
	if o.Collector != "azhaq-ports" {
		return
	}
	out, w := k.out, k.out.w
	add := func(r portRow) {
		if print {
			out.add(r)
		}
	}
	p := payloadOf(o)
	host, _ := p["host"].(string)
	ip, _ := p["ip"].(string)
	cdn, _ := p["cdn"].(string)
	if print {
		k.mu.Lock()
		switch {
		case p["range"] == true:
			k.scanned += float64(intOf(p["addresses"]))
		case p["unresolved"] != nil:
			k.unresolved++
		case p["prefix"] == nil:
			k.scanned++
		}
		k.mu.Unlock()
	}
	if p["up"] == true && p["scanned"] == float64(0) && ip != "" {
		if once(&k.mu, k.seen, "up "+ip) {
			add(portRow{Host: host, IP: ip, State: "up", At: time.Now()})
		}
		return
	}
	services, _ := p["services"].([]any)
	for _, s := range services {
		svc, _ := s.(map[string]any)
		port := fmt.Sprint(svc["port"])
		key := host + ":" + port
		if w.json || out.csv || out.keep {
			key = ip + " " + key // a row per address, as naabu prints
		}
		if !once(&k.mu, k.seen, key) {
			continue
		}
		n, _ := strconv.Atoi(port)
		row := portRow{Host: host, IP: ip, Port: n, Proto: "tcp", State: "open", TLS: svc["tls"] == true, CDN: cdn, At: time.Now(), Fields: map[string]any{}}
		for _, f := range []string{"service", "product", "version", "title", "banner", "subject_cn", "subject_an"} {
			if v, ok := svc[f]; ok {
				row.Fields[f] = v
			}
		}
		add(row)
	}
	udpServices, _ := p["udp_services"].([]any)
	for _, s := range udpServices {
		svc, _ := s.(map[string]any)
		port := fmt.Sprint(svc["port"])
		if !once(&k.mu, k.seen, ip+" "+host+":"+port+"/udp") {
			continue
		}
		n, _ := strconv.Atoi(port)
		state, _ := svc["state"].(string)
		if state != "open" && print {
			k.mu.Lock()
			k.silentUDP = true
			k.mu.Unlock()
		}
		row := portRow{Host: host, IP: ip, Port: n, Proto: "udp", State: state, At: time.Now(), Fields: map[string]any{}}
		for _, f := range []string{"service", "product", "version", "banner"} {
			if v, ok := svc[f]; ok {
				row.Fields[f] = v
			}
		}
		add(row)
	}
}

// resumePorts continues a ports run a limit stopped, as azhaq resume does
// every run, and prints what ports prints: the open ports this run finds
// (-json for rows as objects, -quiet for the summary only), with the
// summary of a ports run. The ports the earlier runs found are in the
// workspace and are not printed again.
func resumePorts(db, id string, runArgs, rest []string) error {
	c := common{json: wantsJSON(rest), db: db}
	rep := newReport("ports")
	rep.what = "open ports"
	w, err := newWriter(&c)
	if err != nil {
		return err
	}
	out := &portOut{w: w, exclude: map[string]bool{}, quiet: hasFlag(rest, "quiet")}
	sink := newPortsSink(out)
	st, err := store.OpenExisting(db)
	if err != nil {
		return err
	}
	st.UseRun(id)
	obs, err := st.Observations()
	st.Close()
	if err != nil {
		return err
	}
	sink.replay(obs)
	var args []string
	for _, a := range rest {
		if k, _, _ := strings.Cut(strings.TrimLeft(a, "-"), "="); !strings.HasPrefix(a, "-") || (k != "json" && k != "jsonl") {
			args = append(args, a)
		}
	}
	args = append(append(slices.Clone(runArgs), args...), "-resume-run", id)
	_, done, err := runPreset(&c, args, rep, sink.see)
	if err != nil {
		return err
	}
	defer done()
	if err := w.close(); err != nil {
		return err
	}
	sink.settle(rep, discoversOnly(runArgs))
	return rep.finish(c.json, false)
}

// discoversOnly says whether a stored ports run was -sn: it lists the
// addresses that are up and scans nothing.
func discoversOnly(runArgs []string) bool {
	for i, a := range runArgs {
		if a == "-port-discover" && i+1 < len(runArgs) {
			return runArgs[i+1] == "only"
		}
	}
	return false
}

// once says whether key is new, and notes it.
func once(mu *sync.Mutex, seen map[string]bool, key string) bool {
	mu.Lock()
	defer mu.Unlock()
	if seen[key] {
		return false
	}
	seen[key] = true
	return true
}

// resolverFile is the file of resolvers run takes: -resolvers is a list on
// the command line or a file.
func resolverFile(v string) (string, func(), error) {
	if _, err := os.Stat(v); err == nil {
		return v, func() {}, nil
	}
	var rs []string
	for _, r := range strings.Split(v, ",") {
		if r = strings.TrimSpace(r); r != "" {
			if strings.ContainsAny(r, "/\\") {
				return "", nil, usagef("-resolvers %q is neither a file nor a list of resolvers", v)
			}
			rs = append(rs, r)
		}
	}
	if len(rs) == 0 {
		return "", nil, usagef("-resolvers is empty")
	}
	return tempList(rs)
}

// exclusions are the lines of -ef.
func exclusions(file string) ([]string, error) {
	if file == "" {
		return nil, nil
	}
	return loadLines(file)
}

func humanCount(n float64) string {
	switch {
	case n >= 1e9:
		return fmt.Sprintf("%.1f billion", n/1e9)
	case n >= 1e6:
		return fmt.Sprintf("%.1f million", n/1e6)
	}
	return fmt.Sprintf("%.0f", n)
}

func jsonLine(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	return append(raw, '\n'), err
}
