package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"sort"
	"strings"
)

// command is one azhaq command: what it does, how to call it, what it
// prints. help, -h and help -json are built from this table and the
// command's own flags.
type command struct {
	name     string
	group    string
	summary  string
	usage    string // after "azhaq NAME "
	like     string // the tool it stands in for
	output   string // what stdout carries
	examples []string
	run      func([]string) error
}

const (
	groupMap    = "Map a target"
	groupDropIn = "One job each, output like the tool you know"
	groupWS     = "Read and compare results"
	groupOther  = "Other"
)

var groups = []string{groupMap, groupDropIn, groupWS, groupOther}

// commands is filled in init: the help command reads the table it is in.
var commands []command

func init() {
	commands = []command{
		{name: "run", group: groupMap, run: cmdRun,
			summary: "map a target: names, services, pages, scripts, APIs, forms, parameters, in one graph",
			usage:   "(-url URL | -domain D | -list FILE | -scope FILE|PLATFORM -program P | -asn AS | -cidr NET | -in seeds.jsonl) [flags]",
			output:  "a ranked map, one row per entity (-json: one JSON object per row); the summary on stderr",
			examples: []string{
				"azhaq run -url https://app.example.com/ -db app.db",
				"azhaq run -scope hackerone -program security -db h1.db -max-requests 5000 -rate 5",
				"azhaq run -domain example.com -passive -json > map.jsonl",
				"azhaq run -url https://app.example.com/ -browser -login https://app.example.com/login -login-user me@x.test -login-pass '…'",
			}},
		{name: "plan", group: groupMap, run: cmdPlan,
			summary: "show what a run would do and send, without sending anything",
			usage:   "(-url URL | -domain D | -list FILE | -scope … -program P) [run flags]",
			output:  "the collectors that would run on each seed, the seeds left out of scope, the active techniques asked for, the third-party source queries (counted) and a bound on the requests to the targets: per web service, and the cap",
			examples: []string{
				"azhaq plan -url https://app.example.com/",
				"azhaq plan -scope bugcrowd -program tesla -dirs words.txt",
			}},
		{name: "scope", group: groupMap, run: cmdScope,
			summary: "read a program's scope: what a run would take, exclude and skip",
			usage:   "-scope FILE|hackerone|bugcrowd|intigriti|yeswehack [-program NAME] [-json]",
			output:  "the allow and deny rules, domains to enumerate, targets to probe, and the entries that cannot be used",
			examples: []string{
				"azhaq scope -scope bugcrowd -program tesla",
				"azhaq scope -scope scope.csv",
			}},
		{name: "roles", group: groupMap, run: cmdRoles,
			summary: "map the same target once per session and show where the answers differ (access control)",
			usage:   "-role NAME[=Header: value] -role … [-role-login NAME=USER:PASS -login URL] [-id [ROLE:]NAME=VALUE] [-jsonl] -- RUN FLAGS; roles show -dir DIR URL [-method M]",
			output: "one row per endpoint whose answer depends on the session: status, length and body per role, and a verdict (a role reading another role's object, sensitive fields anyone reads, …); " +
				"a role refused wherever a session matters is named in a note (exit 3). A role sends only the headers it is given: what an app reads from a cookie " +
				"(Juice Shop's /rest/user/whoami) needs NAME=Cookie: …, or -role-login, which carries the cookies and the stored token",
			examples: []string{
				"azhaq roles -role anon -role 'user=Authorization: Bearer eyJ…' -- -url https://api.example.com/",
				"azhaq roles -role anon -role 'alice=Authorization: Bearer eyJ…' -role 'bob=Authorization: Bearer eyJ…' -id 'alice:book_title=Alice book' -- -url https://api.example.com/",
				"azhaq roles -role anon -role 'alice=Authorization: Bearer eyJ…' -role 'alice=Cookie: token=eyJ…' -- -url https://app/",
				"azhaq roles -login https://app/login -role anon -role-login 'alice=a@x.test:pw' -role-login 'bob=b@x.test:pw' -- -url https://app/",
				"azhaq roles show -dir azhaq-roles-20261028-101500 https://app/rest/basket/6",
			}},
		{name: "subs", group: groupDropIn, like: "subfinder", run: cmdSubs,
			summary: "subdomains from passive sources",
			usage:   "-d DOMAIN | -dL FILE | stdin  [-live] [-json] [-silent] [-o FILE] [-db FILE]",
			output:  "one name per line; -json: {\"host\",\"input\",\"source\",\"sources\"} like subfinder",
			examples: []string{
				"azhaq subs -d example.com",
				"azhaq subs -d example.com -live -json -db example.db",
			}},
		{name: "dns", group: groupDropIn, like: "dnsx", run: cmdDNS,
			summary:  "resolve names; wildcard answers left out",
			usage:    "-d NAME | -l FILE | stdin  [-resp] [-json]",
			output:   "one live name per line; -json: {\"host\",\"a\",\"aaaa\",\"cname\"} like dnsx",
			examples: []string{"azhaq subs -d example.com | azhaq dns -json"}},
		{name: "probe", group: groupDropIn, like: "httpx", run: cmdProbe,
			summary: "find the web services of hosts: status, title, technologies, CDN, favicon",
			usage:   "-u TARGET | -l FILE | stdin  [-web-ports P] [-scope … -program P] [-rate N] [-json] [-silent]",
			output:  "one web service per line, as it answers; -json: httpx's fields (url, host, host_ip, port, scheme, status_code, title, tech, …)",
			examples: []string{
				"azhaq subs -d example.com -live | azhaq probe -json",
				"azhaq probe -l hosts.txt -scope hackerone -program security -rate 10",
			}},
		{name: "crawl", group: groupDropIn, like: "katana + jsluice", run: cmdCrawl,
			summary:  "the URLs of an application: links, forms, scripts, routes in JavaScript, API descriptions",
			usage:    "-u URL | -l FILE | stdin  [-depth N] [-assets] [-no-catchall] [-json]",
			output:   "one URL per line; -json: {\"url\",\"coverage\",\"role\",\"status\",\"methods\",\"params\"}",
			examples: []string{"azhaq crawl -u https://app.example.com/ -json"}},
		{name: "urls", group: groupDropIn, like: "gau", run: cmdURLs,
			summary:  "archived URLs of domains (Wayback Machine, Common Crawl, OTX, urlscan, Arquivo)",
			usage:    "-d DOMAIN | -dL FILE | stdin  [-json]",
			output:   "one URL per line; -json: {\"url\"}",
			examples: []string{"azhaq urls -d example.com"}},
		{name: "ports", group: groupDropIn, like: "naabu", run: cmdPorts,
			summary:  "open TCP ports (connect scan, no root), with banners",
			usage:    "-host HOST | -l FILE | stdin  [-p top-100|top-1000|full|LIST] [-rate N] [-json]",
			output:   "host:port per open port; -json: {\"host\",\"ip\",\"port\",\"protocol\",\"service\",\"banner\"}",
			examples: []string{"azhaq ports -host scanme.nmap.org -p top-1000 -json"}},
		{name: "dirs", group: groupDropIn, like: "ffuf -ac", run: cmdDirs,
			summary:  "paths from a wordlist that answer unlike a path that cannot exist",
			usage:    "-u URL | -l FILE | stdin  -w WORDLIST [-e EXT] [-depth N] [-mc LIST] [-rate N] [-json]",
			output:   "one URL per line with status and size; -json: {\"url\",\"status\",\"length\",\"words\",\"lines\"}",
			examples: []string{"azhaq dirs -u https://app.example.com/ -w common.txt -rate 20"}},
		{name: "params", group: groupDropIn, like: "arjun", run: cmdParams,
			summary:  "query parameters pages read, from a wordlist (GET)",
			usage:    "-u URL | -l FILE | stdin  -w NAMES [-rate N] [-json]",
			output:   "URL and parameter names per line; -json: {\"url\",\"method\",\"params\",\"why\"}",
			examples: []string{"azhaq params -u https://app.example.com/search -w params.txt"}},
		{name: "asn", group: groupDropIn, like: "asnmap", run: cmdASN,
			summary:  "the prefixes autonomous systems announce",
			usage:    "-a AS64500 | -l FILE | stdin  [-json]",
			output:   "one prefix per line; -json: {\"as_number\",\"as_name\",\"prefix\"}",
			examples: []string{"azhaq asn -a AS13335"}},
		{name: "shots", group: groupDropIn, like: "gowitness", run: cmdShots,
			summary:  "a screenshot of each web service, look-alikes grouped (needs Chrome)",
			usage:    "-u TARGET | -l FILE | stdin  [-dir DIR] [-tabs N] [-json]",
			output:   "URL and PNG file per line; -json: {\"url\",\"file\",\"title\",\"phash\"}",
			examples: []string{"azhaq shots -l services.txt -dir shots"}},
		{name: "query", group: groupWS, run: cmdQuery,
			summary: "ask a database a precise question instead of reading the whole map",
			usage:   "-db FILE [-type T] [-role R] [-coverage C] [-status N] [-method M] [-host H] [-match TEXT] [-new] [-fields A,B] [-limit N] [-json]",
			output:  "the matching rows of the map, best first",
			examples: []string{
				"azhaq query -db app.db -role auth",
				"azhaq query -db app.db -role api -method POST -fields key,methods,body -json",
				"azhaq query -db app.db -type URL -status 5xx",
				"azhaq query -db h1.db -type Hostname -new",
			}},
		{name: "show", group: groupWS, run: cmdShow,
			summary:  "everything known about one URL, host or name: what found it, what it leads to, every observation",
			usage:    "-db FILE [-json] KEY",
			output:   "the entity's row, its links and its observations",
			examples: []string{"azhaq show -db app.db https://app.example.com/api/users"}},
		{name: "watch", group: groupWS, run: cmdWatch,
			summary:  "run again and again into a workspace and report what appeared, changed or disappeared",
			usage:    "-db WORKSPACE.db [-every 24h] [-notify WEBHOOK] [-notify-cmd CMD] [-json] -- RUN FLAGS",
			output:   "the change set after each run (-json: one JSON object)",
			examples: []string{"azhaq watch -db acme.db -every 24h -notify https://hooks.slack.com/… -- -scope hackerone -program acme"}},
		{name: "new", group: groupWS, run: cmdNew,
			summary:  "what a workspace first saw lately",
			usage:    "-db WORKSPACE.db [-since 168h] [-json]",
			output:   "one entity per line with when it was first seen",
			examples: []string{"azhaq new -db acme.db -since 24h"}},
		{name: "diff", group: groupWS, run: cmdDiff,
			summary:  "compare two runs",
			usage:    "-a OLD.db -b NEW.db | -db WORKSPACE.db  [-jsonl] [-quiet]",
			output:   "entities added and removed, new observations",
			examples: []string{"azhaq diff -db acme.db"}},
		{name: "export", group: groupWS, run: cmdExport,
			summary: "write a database in another tool's format",
			usage:   "[-db FILE] [-format jsonl|urls|hosts|names|targets|openapi|graphql|sdl|burp|html|graphml|secrets] [-origin ORIGIN|URL]",
			output:  "the chosen format; graphql: {\"data\":{\"__schema\":…}} of a GraphQL endpoint read with -graphql (keyed by URL when there are several; -origin picks one), sdl: its schema in GraphQL SDL, burp: the run's scope, allow rules as include and deny rules as exclude",
			examples: []string{
				"azhaq export -db app.db -format openapi > app.openapi.json",
				"azhaq export -db app.db -format graphql -origin https://app.example.com/graphql > schema.json",
				"azhaq export -db app.db -format sdl > schema.graphql",
				"azhaq export -db h1.db -format burp > scope.json",
				"azhaq export -db h1.db -format targets | nuclei -l -",
			}},
		{name: "ingest", group: groupWS, run: cmdIngest,
			summary: "add other tools' results to a database (subfinder, httpx, katana, naabu, ffuf JSONL, or connector facts)",
			usage:   "-in FILE [-db FILE]",
			output:  "the map of what was added",
			examples: []string{
				"subfinder -d example.com -json | azhaq ingest -in - -db example.db",
				"httpx -l hosts.txt -json | azhaq ingest -in - -db example.db && azhaq export -db example.db -format targets",
			}},
		{name: "resume", group: groupWS, run: cmdResume,
			summary:  "continue a run that was interrupted or stopped by a limit",
			usage:    "-db FILE [run flags to add, such as -cookie or -max-requests]",
			output:   "as run",
			examples: []string{"azhaq resume -db app.db -max-requests 2000"}},
		{name: "mcp", group: groupOther, run: cmdMCP,
			summary: "serve Azhaq to MCP clients over stdio, the scope and request budget fixed at start",
			usage:   "[-scope FILE|PLATFORM -program P] [-allow D] [-deny D] [-max-requests N] [-rate N] [-dir DIR]",
			output:  "JSON-RPC (Model Context Protocol) on stdin and stdout",
			examples: []string{
				"azhaq mcp -scope hackerone -program security -max-requests 20000 -rate 5",
				"claude mcp add azhaq -- azhaq mcp -allow example.com -max-requests 5000",
			}},
		{name: "worker", group: groupOther, run: cmdWorker,
			summary:  "take work from a run started with -serve",
			usage:    "-server URL [-token T]",
			output:   "progress on stderr",
			examples: []string{"AZHAQ_WORKER_TOKEN=… azhaq worker -server http://10.0.0.5:7777"}},
		{name: "docs", group: groupOther, run: cmdDocs,
			summary:  "print the documentation: output fields, exit codes, connectors, MCP",
			usage:    "[TOPIC]",
			output:   "Markdown",
			examples: []string{"azhaq docs output"}},
		{name: "version", group: groupOther, run: cmdVersion,
			summary: "print the version",
			usage:   "[-json]",
			output:  "azhaq VERSION",
		},
		{name: "help", group: groupOther, run: cmdHelp,
			summary: "help for azhaq or one command; -json for every command and flag",
			usage:   "[COMMAND] [-json]",
			output:  "text, or JSON with -json",
		},
		{name: "bench", group: groupOther, run: cmdBench,
			summary: "a quick self-test against a built-in site",
			usage:   "",
			output:  "time and memory",
		},
	}
}

func lookup(name string) (command, bool) {
	for _, c := range commands {
		if c.name == name {
			return c, true
		}
	}
	return command{}, false
}

// Exit codes, the same for every command.
const (
	exitOK      = 0
	exitError   = 1 // the command could not do its job
	exitUsage   = 2 // bad flags or input; nothing was sent
	exitPartial = 3 // finished, but some sources or requests failed: results are usable, the summary lists what failed
	exitLimit   = 4 // stopped by a limit (-max-requests, -timeout, a daily budget) with work left: azhaq resume continues
)

var exitCodes = []struct {
	Code    int    `json:"code"`
	Meaning string `json:"meaning"`
}{
	{exitOK, "complete"},
	{exitError, "error: the command could not do its job"},
	{exitUsage, "usage: bad flags or input, nothing was sent"},
	{exitPartial, "finished, but some sources or requests failed: the results are usable, the summary on stderr lists what failed"},
	{exitLimit, "stopped by a limit (-max-requests, -timeout, -daily-requests, -max-items) with work left: azhaq resume -db FILE continues"},
}

// exitErr carries an exit code out of a command whose summary already
// said what happened.
type exitErr struct {
	code int
	msg  string
}

func (e exitErr) Error() string { return e.msg }

// usageErr is a mistake in how a command was called.
type usageErr struct{ err error }

func (e usageErr) Error() string { return e.err.Error() }
func (e usageErr) Unwrap() error { return e.err }

func usagef(format string, a ...any) error {
	return usageErr{fmt.Errorf(format, a...)}
}

// exitCode is the process exit code for a command's error.
func exitCode(err error) int {
	var ee exitErr
	var ue usageErr
	switch {
	case err == nil, errors.Is(err, flag.ErrHelp):
		return exitOK
	case errors.As(err, &ee):
		return ee.code
	case errors.As(err, &ue):
		return exitUsage
	default:
		return exitError
	}
}

// Describing: help and help -json read a command's flags by calling it
// with -h; newFlags hands the flag set over instead of printing.
var (
	describing bool
	described  *flag.FlagSet
)

func newFlags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {} // parse prints the help when it is asked for
	return fs
}

// parse reads a command's flags; -h prints the command's help, and a
// mistake is a usage error. Flags may come after the other arguments
// (azhaq show URL -json); everything after -- is left as given.
func parse(fs *flag.FlagSet, args []string) error {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				if describing {
					described = fs
				} else {
					printHelp(os.Stdout, fs.Name(), fs)
				}
				return err
			}
			return usageErr{err}
		}
		rest := fs.Args()
		if len(rest) == 0 {
			break
		}
		if n := len(args) - len(rest); n > 0 && args[n-1] == "--" {
			pos = append(pos, rest...)
			break
		}
		pos = append(pos, rest[0])
		args = rest[1:]
	}
	return fs.Parse(append([]string{"--"}, pos...))
}

// flagsOf returns a command's flag set without running it.
func flagsOf(name string) *flag.FlagSet {
	c, ok := lookup(name)
	if !ok || c.run == nil || name == "help" || name == "resume" {
		return nil
	}
	wasDescribing, wasDescribed := describing, described
	describing, described = true, nil
	defer func() { describing = wasDescribing }()
	stdout, stderr := os.Stdout, os.Stderr
	null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err == nil {
		os.Stdout, os.Stderr = null, null
		defer func() { os.Stdout, os.Stderr = stdout, stderr; null.Close() }()
	}
	_ = c.run([]string{"-h"})
	fs := described
	described = wasDescribed
	return fs
}

type flagInfo struct {
	Name       string `json:"name"`
	Type       string `json:"type"` // bool, string, int, float, duration
	Repeatable bool   `json:"repeatable,omitempty"`
	Default    string `json:"default,omitempty"`
	Usage      string `json:"usage"`
}

func flagInfos(fs *flag.FlagSet) []flagInfo {
	var out []flagInfo
	if fs == nil {
		return out
	}
	fs.VisitAll(func(f *flag.Flag) {
		if strings.HasPrefix(f.Usage, "internal:") {
			return
		}
		typ, usage := flag.UnquoteUsage(f)
		fi := flagInfo{Name: f.Name, Usage: usage, Type: typ}
		if u, ok := strings.CutSuffix(strings.TrimSpace(usage), "(repeatable)"); ok {
			fi.Usage, fi.Repeatable = strings.TrimSpace(u), true
		} else if strings.Contains(usage, "(repeatable;") || strings.Contains(usage, "(repeatable)") {
			fi.Repeatable = true
		}
		switch f.Value.(type) {
		case *stringsFlag:
			fi.Type, fi.Repeatable = "string", true
		}
		if bf, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && bf.IsBoolFlag() {
			fi.Type = "bool"
		}
		if typ == "value" && !fi.Repeatable {
			fi.Type = "string"
		}
		if f.DefValue != "" && f.DefValue != "false" && f.DefValue != "0" && f.DefValue != "0s" && f.DefValue != "[]" {
			fi.Default = f.DefValue
		}
		out = append(out, fi)
	})
	return out
}

// printHelp is azhaq NAME -h.
func printHelp(w io.Writer, name string, fs *flag.FlagSet) {
	c, ok := lookup(name)
	if !ok {
		return
	}
	fmt.Fprintf(w, "azhaq %s: %s", c.name, c.summary)
	if c.like != "" {
		fmt.Fprintf(w, " (like %s)", c.like)
	}
	fmt.Fprintf(w, "\n\nusage: azhaq %s %s\n", c.name, c.usage)
	if c.output != "" {
		fmt.Fprintf(w, "output: %s\n", c.output)
	}
	if len(c.examples) > 0 {
		fmt.Fprintf(w, "\nexamples:\n")
		for _, e := range c.examples {
			fmt.Fprintf(w, "  %s\n", e)
		}
	}
	infos := flagInfos(fs)
	if len(infos) > 0 {
		fmt.Fprintf(w, "\nflags:\n")
		width := 0
		cols := make([]string, len(infos))
		for i, f := range infos {
			col := "-" + f.Name
			if f.Type != "bool" {
				col += " " + strings.ToUpper(f.Type)
			}
			cols[i] = col
			width = max(width, len(col))
		}
		for i, f := range infos {
			line := f.Usage
			if f.Repeatable && !strings.Contains(line, "repeatable") {
				line += " (repeatable)"
			}
			if f.Default != "" {
				line += fmt.Sprintf(" (default %s)", f.Default)
			}
			fmt.Fprintf(w, "  %-*s  %s\n", width, cols[i], line)
		}
	}
	fmt.Fprintf(w, "\nexit: 0 complete, 1 error, 2 usage, 3 finished with failures (see the summary), 4 stopped by a limit (resumable)\n")
}

// printOverview is azhaq help.
func printOverview(w io.Writer) {
	fmt.Fprintf(w, "azhaq %s: one recon engine for names, services, applications and APIs, in one graph\n\n", version)
	fmt.Fprintf(w, "usage: azhaq COMMAND [flags]    azhaq help COMMAND    azhaq help -json    azhaq docs\n")
	for _, g := range groups {
		fmt.Fprintf(w, "\n%s:\n", g)
		for _, c := range commands {
			if c.group != g {
				continue
			}
			line := c.summary
			if c.like != "" {
				line += " (like " + c.like + ")"
			}
			fmt.Fprintf(w, "  %-8s %s\n", c.name, line)
		}
	}
	fmt.Fprintf(w, `
Every command:
  results on stdout, one per line (-json: one JSON object per line);
  progress and a summary on stderr (-json: the summary is one JSON object,
  "type":"summary": results, failures, what was skipped and why, limits);
  exit 0 complete, 1 error, 2 usage, 3 finished with failures, 4 stopped
  by a limit (azhaq resume continues).
Active techniques (-dirs, -params, -ports, -dns-brute, -permute, -graphql)
need a scope (-allow or -scope). azhaq plan shows what a run would send.
`)
}

type manifest struct {
	Name      string        `json:"name"`
	Version   string        `json:"version"`
	ExitCodes any           `json:"exit_codes"`
	Output    string        `json:"output"`
	Commands  []commandInfo `json:"commands"`
}

type commandInfo struct {
	Name     string     `json:"name"`
	Group    string     `json:"group"`
	Summary  string     `json:"summary"`
	Usage    string     `json:"usage"`
	Like     string     `json:"like,omitempty"`
	Output   string     `json:"output,omitempty"`
	Examples []string   `json:"examples,omitempty"`
	Flags    []flagInfo `json:"flags,omitempty"`
}

func buildManifest() manifest {
	m := manifest{Name: "azhaq", Version: version, ExitCodes: exitCodes,
		Output: "results on stdout (-json: JSONL); progress and a final summary on stderr (-json: one JSON object with \"type\":\"summary\"); azhaq docs output describes every field"}
	for _, c := range commands {
		ci := commandInfo{Name: c.name, Group: c.group, Summary: c.summary, Usage: "azhaq " + strings.TrimSpace(c.name+" "+c.usage), Like: c.like, Output: c.output, Examples: c.examples}
		ci.Flags = flagInfos(flagsOf(c.name))
		m.Commands = append(m.Commands, ci)
	}
	return m
}

func cmdHelp(args []string) error {
	asJSON := false
	var names []string
	for _, a := range args {
		switch a {
		case "-json", "--json":
			asJSON = true
		case "-h", "--help":
		default:
			names = append(names, a)
		}
	}
	if asJSON {
		m := buildManifest()
		if len(names) > 0 {
			var keep []commandInfo
			for _, c := range m.Commands {
				for _, n := range names {
					if c.Name == n {
						keep = append(keep, c)
					}
				}
			}
			if len(keep) == 0 {
				return usagef("no command %q; azhaq help lists them", names[0])
			}
			m.Commands = keep
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(m)
	}
	if len(names) == 0 {
		printOverview(os.Stdout)
		return nil
	}
	if _, ok := lookup(names[0]); !ok {
		return usagef("no command %q; azhaq help lists them", names[0])
	}
	if names[0] == "resume" {
		c, _ := lookup("resume")
		fmt.Printf("azhaq resume: %s\n\nusage: azhaq resume %s\n\nThe run's flags are read back from the database; flags given here are added and win.\n", c.summary, c.usage)
		return nil
	}
	printHelp(os.Stdout, names[0], flagsOf(names[0]))
	return nil
}

func cmdVersion(args []string) error {
	fs := newFlags("version")
	asJSON := fs.Bool("json", false, "print as JSON")
	if err := parse(fs, args); err != nil {
		return err
	}
	if *asJSON {
		return json.NewEncoder(os.Stdout).Encode(map[string]string{"version": version, "go": runtime.Version(), "os": runtime.GOOS, "arch": runtime.GOARCH})
	}
	fmt.Printf("azhaq %s\n", version)
	return nil
}

// suggest names the commands closest to a mistyped one.
func suggest(name string) []string {
	var out []string
	for _, c := range commands {
		if strings.HasPrefix(c.name, name) || strings.HasPrefix(name, c.name) || levenshtein(name, c.name) <= 2 {
			out = append(out, c.name)
		}
	}
	sort.Strings(out)
	return out
}

func levenshtein(a, b string) int {
	prev := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur := make([]int, len(b)+1)
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev = cur
	}
	return prev[len(b)]
}
