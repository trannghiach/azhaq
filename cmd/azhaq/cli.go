package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/trannghiach/azhaq/internal/neterr"
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
			output:  "the collectors that would run on each seed, the seeds left out of scope, the active techniques asked for, what is sent to the targets (GET requests only, or each port scan, UDP probe, POST body and sign-in that is planned), the third-party source queries (counted) and a bound on the requests to the targets: per web service, and the cap",
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
		{name: "report", group: groupMap, run: cmdReport,
			summary: "write each finding roles listed up as a report to submit (title, steps with curl, evidence, impact)",
			usage:   "-dir DIR [-url URL [-method M]] [-format md|json] [-o FILE|DIR] [-redact]",
			output:  "one Markdown report per cross-role read or write and per sensitive field anyone reads, best-evidenced first (proved, likely, guess), written to DIR/reports or -o; -url writes one to standard output. Every piece comes from the roles run's evidence (roles.db); what it does not hold is named in the report. -redact masks hosts and identifiers",
			examples: []string{
				"azhaq report -dir azhaq-roles-20261028-101500",
				"azhaq report -dir azhaq-roles-20261028-101500 -url https://app/rest/basket/6 -redact",
			}},
		{name: "subs", group: groupDropIn, like: "subfinder", run: cmdSubs,
			summary: "subdomains from passive sources",
			usage:   "-d DOMAIN | -dL FILE | stdin  [-live] [-json] [-silent] [-o FILE] [-db FILE] [-m GLOB | -f GLOB | -match-regex RE | -filter-regex RE] [-source-rate N] [-ls]",
			output:  "one name per line, as subfinder prints it (-cs: host,[sources]; -live -oI: host,ip,source); -json: {\"host\",\"input\",\"source\",\"sources\"} like subfinder, with \"unverified\":true on a name that only subdomain.center guessed or only the name history held, which was not looked up in DNS (without -live), and with -live dnsx's a, aaaa, cname. The domain given is not printed, as subfinder keeps only the names below it. The summary's counts add up: from sources, less the domain itself and did not resolve, plus CNAME targets and guesses found, is the names printed",
			examples: []string{
				"azhaq subs -d example.com",
				"azhaq subs -d example.com -live -json -db example.db",
				"azhaq subs -d example.com,example.org -live -dns-rate 10 -source-rate 2 -m '*.dev.example.com'",
				"azhaq subs -ls -json",
			}},
		{name: "dns", group: groupDropIn, like: "dnsx", run: cmdDNS,
			summary: "resolve names, any record type; wildcard answers left out",
			usage:   "-d NAME | -l FILE | stdin  [-a -aaaa -cname -ns -txt -srv -ptr -mx -soa -caa -any -axfr -all] [-resp] [-json] [-w WORDS] [-r RESOLVERS]",
			output:  "one name per line (A by default); -json: dnsx's fields (host, ttl, resolver, a, aaaa, cname, mx, ns, txt, srv, ptr, soa, caa, all, status_code, status_code_raw, cdn-name, ...) for every name a resolver answered, left out when empty",
			examples: []string{
				"azhaq subs -d example.com | azhaq dns -a -json",
				"azhaq dns -l names.txt -mx -txt -resp -r 1.1.1.1,tcp:9.9.9.9",
				"azhaq dns -l 192.0.2.0/24 -ptr -resp",
				"azhaq dns -d example.com -w words.txt -rl 50 -t 100",
				"azhaq dns -d example.com -axfr -allow example.com",
			}},
		{name: "probe", group: groupDropIn, like: "httpx", run: cmdProbe,
			summary: "find the web services of hosts: status, title, technologies, CDN, certificate, hashes; matchers and filters; raw responses",
			usage:   "-u TARGET | -l FILE | stdin  [-p PORTS] [-path P] [-fr] [-mc 200 -ms admin …] [-tls-grab -hash md5 -jarm …] [-sr] [-rate N] [-json | -csv | -md] [-silent]",
			output:  "one web service per line, as it answers; -json: httpx's fields (url, host, host_ip, port, scheme, status_code, title, tech, tls, hash, …); a target with no answer is a row with failed:true (-probe prints [FAILED])",
			examples: []string{
				"azhaq subs -d example.com -live | azhaq probe -json",
				"azhaq probe -l hosts.txt -scope hackerone -program security -rate 10",
				"azhaq probe -l hosts.txt -p 443,8000-8100 -mc 200,401 -ms 'admin' -title -td",
				"azhaq probe -l hosts.txt -fr -tls-grab -hash md5 -json   # follow redirects, certificate, body hash",
				"azhaq probe -l hosts.txt -sr -srd out -irh -irr -json   # keep every response",
				"azhaq probe -u https://app.example.com -x GET,POST -body 'a=1'   # sends POST: can change data on the target",
			}},
		{name: "crawl", group: groupDropIn, like: "katana + jsluice", run: cmdCrawl,
			summary: "the URLs of an application: links, forms, scripts, routes in JavaScript, API descriptions",
			usage:   "-u URL | -l FILE | stdin  [-d N] [-fs rdn|fqdn|dn|REGEX] [-cs RE] [-cos RE] [-do] [-f FIELDS] [-em/-ef/-mr/-fr] [-jsonl | -json] [-rejected] [-submit-forms] [-rl N] [-silent]",
			output:  "one URL per line (pages, scripts and stylesheets; -assets adds images, fonts and media); -jsonl: katana's {\"request\",\"response\"} lines; -json: {\"url\",\"coverage\",\"role\",\"status\",\"methods\",\"params\",\"forms\",\"tech\"} (routes a script calls with POST are listed, and their GET may answer 404 or 405: -json has methods, -ot '{{method}} {{url}}' prints them); -rejected adds the strings kept out of the URLs, with the reason",
			examples: []string{
				"azhaq crawl -u https://app.example.com/ -d 3 -silent",
				"azhaq crawl -u https://app.example.com/ -jsonl > crawl.jsonl",
				"azhaq crawl -u https://app.example.com/ -fs rdn -do -f rdn,path -rl 5",
				"azhaq crawl -u https://app.example.com/ -json -rejected",
			}},
		{name: "urls", group: groupDropIn, like: "gau", run: cmdURLs,
			summary: "archived URLs of domains (Wayback Machine, Common Crawl, OTX, urlscan, Arquivo)",
			usage:   "-d DOMAIN | -dL FILE | DOMAIN… | stdin  [-subs] [-providers wayback,otx,…] [-mc/-fc/-mt/-ft LIST] [-from/-to YYYYMM] [-blacklist EXT,…] [-fp] [-raw] [-proxy URL] [-retries N] [-urls-threads N] [-o FILE] [-json]",
			output:  "one URL per line, as the pages arrive (-sort: sorted, at the end; a terminal sorts); -json: {\"url\",\"source\"}; -o appends",
			examples: []string{
				"azhaq urls -d example.com",
				"azhaq urls example.com -subs -providers wayback,commoncrawl -blacklist png,jpg,css,js -fp | httpx",
				"azhaq urls -d example.com -mc 200 -mt text/html -from 2024 -urls-pause 0",
			}},
		{name: "ports", group: groupDropIn, like: "naabu", run: cmdPorts,
			summary: "open TCP ports (connect scan, no root), named by what they answer on any port, with products and versions; ranges, CIDR and AS numbers without a cap; -udp asks the common UDP ports",
			usage:   "-host HOST[,HOST…] | -l FILE | stdin | TARGET…  [-p LIST | -tp 100|1000|full | -pf FILE] [-ep LIST] [-udp | -pu LIST] [-rate N] [-T0..5] [-connect-timeout MS] [-retries N] [-c N] [-sn | -wn] [-cdn-full] [-csv | -json] [-oX F] [-oG F] [-oA BASE]",
			output:  "host:port per open port (host:port/udp for UDP); -json: {\"host\",\"ip\",\"port\",\"protocol\",\"tls\",\"cdn\",\"cdn-name\",\"timestamp\" (UTC),\"service\",\"product\",\"version\",\"title\",\"banner\",\"state\" (UDP)}; -csv: the same fields as columns; -oX nmap XML, -oG greppable, -oA all three. Targets: a name, an address, host:port (that port only, unless -p is given), a URL, a CIDR range (IPv4 or IPv6 down to /104), AS64500 (the prefixes RIPEstat lists), several to a flag separated by commas. -timeout is how long the whole run may take; the wait for one connect is -connect-timeout",
			examples: []string{
				"azhaq ports -host scanme.nmap.org -p top-1000 -json",
				"azhaq ports 10.0.0.0/16 -p 22,80,443 -rate 2000 -wn",
				"azhaq ports -host 127.0.0.1 -p none -pu 1-1024 -json",
				"azhaq ports -l hosts.txt -tp 1000 -ep 25,3306 -T2 -oA scan",
			}},
		{name: "dirs", group: groupDropIn, like: "ffuf -ac", run: cmdDirs,
			summary:  "paths from a wordlist (SecLists' common.txt built in) that answer unlike a path that cannot exist; a URL with a path is swept from that path",
			usage:    "-u URL | -l FILE | stdin  [-w WORDLIST] [-e EXT] [-depth N] [-mc/-ms/-mw/-ml/-mr LIST] [-fc/-fs/-fw/-fl/-fr LIST] [-rate N] [-json]",
			output:   "one URL per line with status, size, words and lines; -json: {\"url\",\"status\",\"length\",\"words\",\"lines\",\"redirectlocation\"}. Sizes, words and lines are counted as ffuf counts them, so a -fs or -fl value carries over. The calibration is on (it is ffuf's -ac); -mc defaults to ffuf's 200-299,301,302,307,401,403,405,500",
			examples: []string{"azhaq dirs -u https://app.example.com/", "azhaq dirs -u https://app.example.com/api/ -w common.txt -e php,bak -fs 4242 -rate 20"}},
		{name: "fuzz", group: groupDropIn, like: "ffuf", run: cmdFuzz,
			summary: "wordlists put into a request, anywhere in it: paths, query values, headers (virtual hosts), JSON or form bodies; filters, auto-calibration and recursion as ffuf has them",
			usage:   "-u URL | -request FILE  -w FILE[:KEYWORD] [-w …] [-mode clusterbomb|pitchfork|sniper] [-X METHOD] [-d DATA] [-H 'Name: value'] [-mc/-ms/-mw/-ml/-mr/-mt] [-fc/-fs/-fw/-fl/-fr/-ft] [-ac] [-recursion] [-e .php,.bak] [-enc 'FUZZ:urlencode'] [-x PROXY] [-replay-proxy PROXY] [-t N] [-rate N] [-p SECONDS] [-o FILE -of json|ejson|csv|ecsv|html|md|all] [-od DIR] [-json] [-db FILE]",
			output:  "ffuf's: one line per match, the input and [Status, Size, Words, Lines, Duration] (-v adds the URL; several keywords print one block each; -s the inputs only); -json: ffuf's fields {\"input\",\"position\",\"status\",\"length\",\"words\",\"lines\",\"content-type\",\"redirectlocation\",\"url\",\"duration\",\"host\"}, input values base64. -o writes ffuf's report (json by default, -of for the other formats; a name ending .txt gets stdout's text). Auto-calibration is off unless -ac (or -acs, -acc, -ach) is given, as in ffuf. The host of -u is the scope unless -allow, -deny or -scope say otherwise",
			examples: []string{
				"azhaq fuzz -u https://app.example.com/FUZZ -w common.txt -e .php,.bak -recursion -recursion-depth 2 -ac",
				"azhaq fuzz -u https://app.example.com/login -X POST -H 'Content-Type: application/json' -d '{\"user\":\"USER\",\"password\":\"PASS\"}' -w users.txt:USER -w pass.txt:PASS -mode pitchfork -mr 'welcome'",
				"azhaq fuzz -u https://10.0.0.5/ -H 'Host: FUZZ.example.com' -w subdomains.txt -fs 4242 -json -db vhosts.db",
				"azhaq fuzz -request login.req -request-proto https -w pass.txt:PASS -mc all -fc 401 -o report.json -x http://127.0.0.1:8080",
				"azhaq fuzz -u 'https://app.example.com/api/§v1§/users/§1§' -w ids.txt -mode sniper",
			}},
		{name: "params", group: groupDropIn, like: "arjun", run: cmdParams,
			summary: "query parameters pages read, from a list (GET; -X POST, JSON or XML send bodies)",
			usage:   "-u URL | -l FILE | -i FILE | stdin  [-w small|medium|large|FILE] [-X GET|POST|JSON|XML] [-t N] [-c N] [-d SECONDS] [-stable] [-T SECONDS] [-include DATA] [-casing STYLE] [-passive] [-rate N] [-oJ FILE] [-oT FILE] [-oB HOST:PORT] [-json]",
			output:  "URL and parameter names per line; -json: {\"url\",\"method\",\"params\",\"why\"} (why: status, size, headers, location, lines, reflected or named for each name; values: the value a name needed, for debug and the like). -oJ writes arjun's file, {\"URL\": {\"params\",\"method\",\"headers\"}}; -oT one request per line, URL?name=1234&…. A page that rate-limits (429, 418, 503) or leaves requests unanswered fails with exit 3 and a note; a page left alone says why",
			examples: []string{
				"azhaq params -u https://app.example.com/search",
				"azhaq params -u https://app.example.com/search -w burp-parameter-names.txt -rate 5 -oJ params.json",
				"azhaq params -i burp-export.xml -allow app.example.com -X POST    # bodies may change data",
			}},
		{name: "asn", group: groupDropIn, like: "asnmap", run: cmdASN,
			summary:  "the prefixes autonomous systems announce",
			usage:    "-a AS64500 | -l FILE | stdin  [-json]",
			output:   "one prefix per line; -json: {\"as_number\",\"as_name\",\"prefix\"}",
			examples: []string{"azhaq asn -a AS13335"}},
		{name: "shots", group: groupDropIn, like: "gowitness", run: cmdShots,
			summary: "a screenshot of each web service, look-alikes grouped (needs Chrome)",
			usage:   "-u TARGET | -l FILE | -nmap FILE | -nessus FILE | stdin  [-p PORTS] [-dir DIR] [-shot-size WxH] [-shot-fullpage] [-shot-format jpeg] [-rate N] [-json]",
			output:  "URL and picture file per line; -json: one object per page with {\"url\",\"file\",\"title\",\"final_url\",\"phash\",\"response_code\",\"headers\",\"tls\",\"technologies\",\"console\",\"network\"}, and {\"partial\":true} when the page was not fully loaded (exit 3), or drew without assets of hosts outside the scope (\"blocked\", \"blocked_hosts\": a note, and the exit code does not change, the scope is yours); text: partial (3 off-scope assets blocked: cdn.example.com)",
			examples: []string{
				"azhaq shots -l services.txt -dir shots",
				"azhaq shots -u http://127.0.0.1:3001/rest/products/search   # a path and query are kept",
				"azhaq shots -u 192.0.2.0/28 -p small -rate 5   # a range, ports 80 and 443",
				"azhaq shots -nmap scan.xml -shot-format jpeg -shot-fullpage",
			}},
		{name: "notify", group: groupDropIn, like: "notify", run: cmdNotify,
			summary: "send text from a pipe or a file to Slack, Discord, Telegram, Teams, Google Chat, Pushover, Gotify, SMTP or any URL; notify's flags and provider-config.yaml",
			usage:   "[-i FILE | stdin]  [-pc provider-config.yaml] [-p PROVIDER] [-id ID] [-bulk] [-cl 4000] [-mf FORMAT] [-rl 1] [-d SECONDS] [-proxy URL] [-v] [-silent] [-json]",
			output:  "each message as it was sent, one per line (-json: {\"message\",\"sent\",\"failed\"}); the summary on stderr names every provider entry a message did not reach and the exit code is 3 then, where notify exits 0",
			examples: []string{
				"azhaq subs -d example.com -live | azhaq notify -bulk -pc provider-config.yaml",
				"azhaq notify -i report.txt -p slack,discord -id recon -mf 'recon {{date}}: {{data}}'",
				"azhaq ports -host 127.0.0.1 -json | azhaq notify -p custom -rl 2",
			}},
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
		{name: "gallery", group: groupWS, run: cmdGallery,
			summary: "browse a workspace's screenshots in a browser: a grid with filters, search, look-alike groups and a page per shot",
			usage:   "[-db FILE ...] [-workspace DIR] [-listen 127.0.0.1:7180]",
			output:  "the address of a local web page on stderr; the page and its JSON API (/api/) read the workspace and send nothing to any target; exit 3 when a workspace or picture file could not be read",
			examples: []string{
				"azhaq gallery -db app.db",
				"azhaq gallery -workspace ./recon -listen 127.0.0.1:8000",
				"curl -s 'http://127.0.0.1:7180/api/shots?status=200&tech=nginx&collapse=1&limit=20'",
			}},
		{name: "hunt", group: groupWS, run: cmdHunt,
			summary: "where to look first: the mapped routes, hosts and files ranked, each with its evidence and the next command",
			usage:   "-db FILE [-roles roles.jsonl] [-limit 25] [-since 168h] [-json]",
			output:  "one row per route template: rank, score, key, the reasons, and the command to run next (-json: rank, score, key, type, reasons, next)",
			examples: []string{
				"azhaq hunt -db app.db",
				"azhaq roles -json -role anon -role 'user=Authorization: Bearer …' -- -url https://app.example.com/ > roles.jsonl; azhaq hunt -db app.db -roles roles.jsonl",
			}},
		{name: "watch", group: groupWS, run: cmdWatch,
			summary:  "run again and again into a workspace and report what appeared, changed or disappeared",
			usage:    "-db WORKSPACE.db [-every 24h] [-notify WEBHOOK|@FILE] [-notify-config PROVIDER-CONFIG.yaml] [-notify-cmd CMD] [-json] -- RUN FLAGS",
			output:   "the change set after each run (-json: one JSON object); a notification that did not arrive is named on stderr and the exit code is 3",
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
			usage:   "[-db FILE] [-format jsonl|urls|hosts|names|targets|openapi|graphql|sdl|burp|html|graphml|secrets] [-origin ORIGIN|URL] [-safe]",
			output:  "the chosen format; graphql: {\"data\":{\"__schema\":…}} of a GraphQL endpoint read with -graphql (keyed by URL when there are several; -origin picks one), sdl: its schema in GraphQL SDL, burp: the run's scope, allow rules as include and deny rules as exclude",
			examples: []string{
				"azhaq export -db app.db -format openapi > app.openapi.json",
				"azhaq export -db app.db -format graphql -origin https://app.example.com/graphql > schema.json",
				"azhaq export -db app.db -format sdl > schema.graphql",
				"azhaq export -db h1.db -format burp > scope.json",
				"azhaq export -db h1.db -format targets | nuclei -l -",
			}},
		{name: "ingest", group: groupWS, run: cmdIngest,
			summary: "add other tools' results to a database (subfinder, dnsx, httpx, katana, naabu, nuclei, gau and ffuf output, or connector facts)",
			usage:   "FILE… | -in FILE | - [-db FILE]",
			output:  "the map of what was added",
			examples: []string{
				"azhaq ingest httpx.jsonl katana.jsonl -db example.db",
				"subfinder -d example.com -json | azhaq ingest - -db example.db",
				"httpx -l hosts.txt -json | azhaq ingest -in - -db example.db && azhaq export -db example.db -format targets",
			}},
		{name: "ledger", group: groupWS, run: cmdLedger,
			summary: "check, count or export the record of every request and connection a run sent to a target",
			usage:   "-verify FILE | -summary FILE [-json] | -csv FILE",
			output:  "verify: entries and whether the hash chain is intact (exit 3, naming the first bad line, when not); summary: counts by kind, host, method and scope rule, first and last time; csv: one row per entry",
			examples: []string{
				"azhaq ledger -verify app.db.ledger.jsonl",
				"azhaq ledger -summary app.db.ledger.jsonl",
				"azhaq ledger -csv app.db.ledger.jsonl > sent.csv",
			}},
		{name: "resume", group: groupWS, run: cmdResume,
			summary:  "continue a run that was interrupted or stopped by a limit",
			usage:    "-db FILE [run flags to add, such as -cookie or -max-requests]",
			output:   "as run; a run that ports started prints the open ports it finds, as ports does (-json: objects; -quiet: the summary only), not the ones an earlier run printed",
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
			summary: "print the documentation: a page for each command, output fields, exit codes, connectors, MCP",
			usage:   "[TOPIC | COMMAND] | -flags COMMAND | -flags-into DIR",
			output:  "Markdown; -flags prints one command's flag table, -flags-into rewrites the flag tables of the pages in DIR",
			examples: []string{
				"azhaq docs output",
				"azhaq docs ports",
				"azhaq docs -flags ports",
				"azhaq docs -flags-into docs/commands",
			}},
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
	{exitUsage, "usage: bad flags or input (targets all outside the scope given too), nothing was sent"},
	{exitPartial, "finished, but some sources or requests failed: the results are usable, the summary on stderr lists what failed"},
	{exitLimit, "stopped by a limit (-max-requests, -timeout, -daily-requests, -max-items) or by the kill file (-kill-file) or by a signal (Ctrl-C, SIGTERM, SIGHUP) with work left: azhaq resume -db FILE continues"},
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
	case errors.Is(err, neterr.ErrBudget):
		return exitLimit // a resumable stop, wherever the budget ran out (a role's Chrome sign-in)
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
	return describe(c.run)
}

// describe reads the flags of a command function by calling it with -h.
func describe(run func([]string) error) *flag.FlagSet {
	wasDescribing, wasDescribed := describing, described
	describing, described = true, nil
	defer func() { describing = wasDescribing }()
	stdout, stderr := os.Stdout, os.Stderr
	null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err == nil {
		os.Stdout, os.Stderr = null, null
		defer func() { os.Stdout, os.Stderr = stdout, stderr; null.Close() }()
	}
	_ = run([]string{"-h"})
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
reach only the targets given, or the scope -allow or -scope names. azhaq
plan shows what a run would send.
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
		Output: "results on stdout (-json: JSONL); progress and a final summary on stderr (-json: one JSON object with \"type\":\"summary\"); azhaq docs COMMAND describes the fields of one command, azhaq docs output the shared contract"}
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
