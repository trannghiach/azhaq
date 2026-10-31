# azhaq crawl

The URLs of an application: links, forms, scripts, routes in JavaScript, API descriptions. Replaces katana + jsluice (see [Migrating](../MIGRATING.md#katana-azhaq-crawl)).

## Synopsis

```
azhaq crawl -u URL | -l FILE | stdin  [-d N] [-fs rdn|fqdn|dn|REGEX] [-cs RE] [-cos RE] [-do] [-f FIELDS] [-em/-ef/-mr/-fr] [-jsonl | -json] [-rejected] [-submit-forms] [-rl N] [-silent]
```

## Examples

```
azhaq crawl -u https://app.example.com/ -d 3 -silent
azhaq crawl -u https://app.example.com/ -jsonl > crawl.jsonl
azhaq crawl -u https://app.example.com/ -fs rdn -do -f rdn,path -rl 5
azhaq crawl -u https://app.example.com/ -json -rejected
```

## Output

One URL per line (pages, scripts and stylesheets; -assets adds images, fonts and media); -jsonl: katana's {"request","response"} lines; -json: {"url","coverage","role","status","methods","params","forms","tech"} (routes a script calls with POST are listed, and their GET may answer 404 or 405: -json has methods, -ot '{{method}} {{url}}' prints them); -rejected adds the strings kept out of the URLs, with the reason.

## Summary and exit codes

The summary and the exit codes are the shared ones: see [OUTPUT.md](../OUTPUT.md#exit-codes).

## Flags

<!-- flags:begin crawl -->
| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-H` | string, repeatable |  | extra request header K: V |
| `-allow` | string, repeatable |  | a domain, host or address range the run may touch; with any -allow, nothing else is requested |
| `-assets` | bool |  | also list images, fonts and media, and the source maps and build manifests azhaq reads (scripts and stylesheets are listed by default, as katana lists them) |
| `-backoff` | bool |  | when a host answers 429 or 503, wait (1 s doubling to 30 s, or its Retry-After) and ask again, up to 3 times; the summary says which hosts did |
| `-browser` | bool |  | also load pages in Chrome: the requests their scripts send and the links of the rendered page (needs Chrome) |
| `-browser-writes` | bool |  | let pages in Chrome send their writes (POST, PUT, DELETE…, beacons, forms posted on load) as a user's browser would: they change data on the target; by default Chrome sends only GET, HEAD and OPTIONS outside signing in, and maps the writes it does not send |
| `-c` | int |  | requests in flight per host (default 10, as katana) |
| `-cookie` | string, repeatable |  | Cookie name=value (repeatable; sent as one Cookie header) |
| `-cookie-jar` | bool |  | carry the cookies targets set (Set-Cookie) on the requests that follow, as a browser does; -cookie and -H values go first |
| `-cos` | string, repeatable |  | never follow URLs that match this regex |
| `-cs` | string, repeatable |  | follow only URLs that match this regex |
| `-ct` | duration |  | stop after this long and keep what was found; azhaq resume continues (0: no limit) |
| `-d` | int | `-1` | katana's -d: link levels below the start URL to visit (3 by default); -depth N is -d N-1 |
| `-db` | string |  | keep the graph in this database for query, show, export and diff (default: a temporary one) |
| `-delay` | duration |  | pause before each uncached fetch |
| `-deny` | string, repeatable |  | a domain, host or address range the run must not touch, even when given as a target |
| `-depth` | int | `4` | max fan-out waves (0 = seed wave only, not unlimited) |
| `-do` | bool |  | also list the URLs found and left out of the crawl's scope (never requested) |
| `-dr` | bool |  | do not follow redirects: each URL is asked once and its redirect recorded with the Location (httpx's default) |
| `-duc` | bool |  | accepted for katana's command lines; azhaq always reads scripts, forms and technologies |
| `-ef` | string |  | leave out URLs with these extensions, comma-separated, besides the default list (images, fonts, archives, media, .pdf, .txt, .map, …) |
| `-em` | string |  | list only URLs with these extensions, comma-separated (none: URLs without one) |
| `-eof` | string |  | leave these fields out of -json and -jsonl lines, comma-separated (request.tag, response.forms, tech, …) |
| `-f` | string |  | print these fields of each URL instead of the URL, comma-separated: url,path,fqdn,rdn,rurl,qurl,qpath,file,ufile,key,value,kv,dir,udir,method (katana's -f) |
| `-fill-forms` | bool |  | ask the action of each GET form with neutral values in its fields (a search box gets a word): one request per form, GET only |
| `-fr` | string |  | leave out URLs that match this regex (printed URLs only) |
| `-fs` | string |  | the hosts a crawl follows links to: rdn (the start host's registrable domain and its subdomains), fqdn (the host only), dn (hosts that name its domain keyword) or a regex on the host (default: rdn for a name, the origin itself for an address) |
| `-fx` | bool |  | accepted for katana's command lines; azhaq always reads scripts, forms and technologies |
| `-host-parallel` | int |  | requests in flight per host (default 10, as katana) |
| `-host-rate` | float |  | requests per second to each host, besides -rate over all (0: none) |
| `-hrl` | int |  | requests per second to each host (katana's -hrl) |
| `-hrlm` | int |  | requests per minute to each host (katana's -hrlm) |
| `-interact` | bool |  | with -browser: click the buttons, links and menus of each page (up to -interact-clicks) to find what only a click brings; writes a click would send are mapped, not sent, and a click on log out, delete, … is not made |
| `-interact-clicks` | int | `12` | clicks -interact makes on each page |
| `-iqp` | bool |  | ask one URL of each path whatever its query values (katana's -iqp; the others are listed) |
| `-j` | bool |  | same as -jsonl |
| `-jc` | bool |  | accepted for katana's command lines; azhaq always reads scripts, forms and technologies |
| `-jsl` | bool |  | accepted for katana's command lines; azhaq always reads scripts, forms and technologies |
| `-json` | bool |  | JSONL output, and the summary as one JSON object on stderr |
| `-jsonl` | bool |  | katana's JSON lines: {timestamp, request{method, endpoint, tag, attribute, source}, response{status_code, technologies, forms, content_length}, error} |
| `-kb` | bool |  | accepted for katana's command lines; azhaq always reads scripts, forms and technologies |
| `-kf` | string |  | ask each web service only for its robots.txt and sitemaps and read every entry (all, robotstxt or sitemapxml); replaces the 32 built-in paths |
| `-kill-file` | string |  | stop all sending, at once, when this file exists, and exit 4; azhaq resume works once it is removed (default DB.stop) |
| `-l` | string |  | file of start URLs (- for stdin) |
| `-ledger` | string |  | write every request and connection to a target to this file, a chain of hashes that azhaq ledger -verify checks (default DB.ledger.jsonl next to the workspace; off: none; with a temporary database, only when given) |
| `-lof` | bool |  | list the fields -f, -sf and -ot take, and the fields of -jsonl lines, and exit |
| `-login` | string |  | sign in on this page with Chrome before the run; its cookies and token go with every request (needs -login-user and -login-pass) |
| `-login-pass` | string |  | password for -login (default $AZHAQ_LOGIN_PASS) |
| `-login-user` | string |  | user name or email for -login |
| `-max-host-requests` | int |  | requests one host may be sent (0: no cap); the rest of its work is left for azhaq resume |
| `-max-items` | int |  | max collector invocations (default 2048) |
| `-max-requests` | int |  | requests to targets this run may send (0: no cap); the work left over is for azhaq resume |
| `-max-response-size` | int |  | bytes read of a page or document (default 2097152; scripts and JSON get 16 MiB) |
| `-mdp` | int |  | requests one host may be sent, then its work is left for resume (katana's -mdp) |
| `-mr` | string |  | list only URLs that match this regex (regex of the printed URL; the crawl itself is not limited) |
| `-mrs` | int |  | bytes read of a page (katana's -mrs; default 2 MiB, scripts and JSON 16 MiB) |
| `-nc` | bool |  | accepted for katana's command lines; azhaq always reads scripts, forms and technologies |
| `-ndef` | bool |  | do not leave out the default extensions |
| `-no-catchall` | bool |  | leave out URLs that answer with the page every unknown path gets (client-side routes of a single-page app) |
| `-no-follow` | bool |  | do not follow redirects: each URL is asked once and its redirect recorded with the Location (httpx's default) |
| `-no-form-fill` | bool |  | do not ask the action of GET forms with neutral values |
| `-no-map-guess` | bool |  | do not ask for main.js.map next to a script that names no source map (a map a script or a header names is still read) |
| `-ns` | bool |  | follow links to any host, within -allow and -deny (katana's -ns) |
| `-o` | string |  | also write results to this file |
| `-ob` | bool |  | with -sr: write the status line and headers only |
| `-ot` | string |  | print each URL through this template, {{url}} or any field name in braces ({{rdn}} {{path}} …) |
| `-p` | int |  | work items in flight (default 16) |
| `-parallel` | int |  | work items in flight (default 16) |
| `-path-climb` | bool |  | also list and ask the parent directories of each link a page names (/a/b/c: /a/b/ and /a/) |
| `-paths` | string |  | extra path wordlist (one path per line) |
| `-pc` | bool |  | same as -path-climb (katana's -pc) |
| `-per-template` | int |  | URLs of one template (/product?id={n}) to request; the rest are listed (default 3) |
| `-program` | string |  | the program to take from a -scope list (handle, name or URL) |
| `-proxy` | string |  | send requests to targets through this proxy (http://, https:// or socks5://); Chrome too (default: $HTTP_PROXY, $HTTPS_PROXY) |
| `-r` | string |  | DNS resolvers: a file with one per line, or a comma list; each is ADDR, ADDR:PORT or udp:, tcp:, dot:, doh:URL[:get] and then the address (default: public resolvers) |
| `-rate` | float |  | requests per second to targets, over all hosts (0: no pace) |
| `-rd` | int |  | seconds to wait before each request (katana's -rd) |
| `-rejected` | bool |  | also list the strings read from scripts and pages and kept out of the URLs, each with its reason (text: string, a tab, the reason; -json: one object each) |
| `-request-timeout` | duration |  | time one request gets, headers and body (default: 10 s for headers, 30 s in all; not -timeout, the run's bound) |
| `-resolvers` | string |  | DNS resolvers: a file with one per line, or a comma list; each is ADDR, ADDR:PORT or udp:, tcp:, dot:, doh:URL[:get] and then the address (default: public resolvers) |
| `-retry` | int |  | ask again this many times when a host that answered before gives no answer (a timeout, a reset) |
| `-rl` | float |  | requests per second to targets, over all hosts (0: no pace) |
| `-rlm` | int |  | requests per minute over all hosts (katana's -rlm) |
| `-s` | string |  | accepted for katana's command lines; azhaq orders its work by worth within a host, not by -s depth-first or breadth-first |
| `-scope` | string |  | a program's scope: a file (HackerOne CSV, bounty-targets JSON, Burp options, lines) or hackerone, bugcrowd, intigriti, yeswehack |
| `-sf` | string |  | also write these fields, one file each, to the -sfd directory: katana_field/SCHEME_HOST_FIELD.txt |
| `-sfd` | string | `katana_field` | directory for -sf |
| `-silent` | bool |  | results only: no progress; the summary only when something failed (a source that failed, a takeover candidate as a [takeover] line on stderr); stdout stays one result per line |
| `-sr` | bool |  | also write each answer kept in the workspace to the -srd directory, DIR/HOST/SHA1.txt, with an index.txt (katana's -sr) |
| `-srd` | string | `katana_response` | directory for -sr |
| `-submit-forms` | bool |  | also submit POST forms with neutral values (crawl): CHANGES DATA on the target, each submission counts as a request and is in the ledger, the summary says how many; held to -allow, -deny and the crawl's scope |
| `-sweep` | bool |  | also ask each web service for the 32 built-in paths (robots.txt, sitemaps, API descriptions, .git/HEAD, admin, …) and for the source map next to each script, as run does; crawl asks only what a crawler does |
| `-td` | bool |  | accepted for katana's command lines; azhaq always reads scripts, forms and technologies |
| `-timeout` | duration |  | stop after this long and keep what was found; azhaq resume continues (0: no limit) |
| `-u` | string, repeatable |  | start URL (repeatable, or comma-separated) |
| `-v` | bool |  | print a line for every finished task, not only failures |
<!-- flags:end -->
