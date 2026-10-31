# azhaq crawl

The URLs of an application: links, forms, scripts, routes in JavaScript, API descriptions. Replaces katana + jsluice (see [Migrating](../MIGRATING.md#katana-azhaq-crawl)).

## Synopsis

```
azhaq crawl -u URL | -l FILE | stdin  [-d N] [-fs rdn|fqdn|dn|REGEX] [-cs RE] [-cos RE] [-do] [-f FIELDS] [-em/-ef/-mr/-fr] [-jsonl | -json] [-rejected] [-submit-forms] [-rl N] [-silent]
```

## Examples

```
# Crawl three link levels deep, URLs only
azhaq crawl -u https://app.example.com/ -d 3 -silent

# katana's JSON lines, for tools that read them
azhaq crawl -u https://app.example.com/ -jsonl > crawl.jsonl

# Stay on the registrable domain, list URLs found outside it, print two fields, 5 requests a second
azhaq crawl -u https://app.example.com/ -fs rdn -do -f rdn,path -rl 5

# The map's rows, with the strings kept out of the URLs
azhaq crawl -u https://app.example.com/ -json -rejected
```

## What it does

1. Starts from the URLs you give and follows links to the depth `-d`: 3 link levels below the start URL by default, as katana does.
2. Reads forms, scripts and API descriptions for more URLs and routes. Library scripts are not read for routes.
3. Asks only what a crawler does. The built-in path checks of `run` are off unless you add `-sweep`.
4. Lists every page it asked and every URL it found, each distinct URL once.
5. Lists routes that scripts call with POST, PUT or another method. Their GET may answer 404 or 405.
6. Never drops links without a word. When a limit stops the crawl, it exits 4 and `azhaq resume` continues it.

## Output

`crawl` prints one URL per line, as katana does: pages, scripts and stylesheets. `-assets` adds images, fonts and media. [What is listed](#what-is-listed) says what that includes.

- `-json` prints one object per row, with the map's fields. `-jsonl` prints katana's lines instead.
- `-rejected` adds the strings that were kept out of the URLs, with the reason.
- `-f`, `-ot` and `-sf` print katana's field output ([Field output](#field-output)).

| Flag | Output |
| --- | --- |
| `-json` | One object per row: `url`, `coverage`, `role`, `status`, `methods`, `params`, `forms`, `found_in` and `tech` on a page. See below. |
| `-jsonl` (`-j`) | katana's lines, with a `request` and a `response`. See [Katana lines](#katana-lines). |
| `-f url,path,…` | Katana's URL fields, and `method`. See [Field output](#field-output). |
| `-rejected` | The strings kept out of the URLs, each with its reason. See [Rejected strings](#rejected-strings). |
| `-do` | The URLs found outside the crawl's scope, never asked. See [Links outside the scope](#links-outside-the-scope). |
| `-sr` | Each answer, written to `-srd DIR`. See [Saved responses](#saved-responses). |

The fields of a `-json` row are the map row's. [run](run.md#output) defines them. A view or a socket also has `guard`, `protocol` and `namespace`.

## Summary and exit codes

The summary and the exit codes are the shared ones: see [OUTPUT.md](../OUTPUT.md#exit-codes). The summary of a crawl:

- counts the rejected strings and the links outside the scope;
- names a host that answered 429 or 503, and what was done about it;
- counts both kinds of listed URL, and says where to look: routes that scripts call with other methods, and strings that scripts only name;
- says how many POST forms `-submit-forms` sent, and which POST forms it left alone and why.

A crawl never drops links without a word. When `-max-items`, `-max-requests`, `-mdp` or the run's `-timeout` stops it, the run exits 4 and `azhaq resume` continues it.

## Details

### What is listed

- One URL per line, as katana lists them: every page asked and every URL found, each distinct URL once.
- A link or a script's string with its query is its own line: `/catalog?category=Gin`, `/item?id=7`.
- `-per-template N` limits how many URLs of one template (`/item?id={n}`) are asked, not how many are listed.
- Every script and stylesheet a page loads or a script imports is listed, whether it was fetched or only found. This holds when it is in the crawl's scope. Examples are `/main.js`, `/styles.css` and a lazy `chunk-*.js`.
- `-json` is the map's rows. The extension list does not cut it. Its script and stylesheet rows are there by default, and an image's with `-assets`.
- `run`'s map lists every row, scripts and images included.
- Views (`client-route`) and sockets (`websocket`) are listed with `-json` only, as routes with a parameter are. No GET gets them.

### Filters

These filters limit what is printed, not what is crawled.

- Katana's default list is left out: images, fonts, archives, media, `.pdf`, `.txt` and `.map`.
- `-ndef` keeps them. `-ef php,bak` adds to the list.
- `-em php,html` lists only those extensions. `none` stands for URLs without one.
- `-mr` and `-fr` match the printed URL by regex.
- `-assets` brings back the images, fonts and media a page loads. It also lists the source maps and build manifests azhaq reads, which no page names.

### Routes called with other methods

- Routes that a script calls with POST, PUT or another method are listed too, as katana lists them: `/snippets/fixes`, `/logger`.
- They are not pages. A GET may answer 404 or 405.
- `-json` rows carry `methods` (`["POST"]`) and a `proof`: `GET answers 404; called with POST`.
- In plain output, `-ot '{{method}} {{url}}'` or `-f method,url` prints the methods. A route gets one line for each method. A page that no script calls another way gets `GET`.
- A string that a script only names, with no call, is listed when a GET fails. Its `proof` is `GET answers 404; found only in scripts, method unknown`.
- Library scripts are not read for routes: `react`, `jquery` and `angular`, also under a versioned name such as `angular_1-7-7.js`.

### Katana lines

`-jsonl` (`-j`) prints katana's line:

```json
{"timestamp", "request": {"method", "endpoint", "tag", "attribute", "source"},
 "response": {"status_code", "technologies", "forms": [{"method", "action", "enctype", "parameters"}], "content_length"},
 "error"}
```

- `tag` and `attribute` say where the URL was read: `img` `srcset`, `header` `link`, `form` `action`, `call`, `js`.
- `source` is the page.
- A URL that was found and not asked has no `response`.
- A route with other methods has a line for each.
- `azhaq ingest` reads these lines back.

### Field output

- `-f` prints these fields of the URL, as katana does: `url`, `path`, `fqdn`, `rdn`, `rurl`, `qurl`, `qpath`, `file`, `ufile`, `key`, `value`, `kv`, `dir` and `udir`.
- azhaq adds `method`: the methods the route is called with, one line each.
- `-ot '{{rdn}}{{path}}'` fills a template with the fields.
- `-sf key,dir -sfd DIR` writes the fields to `DIR/SCHEME_HOST_FIELD.txt`.
- `-lof` lists the field names.
- `-eof request.tag,tech` leaves fields out of `-json` and `-jsonl`.

### Rejected strings

- `-rejected` lists the strings read from scripts and pages and kept out of the URLs. They are never asked.
- Text output is `string`, a tab, and the reason.
- `-json` output is `{"rejected", "reason", "url", "source", "via"}`. `url` is what the string makes against the page.

### Links outside the scope

- `-do` lists the URLs found outside the crawl's scope. They are never asked.
- Text output is the URL.
- `-json` output is `{"url", "coverage":"out-of-scope", "source", "tag", "attribute"}`.

### Saved responses

- `-sr` writes each answer to `-srd DIR` (`katana_response`) as `HOST/SHA1.txt`.
- A file holds the URL, the request line, the status line, the headers and the body. `-ob` leaves the body out.
- `DIR` also gets an `index.txt`.

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
