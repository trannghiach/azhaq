You are hunting for bugs in azhaq (a Go recon CLI) before its next release is tagged. A blind reviewer will soon judge it head-to-head against subfinder, dnsx, httpx, katana, ffuf, arjun, gau, naabu, nmap and gowitness, and will score it down for any wrong result, false claim, silent failure, or a run that is slower or finds less than the reference tool. Find those first. Use the tool the way a skeptical security engineer would. Check what it says against independent evidence: a logging proxy, curl, dig, the lab apps' own state, and the reference tool run on the same target with the same settings. Report anything wrong, misleading, slower or silently incomplete. Be adversarial.

Do not read azhaq's Go source and do not review diffs: judge only by behaviour, as the reviewer will. You may read README.md, CHANGELOG.md (the newest sections are the claims of this release) and docs/*.md under /home/runner/work/azhaq/azhaq, which are the claims to test. Change nothing there.

## Setup

- Binary: /home/runner/hunt/bin/azhaq, built from the commit under test. `help`, `help COMMAND`, `docs` and `docs migrating` describe everything.
- Work only in your own folder, /home/runner/hunt/AREA/, where AREA is given below.
- Reference tools, ready to run, in /home/runner/ref/bin/: subfinder, dnsx, httpx, katana, ffuf, gau, naabu, gowitness, notify, jsluice and arjun. nmap is installed (`nmap`); run it without sudo (`-sT -sV`).
- Independent request log: `python3 -I /home/runner/work/azhaq/azhaq/bench/truth/ledger/countproxy.py LISTEN_PORT TARGET_PORT LOG.jsonl` is a reverse proxy that logs every request as it arrives (method, and path with query). Run it in the background on a free port, put it in front of a lab app, and point azhaq at the proxy port. Do not edit it.
- This machine is yours alone: no other reviewer shares the labs.

## Allowed targets (hard rules)

- **Local lab apps.** Anything is allowed here, including writes:
  - Juice Shop 127.0.0.1:3001
  - VAmPI 127.0.0.1:5002
  - DVGA 127.0.0.1:5013
  - DVNA 127.0.0.1:5020
  - DVWA 127.0.0.1:5030 (admin / password)

  You may `docker restart` only these containers: azq-juice, azq-vampi, azq-dvga, azq-dvna, azq-dvwa.
- **Services lab on 127.0.0.1.** These are `azq-svc-*` containers; read-only probing only, never restart them. Ports:

  | Service | Port |
  |---|---|
  | ssh | 12222 |
  | ftp | 10021 |
  | smtp | 10025 |
  | mail web | 18825 |
  | smb | 10445 |
  | memcached | 21211 (TCP and UDP) |
  | elasticsearch | 19200 |
  | redis | 16379 |
  | snmp | 10161/udp |
  | mqtt | 11883 |
  | postgres | 15432 |
  | mariadb | 13306 |
  | amqp | 15682 |
  | mongo | 17017 |
  | dns | 10053 (TCP and UDP) |
  | ldap | 10389 |
- **Local DNS lab:** resolver 127.0.0.1:5354, zone azqlab.lan: real names, a wildcard subzone (*.wild.azqlab.lan), dangling CNAMEs, MX, TXT, NS, SRV, CAA, SOA and AAAA records, a reverse zone for 127.0.0.0/24 and a zone transfer. It forwards other names to 1.1.1.1.
- **Public test sites, at low rate:** ginandjuice.shop, testphp.vulnweb.com, demo.testfire.net. Low-rate wordlists are allowed there.
- **Ports:** only 127.0.0.1 and scanme.nmap.org. Scan scanme at most twice, top-1000 at most.
- **Passive lookups** (subs, urls) on hackerone.com, tesla.com and vulnweb.com: at most two runs per tool per domain. `subs -live` resolves names; that is allowed.
- **Never** crawl, run wordlists against or port-scan any other public host.
- Nothing outward-facing: no GitHub, no posting.
- Aim to finish within about 60 minutes of wall time.

## Native features this round

Evaluators score what they try, and some of azhaq's strongest features are the ones nobody tries. Use each of these at least once, on the lab where it applies, and report in FINDINGS.md whether it worked and what it found, compared with doing the same by hand or with the reference tool (same target, same settings, counted by independent evidence):

- `subs -permute` and `run -permute`: the DNS lab (`-resolvers 127.0.0.1:5354`, zone azqlab.lan). Which names did the variations find that the sources did not give? Check each with `dig`.
- `run -browser -interact` and `crawl -browser -interact`: Juice Shop. Which routes did the clicks find that `-browser` alone and katana did not? Does the summary's `-interact:` note match what the proxy log shows was sent? No write may leave.
- `fuzz -preflight` with `-preflight-var-auto` (and `-postflight`): the DVWA login, which has a CSRF token. Does it find the right password where a copied token fails? Compare with ffuf in a loop that fetches the token by hand.
- `run -dirs`, `run -params`, `run -ports`, `run -screenshots`: each against the same job done by `dirs`, `params`, `ports`, `shots` or by the reference tool (ffuf, arjun, naabu, gowitness) on one lab. Are the results the same? Is the run slower or heavier?
- `run -stream`: are the found lines printed before the map, and are they the same as the map's rows?

## How to judge

- **The parity bar azhaq claims:** results at least the reference tool's, and time no slower, both at default settings and at a polite pace (`-rate 2` to `5` for HTTP, `-dns-rate 5` to `10` for DNS, with the reference tool's equivalent flag). Check it on your area's commands. Measure wall time with `/usr/bin/time -v`.
  - If azhaq finds fewer true results or is slower beyond noise (run twice), that is a finding. Give both commands and numbers.
  - Known and intended, not a finding: under `-rate` (and `-dns-rate`), azhaq paces every request, the calibration guesses of `dirs` and `fuzz -ac` included; ffuf sends its calibration unpaced. At `-rate 5` a sweep is therefore about (guesses ÷ rate) seconds longer than ffuf's (4–6 guesses: about one second), and azhaq never exceeds the rate. Report it only if the gap is larger than that, or if azhaq is slower at default settings (no `-rate`). The same holds for any reference tool whose rate flag does not hold back every request it sends: measure what each tool actually sends per second before calling azhaq slower.
  - If azhaq finds more, check that the extra results are real.
- **Exit codes:** 0 complete, 1 error, 2 usage, 3 some failures, 4 stopped by a limit. Check them against `help`. A summary whose numbers do not add up is a finding.
- **Safety claims:** scope (including a `Host` header or anything else that names a host), GET-only default, ledger equals what was sent, budget, kill switch, `-proxy` carrying every request, and the MCP lock. Any break is critical.
- **MIGRATING.md:** check that a flag it maps does what the reference tool's flag does.

## Report

Write FINDINGS.md in your folder.

For each finding give:
- **Severity.**
  - critical: a safety claim is false.
  - high: wrong data, a silent failure, or worse than the reference tool on results or time.
  - medium: a misleading message or doc.
  - low.
- **The exact commands,** azhaq's and the reference tool's.
- **Expected versus actual,** with the independent evidence.

Then list, one line each, the claims you checked and found true, with the evidence. Do not pad: no finding is better than an invented one.
