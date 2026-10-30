You are a senior security engineer deciding whether to adopt an open-source reconnaissance and attack-surface-mapping tool, azhaq (https://github.com/trannghiach/azhaq, latest release __VERSION__), for authorized assessment work. You do this kind of discovery every day and trust a stack of established tools (subfinder, dnsx, httpx, katana, ffuf, arjun, gau, naabu, nmap, gowitness). azhaq claims it can replace that stack, adds capabilities none of those tools have, and is safe to drive through an AI assistant.

Your review must be independent and evidence-based. You decide only on what you measure yourself, never on what the tool or its documentation says about itself. Be blunt and specific; a polite or credulous review is useless to its author.

## Core principle: verify everything, assume nothing

- **Trust nothing the tool states about itself.** Treat every claim in its README, `-h`, shipped docs and its own run summaries as a hypothesis to confirm or refute by independent measurement. If you cannot confirm a claim with your own evidence, record it as **unverified** and do not count it in the tool's favour.
- **Establish ground truth yourself first.** Decide what "correct" means from the target itself: the application's responses, its source code (the local apps' source is inside their containers; `docker cp` from them is allowed, read-only), independent DNS resolution, and an independent proxy log. Then run the established reference tools head-to-head on the same targets.
- **Install and run the reference tools.** Use `go install` into ./bin or pip into a venv here, and measure counts, overlap, wall time, memory, and wrong, duplicate, missing or invented results on both sides. Do not describe a comparison you did not run.
- **Test the tool's own framings; do not accept them.** Where azhaq argues a metric should be read its way, test that argument on several targets.
- **Look hard for wrong or misleading output and silent failures.** Check exit codes against their documented meaning. Check that summary numbers add up.

## Coverage rules (these bind your scores)

- Exercise every capability on the checklist below, or say in the report why you could not.
- **An area cannot score above 6** if you did not exercise its listed capabilities. Mark each untested capability **untested**, not as passed.
- **A safety claim that proves false** caps that area at 5 and the overall at 7. Safety claims are: scope enforcement, GET-only mapping by default, state-changing requests skipped, the MCP lock, the request budget, the ledger matching what was sent, and the kill switch.
- Checklist:
  - **Subdomains:** passive collection, live filtering, wildcard handling, takeover candidates, the coverage estimate.
  - **DNS:** resolution and brute force.
  - **Hosts and ports:** TCP connect scan, UDP scan, service and version detection, probing at scale.
  - **Web and API:** crawling, JavaScript routes, API descriptions, GraphQL, path fuzzing with filters, parameter discovery, screenshots, archived URLs.
  - **Signed-in and multi-role:** sign-in, role comparison (read replay), write replay, the proxy-history matrix (HAR import), report generation.
  - **Prioritisation:** `hunt`.
  - **Monitoring:** `watch` with a deploy that changes routes, `diff`, notifications.
  - **Integration:** exports, ingest, the MCP server.
  - **Engagement controls:** request ledger and its verification, kill switch, resume.
  - **Install:** release verification, the install script.

## How to work

- Work only inside this folder (/home/runner/trial). Put binaries in ./bin.
- Install azhaq the way a new user would: from the GitHub release, verifying what the release lets you verify.
- Call the binary you installed by its path (./bin/azhaq).
- Read its README, `-h` and shipped docs to learn what it offers, but treat every statement as a claim to test. Read its source on GitHub only to resolve a discrepancy, and say when you did.
- Log every command you ran and the output that matters in ./notes/.
- Aim to finish within about three hours of wall time.

## Scope and rules (hard rules, no exceptions)

- **Local training apps.** You are authorized to test these, and they are disposable, so **anything is allowed on them, including writes** (POST, PUT, PATCH, DELETE), registration and multi-account tests:
  - OWASP Juice Shop at http://127.0.0.1:3001/
  - VAmPI at http://127.0.0.1:5002/
  - DVGA at http://127.0.0.1:5013/
  - DVNA at http://127.0.0.1:5020/
  - DVWA at http://127.0.0.1:5030/ (its default accounts work, e.g. admin / password)

  To reset one of these apps, you may run `docker restart` on its container: azq-juice, azq-vampi, azq-dvga, azq-dvna, azq-dvwa. Never touch any other container.
- **Local DNS lab.** A resolver at 127.0.0.1:5354 serves the zone azqlab.lan: real names, a wildcard subzone and dangling CNAMEs. It forwards every other name to a public resolver. Use it for wildcard and takeover tests, with `-resolvers` or each tool's equivalent.
- **Public applications published for tool testing,** at low rate only: ginandjuice.shop, *.vulnweb.com (for example testphp.vulnweb.com), demo.testfire.net.
- **Port discovery:** only scanme.nmap.org and 127.0.0.1.
- **Privileged steps:** you may run exactly one command with sudo, `sudo apt-get install -y nmap`, to use nmap as a reference tool. Nothing else with sudo.
- **The public programs hackerone.com and tesla.com,** which publish an invitation for exactly this kind of review:
  - passive lookups (subdomain sources, certificates, archives);
  - probing the web services of the live hosts in their published scope, with at most one low-rate GET per host per tool.

  No port scans, no wordlist runs and no crawling against them.
- **No payloads at public targets.** Keep your evaluation of public targets to discovery, mapping and comparison.
- **Wordlist-based path and parameter discovery** only on the local apps and the public test sites (low rate on the latter).
- **Change nothing outside this folder** (apart from the lab resets allowed above).
- **Nothing outward-facing:** no GitHub issues, PRs, stars or comments, no posting anywhere, and do not use the gh CLI.

## Deliverable: ./REPORT.md, in English

1. **Verdict in three lines:** would you adopt it, for what, and what would you keep using instead.
2. **Scorecard, 1 to 10, one line of reasoning each:** install and first run, docs, subdomain recon, host and port discovery, web and API mapping, signed-in and multi-role testing, output and integration (including assistants), reliability (crashes, hangs, wrong data, silent failures), speed and resources, overall. Score only on what you measured, under the coverage rules above.
3. **Coverage table:** each checklist capability marked tested (with the note file), untested (why), or failed.
4. **What genuinely impressed you,** with evidence you produced: command plus output excerpt, and the ground-truth or reference result it was checked against.
5. **What broke, misled or annoyed you:** exact command, expected versus actual. Tag each one: bug, doc gap, missing feature or design disagreement.
6. **Claims checked:** for each notable claim, your verdict (true, partly true, false or unverified) and the independent evidence.
7. **Head-to-head numbers** against the tools you compared it with, under the same conditions, including where azhaq loses.
8. **Tools you would still keep:** a list. For each tool, the specific job azhaq cannot yet do as well, and the evidence.
9. **The ten changes** that would make you use it daily, ranked.
10. **Who this tool is for,** and who it is not for.
