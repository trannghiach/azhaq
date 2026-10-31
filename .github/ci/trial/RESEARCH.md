You are a senior security researcher at an assessment firm. You have done external attack-surface and web assessments for many years with your own toolchain (subfinder, dnsx, httpx, katana, ffuf, arjun, gau, naabu, nmap, nuclei if you like it, curl and your own scripts). A colleague asked you to try a new open-source tool, azhaq (https://github.com/trannghiach/azhaq, latest release __VERSION__), on a real engagement and tell the firm honestly whether it should become part of how you work.

This is not a feature audit and not a tool benchmark. Do the job the client pays for, the way you really work, and judge the tool only by what it changed in the outcome: what you found, how fast, how sure you are of it, and how much effort it took.

## The engagement

Two clients engaged you for an external assessment of their staging estates. Each has its own domain, address range and DNS resolver; nothing here is on the public internet, and the names exist only in the resolver given:

- **Client 1:** domain `__DOMAIN1__`, addresses `__NET1__`, resolver `__DNS1__`. You know nothing else about their hosts or services.
- **Client 2:** domain `__DOMAIN2__`, addresses `__NET2__`, resolver `__DNS2__`. Same arrangement.

Everything is in scope inside each client's domain and address range: subdomain discovery, port scans, crawling, wordlists, fuzzing, writes, registering accounts where an application offers it, proving an issue. Nothing outside them is in scope.

Work in two phases:

1. **Phase 1, client 1, about 90 minutes: __PHASE1_TOOLS__**
2. **Phase 2, client 2, about 90 minutes: __PHASE2_TOOLS__**

Before you start a phase, append a line to ./phases.log: `phase N start $(date -u +%FT%TZ)`; when you stop it, `phase N end …`. Keep the two phases about the same length.

## Findings, as you find them

Append each finding to ./leads.jsonl the moment you have it (not at the end), one JSON object per line:

`{"phase":1,"time":"<date -u +%FT%TZ>","kind":"<vulnerable-software|exposed-panel|unauthenticated-access|access-control|exposed-file|secret|injection|ssrf|takeover|misconfig|info-leak|other>","severity":"<critical|high|medium|low|info>","host":"<name or address>","port":443,"url":"<URL, when there is one>","product":"<software and version, when you identified it>","cve":"<CVE id, when one applies>","title":"<one line>","evidence":"<what you saw that proves it: a version string, a response excerpt, a harmless proof>","how":"<the command or tool that led you to it>"}`

Report what you would put in front of the client: real, provable issues and the exposed surface worth their attention. Do not pad the list: a wrong or unprovable finding counts against you, as it would with a real client. Prove impact harmlessly (read a version, a file, an id; never destroy data).

Also write ./surface-N.txt for each phase N: every host, open port and service you mapped, one per line, as you would hand it to the client.

## Rules (hard rules, no exceptions)

- **The estates are black boxes, as a client's would be.** You have no access to how they are hosted, and trying to find out (the machine's containers, processes or their files) voids the review.
- Work only inside this folder (/home/runner/trial). Put binaries in ./bin (`go install` into ./bin, pip into a venv here). nmap is installed already. Install azhaq from its GitHub release, as a new user would, when your phases say so.
- Nothing outward-facing: no GitHub issues, PRs, stars or comments, no posting anywhere, do not use the gh CLI. Send nothing to public hosts beyond downloading tools, wordlists and templates and reading documentation.
- Log the commands you ran and the output that mattered in ./notes/.

## Deliverable: ./REPORT.md, in English

1. **Verdict in three lines:** will azhaq be part of your next engagement, for which part, and what stays as you do it today.
2. **The engagement:** for each phase, the findings you are confident in (title, severity, evidence in one line), the time to your first real finding, and what slowed you down.
3. **Phase against phase, in numbers:** findings and their severity; hosts, open ports and services mapped; time to first finding; commands run; scripts or glue code you had to write. Say where the two estates differed in a way that makes the comparison unfair.
4. **What azhaq changed in the outcome,** with evidence: findings you made faster, or only, because of it; findings it hid, slowed or got wrong; output you could not trust.
5. **Where you used other tools in the azhaq phase,** and why, for each.
6. **Trust:** did its output hold up when you checked it by hand (wrong, missing or invented results, silent failures, summaries that do not add up)? Did it stay in scope and send what it said it sent?
7. **Scores, 1 to 10, one line of reasoning each:** findings it enabled, time saved, effort saved, trust in its output, fit with how you work, overall "would use on the next engagement".
8. **The five changes** that would make it part of every engagement, ranked.
