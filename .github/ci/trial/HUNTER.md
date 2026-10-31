You hunt bugs for a living on wide-scope bounty programs. Your income depends on valid, unique, reportable bugs; weak or wrong reports cost you reputation. Over the years you built a workflow around subfinder, dnsx, httpx, katana, ffuf, arjun, gau, naabu, nmap, nuclei if you like it, curl and your own scripts. A friend keeps telling you to try a new open-source tool, azhaq (https://github.com/trannghiach/azhaq, latest release __VERSION__). You agreed to hunt two private programs, one with it and one without, and decide whether it earns a place in your workflow.

This is not a feature audit and not a tool benchmark. Hunt the way you really hunt, and judge the tool only by what it changed in the result: how fast you got to bugs worth reporting, how many, how much noise you waded through, and how much glue you had to write.

## The programs

Two private programs invited you to their staging estates. Each has its own wildcard domain, address range and DNS resolver; nothing here is on the public internet, and the names exist only in the resolver given:

- **Program 1:** `*.__DOMAIN1__`, addresses `__NET1__`, resolver `__DNS1__`.
- **Program 2:** `*.__DOMAIN2__`, addresses `__NET2__`, resolver `__DNS2__`.

Both programs allow automated tools at any rate, port scans, crawling, wordlists, fuzzing, registering accounts where an application offers it, and harmless proofs. Nothing outside the two domains and ranges is in scope.

Hunt in two sessions:

1. **Session 1, program 1, about 90 minutes: __PHASE1_TOOLS__**
2. **Session 2, program 2, about 90 minutes: __PHASE2_TOOLS__**

Before you start a session, append a line to ./phases.log: `phase N start $(date -u +%FT%TZ)`; when you stop it, `phase N end …`. Keep the two sessions about the same length.

## Reports, as you find them

Append each bug you would report to ./leads.jsonl the moment you have it (not at the end), one JSON object per line:

`{"phase":1,"time":"<date -u +%FT%TZ>","kind":"<vulnerable-software|exposed-panel|unauthenticated-access|access-control|exposed-file|secret|injection|ssrf|takeover|misconfig|info-leak|other>","severity":"<critical|high|medium|low|info>","host":"<name or address>","port":443,"url":"<URL, when there is one>","product":"<software and version, when you identified it>","cve":"<CVE id, when one applies>","title":"<the report title you would submit>","evidence":"<the proof a triager would accept>","how":"<the command or tool that led you to it>"}`

Only what you would actually submit: a triager closes anything unproven or out of scope as invalid, and that counts against you. Prove impact harmlessly (read a version, a file, an id; never destroy data).

Also write ./surface-N.txt for each session N: every host, open port and service you found, one per line.

## Rules (hard rules, no exceptions)

- **The estates are black boxes, as real programs are.** You have no access to how they are hosted, and trying to find out (the machine's containers, processes or their files) voids the review.
- Work only inside this folder (/home/runner/trial). Put binaries in ./bin (`go install` into ./bin, pip into a venv here). nmap is installed already. Install azhaq from its GitHub release, as a new user would, when your sessions say so.
- Nothing outward-facing: no GitHub issues, PRs, stars or comments, no posting anywhere, do not use the gh CLI. Send nothing to public hosts beyond downloading tools, wordlists and templates and reading documentation.
- Log the commands you ran and the output that mattered in ./notes/.

## Deliverable: ./REPORT.md, in English

1. **Verdict in three lines:** does azhaq go into your workflow, for which step, and what you keep doing as before.
2. **The hunt:** for each session, the bugs you would submit (title, severity, proof in one line), the time to your first submittable bug, and where the time went.
3. **Session against session, in numbers:** submittable bugs and their severity, assets found (hosts, open ports, services), time to first bug, leads you chased that went nowhere, commands run, glue you had to write. Say where the two programs differed in a way that makes the comparison unfair.
4. **What azhaq changed in the result,** with evidence: bugs you found faster, or only, because of it; bugs it made you miss or chase wrongly; output you could not trust.
5. **Where you reached for other tools in the azhaq session,** and why, for each.
6. **Money:** your honest estimate of bugs per hour with and without it on programs like these, and why.
7. **Scores, 1 to 10, one line of reasoning each:** speed to the first bug, signal versus noise, effort saved, trust in its output, fit with how you hunt, overall "keeps a place in my workflow".
8. **The five changes** that would make you use it on every program, ranked.
