# Workflow trials

`trial.yml` runs three kinds. The first line of the tag's message picks one;
`.github/ci/run.sh trial NAME KIND` writes it.

| Kind | What happens | Brief |
| --- | --- | --- |
| `switch` (default) | A blind review of the latest release against five training apps. | `BRIEF.md` |
| `research` | A researcher does two phases of an engagement on two fresh estates. Phase 1, estate 1: usual tools only, azhaq not installed. Phase 2, estate 2: azhaq installed from its latest release and used as the main tool; every fallback to another tool is logged with its reason. | `RESEARCH.md` |
| `hunter` | The same estates as two bounty sessions, in the opposite order: azhaq first, the usual stack second with azhaq off. | `HUNTER.md` |

```
.github/ci/run.sh trial 11 research            # tag trial-11, kind research
.github/ci/run.sh trial 12 hunter seed=lilac   # the same, with a fixed draw
.github/ci/fetch.sh trial trial-11 /tmp/t11    # copies, decrypts and unpacks
python3 .github/ci/range/grade.py /tmp/t11/key.json /tmp/t11
```

Without `seed=` the draw is a keyed hash of the tag, so the public catalog and
the public tag name do not give the estates away. A fixed seed is readable in
the tag.

## The estates

Both are built from Vulhub (MIT), pinned to the commit in
`.github/ci/range/catalog.json`. `build.py` draws two disjoint estates of ten
environments each with the same category mix and a memory budget for both
together. Each has a random `.test` domain, a /24 of loopback, one address per
host, product-named and neutral host names (some under a `dev.` or `stg.`
subzone, sometimes with a wildcard), a few services on non-default ports, three
names served only by an nginx reverse proxy by Host, two dangling CNAMEs and
PTR records for some hosts. One `bench/labdns` resolver per estate serves its
zone (`-zone`): 127.0.0.1:5301 and 127.0.0.1:5302. `up.py` starts everything and
records which probes answered in the key; the grader leaves out what was not up.

Placeholders filled at run time: `__VERSION__` (the latest release),
`__DOMAIN1__`, `__NET1__`, `__DNS1__`, `__DOMAIN2__`, `__NET2__`, `__DNS2__`,
`__PHASE1_TOOLS__`, `__PHASE2_TOOLS__` (`range/render_brief.py`; it fails if any
is left).

## Isolation

The `work` job does these before the agent starts, and `range/isolate.sh` fails
the job when any check does not hold:

| Step | How it is verified |
| --- | --- |
| nmap and the other tools that need root are installed first | the job installs them; the agent has no sudo afterwards |
| `/proc` is mounted with `hidepid=2` | no process of another user is listed in /proc, and a canary process of user `nobody` is not visible |
| the docker socket becomes `root:root 0600`, the user leaves the docker group | `docker ps` fails, the socket cannot be opened, nothing listens on 2375/2376 |
| the user's sudo rights are removed (sudoers files, groups) | `sudo -n true` fails, `su root` without a password fails |
| the answer key is encrypted to the maintainer's age key; the plaintext, the build folder and the Vulhub checkout are deleted | the agent's folder starts empty and the key leaves only as `key.json.age` |

Containers, the proxy and the resolvers run as root or as `nobody`, so
`hidepid` hides them from `ps`. What is not hidden: the kernel's table of
listening sockets (`ss`, `/proc/net/tcp`) and the network interfaces. The
grader lists every command in the agent's log that touches docker, processes,
sockets, interfaces, privilege or the outside (`gh`, `git push`), for a person
to judge. Job logs are public: build, start and isolate print counts only.

## What comes back

`REPORT.md`, `leads.jsonl`, `phases.log`, `surface-*.txt`, `notes/`, the last
300 lines of the stream, the whole stream (`stream.ts.jsonl.gz`, up to 40 MB),
and `key.json`. Every stream line starts with the epoch second it arrived, so
the grader measures the time to a finding from the command that wrote the lead.

`grade.py KEY DIR` prints a Markdown table and writes `DIR/grade.json`: per
phase the share of hosts, ports and services in `surface-N.txt`, the
vulnerabilities identified (a lead's host or address, port and CVE or product
match a key entry), the leads that match nothing (listed, not counted as wrong),
the seconds to the first match and to each, and the commands run.

## The catalog

`range/catalog_gen.py VULHUB_DIR` writes `catalog.json` from a Vulhub checkout
(needs PyYAML). Push `range-smoke-NAME` (`run.sh range-smoke NAME`) to start the
environments on four runners and record readiness, seconds to answer, memory
and image size; then
`python3 .github/ci/range/smoke_apply.py DIR/smoke-*.json` keeps only the entries that passed.

Tests: `python3 -m unittest discover -s .github/ci/range` (set `VULHUB` to also
render every override with `docker compose config`).
