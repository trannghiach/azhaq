# Troubleshooting

`azhaq docs troubleshooting` prints this page.

**Why is my URL `hint`?** Azhaq knows it (from a script, an API description, an archive or a link) but no GET proved it: it takes a path parameter, or only another method (scripts call it with POST), or a GET there answers 404 while scripts call it. Send the method its operations name. `azhaq show -db W URL` gives the call site.

**Why is a live endpoint `gone`?** It answered 404 or 410 to a GET. If scripts call it with another method, it is a `hint` instead; if it is `gone`, nothing Azhaq read says it takes another method. Archived URLs are often gone.

**Why was `/exec` (or `/logout`, `/createdb`) not requested?** Its name says a GET there could change something. A directory named after a verb (`/vulnerabilities/exec/`, `/admin/user/add/`) is a section with a form and is requested; one under an API path (`/api/jobs/run/`) is not. It is listed under "left alone" with the word. `-get-words exec` requests the URLs left alone for that word only, `-all-gets` all of them, if you accept the side effect.

**The map looks thin.** The app may draw its links with scripts. The summary suggests `-browser` when a page leaves its links to its scripts. Behind a login, give a session (`-cookie`, `-header`, `-login`).

**`roles` lists nothing.** Check the notes first: a dead session (`refused wherever a session matters`) means the tokens expired; use `-role-cmd` for short-lived ones. Every endpoint answering every role alike is listed with `-all`.

**Exit 3, but the results look fine.** Exit 3 means the results are usable and something failed: a source, a host that did not answer, a dead session. The summary's `failed` list and notes say what; `azhaq query -db W -failed` lists every failed target.

**Exit 4.** A limit stopped the run with work left (`-max-requests`, `-timeout`, Ctrl-C, or the kill file). `azhaq resume -db W` continues it.

**The run stopped at once with exit 4 and a kill file.** The file `W.stop` (or the one `-kill-file` names; `roles.stop` in the `-dir` of `roles`, where it stops the runs of the roles and not the replay after them) exists, from an earlier stop too, and `stopped` says `the kill switch`. Nothing more is sent while it exists. Remove it, then `azhaq resume -db W`.

**Chrome does not start.** Azhaq looks for Chrome or Chromium on the usual paths; `AZHAQ_CHROME=/path/to/chrome` names it. Where Chrome cannot start its sandbox (some containers), the error says so; `AZHAQ_CHROME_NO_SANDBOX=1` runs it without one. Do this only where you accept that the pages Chrome loads are untrusted.

**The Wayback Machine answers 429, Common Crawl refuses.** Both rate-limit or block some networks. The summary lists them as failures; the other archives still count. Run again later, or from another network.

**Where did my database go?** `run` without `-db` writes `azhaq-TIME-PID.db` in the current directory (or `$AZHAQ_DB`) and remembers it in `.azhaq-last` for `query` and `show`. Drop-ins (`subs`, `probe`, `dirs`, …) without `-db` use a temporary one, gone when they end.

**`dirs` hid a page I know exists.** The calibration drops a guess that answers like a path that cannot exist: the same status and size (ffuf's rule), the same word and line counts where the not-found pages differ in size among themselves, or a size within the path's length where they repeat the path. A real page that is byte-for-byte the not-found page cannot be told apart by any size or count; `-fs`, `-fw` and `-fl` do not undo the calibration. Use `fuzz -ac=false -mc all` to see every answer.

**`dirs` says `N of M guesses were answered 429`.** The service is rate-limiting the sweep. A 429 is not in the default `-mc`, so those guesses were not judged and the paths may exist. The exit code is 3. Lower `-rate` or `-t` and run again.

**`dirs -u URL/path` found less than a sweep of the root.** A URL with a path is swept under that path only (`/api/WORD`); it does not also sweep `/`. Give both URLs to sweep both.

**A UDP port is `open|filtered`.** The port stayed silent when asked twice and no ICMP port unreachable came back: a service that ignores a request it does not understand, or a filter. On a loopback or LAN address it usually means the first; a closed port there answers with an ICMP error and is `closed`. Across a firewall that drops ICMP, closed ports also read `open|filtered`. `ports -json` lists them; the plain output lists only the open ones.

**`subs` returns different names from run to run.** Some passive sources answer differently each time (subdomain.center returns a random 500 of about 6,300 tesla.com names per call). Azhaq keeps the names it found in `names/DOMAIN.json` (under `$AZHAQ_DATA_DIR`, else `$XDG_DATA_HOME/azhaq`, else `~/.local/share/azhaq`) and asks them again as the `history` source, so a name that resolves still comes back. The `coverage:` note says how much of what the sources know the run holds. `-no-history` turns the file off.

**The `subs` summary says `degraded`.** A source in the default set failed (`sources failed` is above 0), so the names may be incomplete. The exit code is not changed; the failed sources are listed. `azhaq subs -v` shows what each source returned and its error.

**`shots` says `screenshot … not taken`.** The page's images, scripts and styles count against `-max-requests`, and too few were left; the note says how many the page needs and how many were left. Raise `-max-requests`.

**`note: path checks: 28 skipped (an API description was already found)`.** Not a failure. The checks that guess where an API description sits stop once one is found on that origin; every other check was still asked.

**A port I know is open is missing.** A port that neither accepts nor refuses a connect is asked once more; if it stays silent, the summary lists it (`ports that neither accepted nor refused a connect…`, rows: `filtered_ports`). A firewall or a loaded host can do that; scan it again.
