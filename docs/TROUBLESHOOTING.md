# Troubleshooting

`azhaq docs troubleshooting` prints this page.

**Why is my URL `hint`?** Azhaq knows it (from a script, an API description, an archive or a link) but no GET proved it: it takes a path parameter, or only another method (scripts call it with POST), or a GET there answers 404 while scripts call it. Send the method its operations name. `azhaq show -db W URL` gives the call site.

**Why is a live endpoint `gone`?** It answered 404 or 410 to a GET. If scripts call it with another method, it is a `hint` instead; if it is `gone`, nothing Azhaq read says it takes another method. Archived URLs are often gone.

**Why was `/exec/` (or `/logout`, `/createdb`) not requested?** Its name says a GET there could change something. It is listed under "left alone" with the word. `-get-words exec` requests the URLs left alone for that word only, `-all-gets` all of them, if you accept the side effect.

**The map looks thin.** The app may draw its links with scripts. The summary suggests `-browser` when a page leaves its links to its scripts. Behind a login, give a session (`-cookie`, `-header`, `-login`).

**`roles` lists nothing.** Check the notes first: a dead session (`refused wherever a session matters`) means the tokens expired; use `-role-cmd` for short-lived ones. Every endpoint answering every role alike is listed with `-all`.

**Exit 3, but the results look fine.** Exit 3 means the results are usable and something failed: a source, a host that did not answer, a dead session. The summary's `failed` list and notes say what; `azhaq query -db W -failed` lists every failed target.

**Exit 4.** A limit stopped the run with work left (`-max-requests`, `-timeout`, Ctrl-C). `azhaq resume -db W` continues it.

**Chrome does not start.** Azhaq looks for Chrome or Chromium on the usual paths; `AZHAQ_CHROME=/path/to/chrome` names it. Where Chrome cannot start its sandbox (some containers), the error says so; `AZHAQ_CHROME_NO_SANDBOX=1` runs it without one, knowing the pages are untrusted.

**The Wayback Machine answers 429, Common Crawl refuses.** Both rate-limit or block some networks. The summary lists them as failures; the other archives still count. Run again later, or from another network.

**Where did my database go?** `run` without `-db` writes `azhaq-TIME-PID.db` in the current directory (or `$AZHAQ_DB`) and remembers it in `.azhaq-last` for `query` and `show`. Drop-ins (`subs`, `probe`, `dirs`, …) without `-db` use a temporary one, gone when they end.

**A port I know is open is missing.** A port that neither accepts nor refuses a connect is asked once more; if it stays silent, the summary lists it (`ports that neither accepted nor refused a connect…`, rows: `filtered_ports`). A firewall or a loaded host can do that; scan it again.
