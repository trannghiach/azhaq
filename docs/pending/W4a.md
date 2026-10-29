# W4a: name history and coverage (proposed text)

## README / subs

**Name history.** Passive sources answer differently each run (subdomain.center
returns a random 500 of about 6,300 tesla.com names per call). Azhaq keeps every
name it has kept for a domain in `names/DOMAIN.json` under `$AZHAQ_DATA_DIR`,
else `$XDG_DATA_HOME/azhaq`, else `~/.local/share/azhaq` (first and last time
seen, and the sources that gave it; at most 200,000 names per domain, the
longest unseen go first). The next run asks this file as a source called
`history`: a stored name counts only if it resolves now (not to a wildcard), so
stale names drop out and a name a source missed this time comes back.
`-no-history` neither reads nor writes the file.

**Coverage.** `subs` ends with a note such as

    coverage: the independent sources hold about 1609 names; this run has 1400 of them (87%) — an estimate of what the sources know, not of every name that exists

It is a Chao1 estimate over how many independent sources gave each name:
S + f1²/(2·f2), with f1 names given by one source and f2 by two (with f2 = 0:
S + f1(f1−1)/2). Independent means every source except the ones that pad their
answer (subdomain.center) and `history`; a name only those gave is in the output
but not in the count. It needs two independent sources that answered; with `-live`
it counts the live names printed. It estimates what the sources know, not every
name that exists.

JSON payload: `"coverage": {"observed", "estimated", "share"}`. A sampled
source's row in `sources` (subdomain.center) has `"population_estimate"`, a
Schnabel estimate of how many names one call draws from, when its rounds
repeated names.

## CHANGELOG

- subs: azhaq keeps the names it has found for a domain and asks them again as the `history` source, kept when they resolve (`-no-history` turns it off); the sources table and payload say how complete the result is (coverage estimate, per-source population estimate).
