#!/usr/bin/env python3
"""smoke_apply.py [--catalog catalog.json] RESULT.json...: keeps in the
catalog only the entries whose smoke run passed, and writes what the run
measured (seconds to answer, memory after start, image size) beside the
estimates. An entry the run did not cover is kept as it is. Entries that
failed move to "dropped" with the reason, so the cut can be checked.
"""
import argparse
import datetime
import json
import sys

import rangelib


def apply(cat, results, commit_ok=True):
    """Returns (new catalog, summary). `results` is a list of smoke documents."""
    by_id = {}
    for doc in results:
        if doc.get("dry_run"):
            continue
        if doc.get("vulhub_commit") != cat["vulhub"]["commit"]:
            raise ValueError("a smoke result is for Vulhub %s but the catalog is pinned to %s"
                             % (doc.get("vulhub_commit"), cat["vulhub"]["commit"]))
        for r in doc["results"]:
            if r.get("ok") is not None:
                by_id[r["id"]] = r
    kept, dropped = [], list(cat.get("dropped", []))
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
    for e in cat["entries"]:
        r = by_id.get(e["id"])
        if r is None:
            kept.append(e)
        elif r["ok"]:
            e = dict(e)
            e["smoke"] = {"ok": True, "date": now, "ready_s": r.get("ready_s")}
            if r.get("mem_mb"):
                e["mem_mb_measured"] = r["mem_mb"]
            if r.get("image_mb"):
                e["image_mb"] = r["image_mb"]
            kept.append(e)
        else:
            dropped.append({"id": e["id"], "category": e["category"], "reason": r.get("reason", "failed"), "date": now})
    out = dict(cat)
    out["entries"] = kept
    out["dropped"] = dropped
    per = {}
    for e in kept:
        per[e["category"]] = per.get(e["category"], 0) + 1
    return out, {"kept": len(kept), "dropped": len(dropped), "per_category": per, "covered": len(by_id)}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--catalog", default=rangelib.CATALOG)
    ap.add_argument("--out", help="default: rewrite the catalog in place")
    ap.add_argument("results", nargs="+")
    a = ap.parse_args(argv)
    cat = rangelib.load_catalog(a.catalog)
    docs = []
    for p in a.results:
        with open(p, encoding="utf-8") as f:
            docs.append(json.load(f))
    new, summary = apply(cat, docs)
    with open(a.out or a.catalog, "w", encoding="utf-8") as f:
        json.dump(new, f, indent=1, ensure_ascii=False)
        f.write("\n")
    print("covered %(covered)d, kept %(kept)d, dropped %(dropped)d" % summary)
    for c, n in sorted(summary["per_category"].items()):
        print("  %-12s %d" % (c, n))
    return 0


if __name__ == "__main__":
    sys.exit(main())
