#!/usr/bin/env python3
"""smoke.py: starts catalog environments in batches, checks each readiness
probe and records the time to answer, the memory after start and the image
size. On a runner:

  smoke.py --vulhub DIR --shard 0/4 --out smoke-0.json

--dry-run starts nothing: it prints the batches and, where docker is
installed, asks `docker compose config` to render each environment's file
with its override (that needs no daemon). smoke_apply.py then drops the
entries that did not pass from catalog.json.
"""
import argparse
import concurrent.futures
import datetime
import json
import os
import platform
import shutil
import sys
import tempfile
import time

import rangelib

TAIL = 600


def make_batches(entries, batch_mb, max_batch):
    """Greedy first-fit by estimated memory, largest first."""
    batches = []
    for e in sorted(entries, key=lambda e: (-e["mem_mb"], e["id"])):
        for b in batches:
            if len(b["entries"]) < max_batch and b["mb"] + e["mem_mb"] <= batch_mb:
                b["entries"].append(e)
                b["mb"] += e["mem_mb"]
                break
        else:
            batches.append({"entries": [e], "mb": e["mem_mb"]})
    return [b["entries"] for b in batches]


def shard(entries, spec):
    """'I/N': every Nth entry of the list ordered by memory, so shards weigh the same."""
    i, n = (int(x) for x in spec.split("/"))
    ordered = sorted(entries, key=lambda e: (-e["mem_mb"], e["id"]))
    return ordered[i::n]


class Ctx:
    def __init__(self, vulhub, workdir, run=rangelib.sh, check=rangelib.probe_once,
                 clock=time.time, sleep=time.sleep, settle=15.0, base="127.50.0", log=print):
        self.vulhub, self.workdir, self.run, self.check = vulhub, workdir, run, check
        self.clock, self.sleep, self.settle, self.base, self.log = clock, sleep, settle, base, log


def tail(text, n=TAIL):
    text = (text or "").strip()
    return text[-n:]


def start_one(ctx, entry, addr):
    """Writes the override and runs compose up; returns (ok, message)."""
    proj = rangelib.project_name(entry["id"], "azs")
    d = os.path.join(ctx.vulhub, entry["path"])
    ov = os.path.join(ctx.workdir, entry["id"] + ".override.yml")
    with open(ov, "w") as f:
        f.write(rangelib.override_text(entry, addr))
    cmd = rangelib.compose_cmd(proj, d, ov, "up", "-d", "--quiet-pull")
    rc, out = ctx.run(cmd, cwd=d, env={"TARGET_IP": addr}, timeout=1500)
    return rc == 0, tail(out)


def measure_mem(ctx, entry):
    proj = rangelib.project_name(entry["id"], "azs")
    rc, out = ctx.run(["docker", "ps", "-q", "--filter", "label=com.docker.compose.project=" + proj])
    ids = out.split()
    if rc != 0 or not ids:
        return None
    rc, out = ctx.run(["docker", "stats", "--no-stream", "--format", "{{.MemUsage}}", *ids])
    if rc != 0:
        return None
    total = 0.0
    for line in out.splitlines():
        mb = rangelib.parse_size_mb(line.split("/")[0])
        if mb is not None:
            total += mb
    return round(total)


def image_mb(ctx, entry):
    total, seen = 0, set()
    for svc in entry["services"].values():
        img = svc.get("image")
        if not img or img in seen:
            continue
        seen.add(img)
        rc, out = ctx.run(["docker", "image", "inspect", "--format", "{{.Size}}", img])
        if rc == 0 and out.strip().isdigit():
            total += int(out.strip())
    return round(total / 1024 ** 2)


def stop_one(ctx, entry):
    proj = rangelib.project_name(entry["id"], "azs")
    d = os.path.join(ctx.vulhub, entry["path"])
    ov = os.path.join(ctx.workdir, entry["id"] + ".override.yml")
    ctx.run(rangelib.compose_cmd(proj, d, ov, "down", "-v", "--remove-orphans", "-t", "3"), cwd=d, timeout=300)


def logs_of(ctx, entry):
    proj = rangelib.project_name(entry["id"], "azs")
    d = os.path.join(ctx.vulhub, entry["path"])
    ov = os.path.join(ctx.workdir, entry["id"] + ".override.yml")
    return tail(ctx.run(rangelib.compose_cmd(proj, d, ov, "logs", "--no-color", "--tail", "15"), cwd=d, timeout=60)[1])


def run_batch(ctx, batch):
    """Starts every entry of the batch together, probes, measures, stops."""
    results = {}
    addrs = {e["id"]: "%s.%d" % (ctx.base, 10 + i) for i, e in enumerate(batch)}
    ctx.log("batch of %d (est. %d MB): %s" % (len(batch), sum(e["mem_mb"] for e in batch), ", ".join(e["id"] for e in batch)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
        started = dict(zip((e["id"] for e in batch), ex.map(lambda e: start_one(ctx, e, addrs[e["id"]]), batch)))
    t0 = ctx.clock()
    pending = []
    for e in batch:
        ok, msg = started[e["id"]]
        if ok:
            pending.append(e)
        else:
            results[e["id"]] = {"id": e["id"], "ok": False, "reason": "compose up failed: " + msg}

    def wait(e):
        deadline = max(120, 2 * e["ready_s"] + 60)
        return rangelib.wait_ready(e["probe"], addrs[e["id"]], deadline, clock=ctx.clock, sleep=ctx.sleep, check=ctx.check)

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        waited = list(ex.map(wait, pending))
    ctx.sleep(ctx.settle)
    for e, (ok, secs, detail) in zip(pending, waited):
        r = {"id": e["id"], "ok": ok, "ready_s": secs, "probe": detail}
        if ok:
            r["mem_mb"] = measure_mem(ctx, e)
            r["image_mb"] = image_mb(ctx, e)
        else:
            r["reason"] = "probe failed after %ss: %s" % (secs, detail)
            r["log_tail"] = logs_of(ctx, e)
        results[e["id"]] = r
    for e in batch:
        stop_one(ctx, e)
    # Free the disk before the next batch pulls its images.
    ctx.run(["docker", "system", "prune", "-af", "--volumes"], timeout=900)
    return [results[e["id"]] for e in batch]


def dry_run(ctx, batches):
    out = []
    have_docker = shutil.which("docker") is not None
    for batch in batches:
        ctx.log("batch of %d (est. %d MB): %s" % (len(batch), sum(e["mem_mb"] for e in batch), ", ".join(e["id"] for e in batch)))
        for i, e in enumerate(batch):
            r = {"id": e["id"], "ok": None, "reason": "dry run"}
            if have_docker:
                addr = "%s.%d" % (ctx.base, 10 + i)
                ov = os.path.join(ctx.workdir, e["id"] + ".override.yml")
                with open(ov, "w") as f:
                    f.write(rangelib.override_text(e, addr))
                d = os.path.join(ctx.vulhub, e["path"])
                rc, o = ctx.run(rangelib.compose_cmd("azs-dry", d, ov, "config", "-q"), cwd=d, env={"TARGET_IP": addr}, timeout=60)
                r["config_ok"] = rc == 0
                if rc != 0:
                    r["reason"] = "compose config failed: " + tail(o)
            out.append(r)
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--vulhub", required=True, help="checkout of the pinned Vulhub commit")
    ap.add_argument("--catalog", default=rangelib.CATALOG)
    ap.add_argument("--out", default="smoke.json")
    ap.add_argument("--shard", default="0/1", help="I/N: this runner's share")
    ap.add_argument("--only", default="", help="comma-separated catalog ids")
    ap.add_argument("--batch-mb", type=int, default=8000, help="estimated memory a batch may take together")
    ap.add_argument("--max-batch", type=int, default=10)
    ap.add_argument("--settle", type=float, default=15, help="seconds to wait before measuring memory")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args(argv)

    cat = rangelib.load_catalog(a.catalog)
    entries = cat["entries"]
    if a.only:
        want = set(a.only.split(","))
        unknown = want - {e["id"] for e in entries}
        if unknown:
            ap.error("not in the catalog: " + ", ".join(sorted(unknown)))
        entries = [e for e in entries if e["id"] in want]
    entries = shard(entries, a.shard)
    batches = make_batches(entries, a.batch_mb, a.max_batch)
    work = tempfile.mkdtemp(prefix="range-smoke-")
    ctx = Ctx(a.vulhub, work, settle=0 if a.dry_run else a.settle)
    started = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
    try:
        if a.dry_run:
            results = dry_run(ctx, batches)
        else:
            results = []
            for b in batches:
                results.extend(run_batch(ctx, b))
    finally:
        shutil.rmtree(work, ignore_errors=True)
    doc = {
        "vulhub_commit": cat["vulhub"]["commit"],
        "shard": a.shard,
        "dry_run": a.dry_run,
        "started": started,
        "host": {"machine": platform.machine(), "cpus": os.cpu_count()},
        "results": results,
    }
    with open(a.out, "w") as f:
        json.dump(doc, f, indent=1)
        f.write("\n")
    n_ok = sum(1 for r in results if r["ok"])
    n_bad = sum(1 for r in results if r["ok"] is False)
    print("smoke: %d passed, %d failed, %d not run; wrote %s" % (n_ok, n_bad, len(results) - n_ok - n_bad, a.out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
