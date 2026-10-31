#!/usr/bin/env python3
"""up.py OUT --vulhub DIR --labdns BIN [--run-as nobody]: starts what build.py
planned: every environment with its override, one nginx reverse proxy per
estate (host network, bound to the estate's proxy address), and one
bench/labdns resolver per estate. Then it waits for each readiness probe and
writes the result into OUT/key.json (per environment: up or not, seconds,
what the probe said), because the key must describe what really runs.

Nothing about the estates is printed (the job log is public): only counts.
Output of docker goes to OUT/up.log, which is deleted with the rest of OUT.
"""
import argparse
import concurrent.futures
import json
import os
import subprocess
import sys
import time

import rangelib


class Ctx:
    def __init__(self, out, vulhub, run=rangelib.sh, check=rangelib.probe_once, clock=time.time,
                 sleep=time.sleep, popen=subprocess.Popen):
        self.out, self.vulhub = out, vulhub
        self.run, self.check, self.clock, self.sleep, self.popen = run, check, clock, sleep, popen
        self.log = open(os.path.join(out, "up.log"), "a")

    def note(self, text):
        self.log.write(text.rstrip() + "\n")
        self.log.flush()


def start_env(ctx, env, attempts=2):
    d = os.path.join(ctx.vulhub, env["path"])
    ov = os.path.join(ctx.out, env["override"])
    cmd = rangelib.compose_cmd(env["project"], d, ov, "up", "-d", "--quiet-pull")
    out = ""
    for _ in range(attempts):
        rc, out = ctx.run(cmd, cwd=d, env={"TARGET_IP": env["address"]}, timeout=1800)
        ctx.note("$ %s\n%s" % (" ".join(cmd), out[-2000:]))
        if rc == 0:
            return True, ""
        ctx.sleep(5)
    return False, out[-300:]


def wait_env(ctx, env):
    remap = {int(k): v for k, v in env["remap"].items()}
    deadline = max(180, 2 * env["ready_s"] + 90)
    return rangelib.wait_ready(env["probe"], env["address"], deadline, remap, clock=ctx.clock, sleep=ctx.sleep, check=ctx.check)


def start_proxy(ctx, proxy):
    conf = os.path.join(ctx.out, proxy["conf"])
    ctx.run(["docker", "rm", "-f", proxy["name"]])
    rc, out = ctx.run(["docker", "run", "-d", "--name", proxy["name"], "--network", "host", "--restart", "unless-stopped",
                       "-v", conf + ":/etc/nginx/conf.d/default.conf:ro", "nginx:1-alpine"])
    ctx.note("proxy %s: rc=%d %s" % (proxy["name"], rc, out[-300:]))
    return rc == 0


def start_dns(ctx, d, labdns, run_as):
    # The zone goes in on stdin: the user the resolver runs as cannot read
    # the runner's files, and no copy is left for anyone to read.
    with open(os.path.join(ctx.out, d["zone"]), "rb") as f:
        raw = f.read()
    cmd = [labdns, "-addr", d["listen"], "-zone", "-"]
    if run_as:
        cmd = ["sudo", "-n", "-u", run_as, "setsid", "nohup"] + cmd
    logf = open(os.path.join(ctx.out, "labdns-%d.log" % d["estate"]), "a")
    p = ctx.popen(cmd, stdout=logf, stderr=logf, stdin=subprocess.PIPE, start_new_session=True)
    if getattr(p, "stdin", None):
        p.stdin.write(raw)
        p.stdin.close()


def dns_ready(ctx, d, apex):
    host, port = d["listen"].rsplit(":", 1)
    import socket
    import struct
    for _ in range(20):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(1.5)
            s.sendto(rangelib.dns_query(apex, 6), (host, int(port)))
            data, _ = s.recvfrom(4096)
            s.close()
            if len(data) >= 12 and struct.unpack(">H", data[2:4])[0] & 0x8000 and data[3] & 0x0F == 0:
                return True
        except OSError:
            pass
        ctx.sleep(0.5)
    return False


def run(ctx, plan, key, labdns, run_as, workers=4):
    envs = plan["envs"]
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        started = list(ex.map(lambda e: start_env(ctx, e), envs))
    for p in plan["proxies"]:
        if not start_proxy(ctx, p):
            ctx.note("proxy %s did not start" % p["name"])
    for d in plan["dns"]:
        start_dns(ctx, d, labdns, run_as)
    pend = [(e, s) for e, s in zip(envs, started) if s[0]]
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as ex:
        waited = list(ex.map(lambda es: wait_env(ctx, es[0]), pend))
    result = {}
    for e, s in zip(envs, started):
        if not s[0]:
            result[e["id"]] = {"up": False, "reason": "compose up failed: " + s[1]}
    for (e, _), (ok, secs, detail) in zip(pend, waited):
        result[e["id"]] = {"up": ok, "seconds": secs, "probe": detail}
    dns_ok = {}
    for d in plan["dns"]:
        est = next(x for x in key["estates"] if x["index"] == d["estate"])
        dns_ok[d["estate"]] = dns_ready(ctx, d, est["domain"] + ".")
    key["up"] = {"envs": result, "dns": {str(k): v for k, v in dns_ok.items()}}
    for est in key["estates"]:
        for h in est["hosts"]:
            if h.get("env"):
                h["up"] = result[h["env"]]["up"]
    return result, dns_ok


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("out")
    ap.add_argument("--vulhub", required=True)
    ap.add_argument("--labdns", required=True, help="the built bench/labdns binary")
    ap.add_argument("--run-as", default="", help="run the resolvers as this user (through sudo -n)")
    ap.add_argument("--min-up", type=float, default=0.7, help="fail when fewer of an estate's environments answer")
    ap.add_argument("--dry-run", action="store_true", help="check the plan and the files; start nothing")
    a = ap.parse_args(argv)
    out = os.path.abspath(a.out)
    with open(os.path.join(out, "plan.json")) as f:
        plan = json.load(f)
    if a.dry_run:
        missing = [p for p in [e["override"] for e in plan["envs"]] + [x["conf"] for x in plan["proxies"]] + [d["zone"] for d in plan["dns"]]
                   if not os.path.exists(os.path.join(out, p))]
        missing += [e["path"] for e in plan["envs"] if not os.path.exists(os.path.join(a.vulhub, e["path"], "docker-compose.yml"))]
        print("dry run: %d environments, %d proxies, %d resolvers; %d files missing" % (len(plan["envs"]), len(plan["proxies"]), len(plan["dns"]), len(missing)))
        return 1 if missing else 0
    with open(os.path.join(out, "key.json")) as f:
        key = json.load(f)
    ctx = Ctx(out, os.path.abspath(a.vulhub))
    result, dns_ok = run(ctx, plan, key, os.path.abspath(a.labdns), a.run_as)
    with open(os.path.join(out, "key.json"), "w") as f:
        json.dump(key, f, indent=1)
    bad = 0
    for i in (1, 2):
        mine = [r for e, r in ((e, result[e["id"]]) for e in plan["envs"] if e["estate"] == i)]
        up = sum(1 for r in mine if r["up"])
        print("estate %d: %d of %d environments answer, resolver %s" % (i, up, len(mine), "answers" if dns_ok[i] else "DOES NOT ANSWER"))
        if not dns_ok[i] or up < a.min_up * len(mine):
            bad += 1
    if bad:
        print("::error title=estates::an estate is not up enough to review")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
