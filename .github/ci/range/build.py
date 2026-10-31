#!/usr/bin/env python3
"""build.py SEED [options]: builds two disjoint estates from catalog.json.

Each estate is about ten Vulhub environments, stratified by category so both
have the same mix, inside a memory budget for the two together. For each
estate it picks a random company-like domain under .test, a /24 of loopback
(Linux routes all of 127/8 to lo), one address per host, names that look
like a company's (some named after the product, some neutral, a few under a
dev. subzone with a wildcard), some services on non-default ports, a few
names served only by a shared nginx reverse proxy by Host, and dangling
CNAMEs.

Everything goes to --out (nothing of it is printed: the job log is public):
  key.json             the answer key; encrypt it, then delete it
  plan.json            what up.py runs
  vars.json            the values for the brief's placeholders
  overrides/*.yml      compose overrides, one per environment
  zone-1.json, zone-2.json   DNS zones for bench/labdns -zone
  proxy-1.conf, proxy-2.conf nginx configs, one per estate

The same SEED gives the same estates.
"""
import argparse
import ipaddress
import json
import os
import random
import sys

import rangelib

WORDS_A = ["north", "blue", "iron", "swift", "lumen", "apex", "cobalt", "vector", "nimbus", "quartz",
           "harbor", "maple", "delta", "orbit", "pixel", "summit", "cedar", "falcon", "ember", "atlas",
           "willow", "granite", "sable", "tidal", "kestrel", "prism"]
WORDS_B = ["pay", "soft", "labs", "cloud", "works", "data", "net", "logic", "grid", "forge", "wave",
           "stack", "bridge", "mark", "core", "trade", "ware", "link", "mint"]
NEUTRAL = ["dev-03", "tools", "internal", "stg-02", "app1", "portal", "legacy", "sandbox", "qa-5", "int",
           "ops", "data", "backoffice", "partners", "hub", "lab", "uat", "preprod", "ext", "svc-04",
           "web2", "old", "edge2", "crm", "hr", "intranet", "files2", "test-7", "corp", "dc2", "mgmt",
           "stage", "demo", "beta", "ws-11", "app-eu", "node7", "hq"]
DANGLING_NAMES = ["assets", "status", "help", "cdn", "static", "docs-old", "shop-old", "media", "careers", "events"]
DANGLING_TARGETS = ["azurewebsites.net", "azureedge.net", "trafficmanager.net", "cloudapp.net", "blob.core.windows.net"]
SUBZONES = ["dev", "stg"]
PORT_POOL = [8000, 8008, 8081, 8088, 8090, 8181, 8888, 9000, 9090, 9999, 7000, 18080, 3000, 5000, 4443, 8443]


def mem(e):
    return e.get("mem_mb_measured") or e["mem_mb"]


def disk(e):
    return e.get("image_mb") or 600


def quotas(cats, pool, size, rng):
    """Entries per category: the same for both estates, `size` in all."""
    base = size // len(cats)
    left = size - base * len(cats)
    ok = [c for c in cats if len({e["family"] for e in pool[c]}) >= 2 * (base + 1)]
    extra = rng.sample(ok, min(left, len(ok)))
    q = {c: base + (1 if c in extra else 0) for c in cats}
    for c in cats:
        if len(pool[c]) < 2 * q[c]:
            raise SystemExit("category %s has %d entries, too few for two estates of %d each" % (c, len(pool[c]), q[c]))
    return q


def try_pick(cats, pool, q, rng):
    """One random draw: two disjoint lists, or None when a category cannot fill both."""
    est = ([], [])
    fams = (set(), set())
    for c in cats:
        cand = pool[c][:]
        rng.shuffle(cand)
        taken = set()
        for i in (0, 1):
            got = 0
            # Prefer products the other estate does not run.
            for prefer_fresh in (True, False):
                for e in cand:
                    if got == q[c]:
                        break
                    if e["id"] in taken or e["family"] in fams[i]:
                        continue
                    if prefer_fresh and e["family"] in fams[1 - i]:
                        continue
                    est[i].append(e)
                    fams[i].add(e["family"])
                    taken.add(e["id"])
                    got += 1
            if got < q[c]:
                return None
    return est


def pick_estates(cat, rng, size, budget_mb, disk_mb, balance=0.3, tries=3000):
    """Two disjoint lists of entries: same category mix, one family at most once per estate,
    the memory and image size of both together within budget, and about equal weight."""
    cats = [c for c in cat["categories"] if any(e["category"] == c for e in cat["entries"])]
    pool = {c: [e for e in cat["entries"] if e["category"] == c] for c in cats}
    q = quotas(cats, pool, size, rng)
    best = None
    for _ in range(tries):
        est = try_pick(cats, pool, q, rng)
        if est is None:
            continue
        m = [sum(mem(e) for e in x) for x in est]
        if m[0] + m[1] > budget_mb or sum(disk(e) for x in est for e in x) > disk_mb:
            continue
        skew = abs(m[0] - m[1]) / max(m)
        if skew <= balance:
            return est
        if best is None or skew < best[0]:
            best = (skew, est)
    if best is not None:
        return best[1]
    raise SystemExit("no pair of estates fits %d MB of memory and %d MB of images; raise the budget or lower --size" % (budget_mb, disk_mb))


def company_domain(rng, taken):
    while True:
        d = rng.choice(WORDS_A) + rng.choice(WORDS_B) + ".test"
        if d not in taken:
            return d


def pick_names(rng, entries, domain):
    """One label (possibly with a subzone) per entry. Product names for about
    half, neutral ones for the rest; a few land under dev. or stg."""
    used = {"www", "ns1", "ns2", "mail", "mx"}
    labels = []
    subs = rng.sample(range(len(entries)), min(2, len(entries)))
    for i, e in enumerate(entries):
        label = None
        if rng.random() < 0.5:
            opts = [n for n in e["names"] if n not in used]
            if opts:
                label = rng.choice(opts)
        if label is None:
            opts = [n for n in NEUTRAL if n not in used]
            label = rng.choice(opts)
        used.add(label)
        if i in subs:
            label = label + "." + rng.choice(SUBZONES)
        labels.append(label)
    return labels


def build_estate(idx, entries, cat, rng, args, domain, net, dns_port, taken_hidden):
    net = ipaddress.ip_network(net)
    if net.prefixlen != 24:
        raise SystemExit("--net%d must be a /24" % idx)
    base = str(net.network_address).rsplit(".", 1)[0]
    hidden_base = "127.%d.0" % (199 + idx)
    n_vhost = min(args.vhosts, sum(1 for e in entries if e["proxy"] and e["ports"]))
    candidates = [e for e in entries if e["proxy"] and any(p["primary"] and p["protocol"] == "http" for p in e["ports"])]
    vhosted = rng.sample(candidates, min(n_vhost, len(candidates)))
    vhost_ids = {e["id"] for e in vhosted}
    direct = [e for e in entries if e["id"] not in vhost_ids]
    octets = rng.sample(range(10, 251), len(direct) + 1)
    proxy_addr = "%s.%d" % (base, octets[-1])
    labels = pick_names(rng, entries, domain)
    label_of = dict(zip((e["id"] for e in entries), labels))

    hosts, zone, plan_envs = [], {}, []
    zs = {}  # zone records by fqdn

    def add(name, rec):
        zs.setdefault(name, []).append(rec)

    apex = domain + "."
    ns = "ns1." + apex
    add(apex, "SOA %s hostmaster.%s %d 3600 600 86400 60" % (ns, apex, 2026103100 + idx))
    add(apex, "NS " + ns)
    add(apex, "NS ns2." + apex)
    add(ns, "A 127.0.0.1")
    add("ns2." + apex, "A 127.0.0.1")
    add(apex, "A " + proxy_addr)
    add("www." + apex, "A " + proxy_addr)
    add(apex, 'TXT "v=spf1 -all"')

    ptr = {}
    key_hosts = []
    for i, e in enumerate(direct):
        addr = "%s.%d" % (base, octets[i])
        label = label_of[e["id"]]
        fq = label + "." + apex
        remap = {}
        prim = next(p for p in e["ports"] if p["primary"])
        if prim["protocol"] in ("http", "https") and rng.random() < 0.3:
            used = {p["host_port"] for p in e["ports"]}
            opts = [p for p in PORT_POOL if p not in used]
            remap[prim["host_port"]] = rng.choice(opts)
        add(fq, "A " + addr)
        if rng.random() < 0.35:
            ptr[addr.rsplit(".", 1)[1]] = [fq]
        key_hosts.append(key_entry(e, fq.rstrip("."), addr, remap, False, True))
        plan_envs.append(plan_env(idx, e, addr, remap))
        if "smtp" in {p["protocol"] for p in e["ports"]}:
            add(apex, "MX 10 " + fq)

    for j, e in enumerate(vhosted):
        label = label_of[e["id"]]
        fq = label + "." + apex
        haddr = "%s.%d" % (hidden_base, 10 + j)
        hidden = j >= len(vhosted) - args.hidden_vhosts
        if not hidden:
            if rng.random() < 0.4:
                add(fq, "CNAME www." + apex)
            else:
                add(fq, "A " + proxy_addr)
        key_hosts.append(key_entry(e, fq.rstrip("."), proxy_addr, {}, True, not hidden))
        plan_envs.append(plan_env(idx, e, haddr, {}, backend=True))

    taken_labels = {l.split(".")[0] for l in labels} | {l.split(".")[-1] for l in labels}
    free = [n for n in DANGLING_NAMES if n not in taken_labels]
    for n in rng.sample(free, min(args.dangling, len(free))):
        target = "%s-%s.%s." % ("%010x" % rng.getrandbits(40), domain.split(".")[0], rng.choice(DANGLING_TARGETS))
        add(n + "." + apex, "CNAME " + target)
        key_hosts.append({"kind": "dangling-cname", "host": (n + "." + apex).rstrip("."), "target": target,
                          "summary": "CNAME to %s, a name nobody has registered: a takeover candidate" % target.rstrip("."),
                          "category": "dns", "vulnerable": True, "ports": []})

    wildcard = None
    subs = sorted({label_of[e["id"]].split(".", 1)[1] for e in entries if "." in label_of[e["id"]]})
    if subs and rng.random() < 0.6:
        wildcard = "*." + subs[0] + "." + apex
        add(wildcard, "A " + proxy_addr)

    proxy = {"estate": idx, "name": "az-proxy-%d" % idx, "conf": "proxy-%d.conf" % idx, "address": proxy_addr}
    key_hosts.append({"kind": "infra", "host": ("www." + apex).rstrip("."), "address": proxy_addr, "product": "nginx",
                      "version": "", "cve": [], "category": "infra", "vulnerable": False,
                      "summary": "reverse proxy; routes the other names by Host and answers 404 for any other",
                      "ports": [{"port": 80, "protocol": "http", "primary": True}], "aliases": [apex.rstrip(".")]})
    conf = proxy_conf(proxy_addr, [(h, e, haddr) for h, e, haddr in vhost_routes(key_hosts, plan_envs, vhosted)])
    zone_doc = {"axfr": False, "zones": {apex: zs}}
    ptr_origin = "%s.in-addr.arpa." % ".".join(reversed(base.split(".")))
    if ptr:
        zone_doc["ptr"] = {ptr_origin: dict(ptr, **{"@": [
            "SOA %s hostmaster.%s %d 3600 600 86400 60" % (ns, apex, 2026103100 + idx), "NS " + ns]})}
    est = {"index": idx, "domain": domain, "net": str(net), "dns": "127.0.0.1:%d" % dns_port,
           "wildcard": wildcard, "hosts": key_hosts}
    return est, zone_doc, plan_envs, proxy, conf


def vhost_routes(key_hosts, plan_envs, vhosted):
    out = []
    for h in key_hosts:
        if h.get("vhost"):
            env = next(p for p in plan_envs if p["id"] == h["env"])
            prim = next(p for p in next(e for e in vhosted if e["id"] == h["env"])["ports"] if p["primary"])
            out.append((h["host"], prim["host_port"], env["address"]))
    return out


def proxy_conf(addr, routes):
    lines = ["server {", "    listen %s:80 default_server;" % addr, "    server_name _;", "    return 404;", "}"]
    for host, port, backend in routes:
        lines += ["server {", "    listen %s:80;" % addr, "    server_name %s;" % host,
                  "    location / {", "        proxy_pass http://%s:%d;" % (backend, port),
                  "        proxy_set_header Host $host;", "        proxy_set_header X-Real-IP $remote_addr;",
                  "        proxy_http_version 1.1;", "        proxy_read_timeout 120s;", "    }", "}"]
    return "\n".join(lines) + "\n"


def key_entry(e, fq, addr, remap, vhost, dns_visible):
    if vhost:
        ports = [{"port": 80, "protocol": "http", "primary": True, "via": "reverse proxy"}]
    else:
        ports = [{"port": remap.get(p["host_port"], p["host_port"]), "protocol": p["protocol"],
                  "transport": p["transport"], "primary": p["primary"]} for p in e["ports"]]
    return {"kind": "service", "host": fq, "address": addr, "vhost": vhost, "dns_visible": dns_visible,
            "env": e["id"], "product": e["product"], "version": e["version"], "cve": e["cve"],
            "category": e["category"], "summary": e["summary"], "vulnerable": True, "ports": ports}


def plan_env(idx, e, addr, remap, backend=False):
    return {"id": e["id"], "estate": idx, "path": e["path"], "address": addr, "backend": backend,
            "project": rangelib.project_name("e%d-%s" % (idx, e["id"])),
            "override": "overrides/e%d-%s.yml" % (idx, e["id"]),
            "remap": {str(k): v for k, v in remap.items()},
            "probe": e["probe"], "ready_s": e["ready_s"]}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("seed")
    ap.add_argument("--catalog", default=rangelib.CATALOG)
    ap.add_argument("--out", default="range-build")
    ap.add_argument("--size", type=int, default=10, help="environments per estate")
    ap.add_argument("--budget-mb", type=int, default=9500, help="memory both estates may take together")
    ap.add_argument("--disk-mb", type=int, default=30000, help="image size both estates may take together")
    ap.add_argument("--net1", default="127.31.0.0/24")
    ap.add_argument("--net2", default="127.47.0.0/24")
    ap.add_argument("--dns-port1", type=int, default=5301)
    ap.add_argument("--dns-port2", type=int, default=5302)
    ap.add_argument("--vhosts", type=int, default=3, help="names per estate served only by the proxy")
    ap.add_argument("--hidden-vhosts", type=int, default=0, help="of those, how many have no DNS name")
    ap.add_argument("--dangling", type=int, default=2, help="dangling CNAMEs per estate")
    a = ap.parse_args(argv)
    if a.hidden_vhosts > a.vhosts:
        ap.error("--hidden-vhosts cannot exceed --vhosts")

    cat = rangelib.load_catalog(a.catalog)
    rng = random.Random(a.seed)
    est = pick_estates(cat, rng, a.size, a.budget_mb, a.disk_mb)
    d1 = company_domain(rng, set())
    d2 = company_domain(rng, {d1})
    out = os.path.abspath(a.out)
    os.makedirs(os.path.join(out, "overrides"), exist_ok=True)

    estates, plan_envs, proxies, dns, confs = [], [], [], [], {}
    for i, (entries, dom, net, port) in enumerate(((est[0], d1, a.net1, a.dns_port1), (est[1], d2, a.net2, a.dns_port2)), 1):
        e, zdoc, envs, proxy, conf = build_estate(i, entries, cat, rng, a, dom, net, port, None)
        estates.append(e)
        plan_envs += envs
        proxies.append(proxy)
        confs[proxy["conf"]] = conf
        zname = "zone-%d.json" % i
        with open(os.path.join(out, zname), "w") as f:
            json.dump(zdoc, f, indent=1)
        dns.append({"estate": i, "zone": zname, "listen": e["dns"]})

    by_id = {e["id"]: e for e in cat["entries"]}
    for p in plan_envs:
        with open(os.path.join(out, p["override"]), "w") as f:
            f.write(rangelib.override_text(by_id[p["id"]], p["address"], {int(k): v for k, v in p["remap"].items()}))
    for name, text in confs.items():
        with open(os.path.join(out, name), "w") as f:
            f.write(text)
    key = {"seed": a.seed, "vulhub_commit": cat["vulhub"]["commit"], "estates": estates}
    plan = {"vulhub_commit": cat["vulhub"]["commit"], "envs": plan_envs, "proxies": proxies, "dns": dns}
    variables = {"DOMAIN1": d1, "NET1": a.net1, "DNS1": estates[0]["dns"],
                 "DOMAIN2": d2, "NET2": a.net2, "DNS2": estates[1]["dns"]}
    for name, doc in (("key.json", key), ("plan.json", plan), ("vars.json", variables)):
        with open(os.path.join(out, name), "w") as f:
            json.dump(doc, f, indent=1)
    sizes = [len(x) for x in est]
    print("built two estates of %d and %d environments, about %d MB of memory in all"
          % (sizes[0], sizes[1], sum(mem(e) for x in est for e in x)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
