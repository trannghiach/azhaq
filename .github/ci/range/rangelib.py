"""Shared pieces of the range scripts: the catalog, compose overrides,
readiness probes, and docker output parsing. Python 3 standard library only.
"""
import http.client
import json
import os
import re
import socket
import ssl
import struct
import subprocess
import time

HERE = os.path.dirname(os.path.abspath(__file__))
CATALOG = os.path.join(HERE, "catalog.json")


def load_catalog(path=CATALOG):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def project_name(entry_id, prefix="az"):
    """A compose project name: lower-case letters, digits, - and _."""
    return prefix + "-" + re.sub(r"[^a-z0-9_-]", "-", entry_id.lower())


def remap_port(entry_ports, remap, port):
    return remap.get(port, port)


def override_text(entry, addr, remap=None):
    """A compose override that publishes each service's ports on addr only.

    `ports: !override` replaces the list from the environment's own file
    (a plain list would be appended to it, and the original 0.0.0.0 binding
    would stay). Needs Docker Compose 2.24 or newer.
    """
    remap = remap or {}
    by_service = {}
    for p in entry["ports"]:
        by_service.setdefault(p["service"], []).append(p)
    lines = ["services:"]
    for svc, ports in by_service.items():
        lines.append(f"  {svc}:")
        lines.append("    ports: !override")
        for p in ports:
            host = remap.get(p["host_port"], p["host_port"])
            lines.append(f'      - "{addr}:{host}:{p["container_port"]}/{p["transport"]}"')
    return "\n".join(lines) + "\n"


# --- probes -----------------------------------------------------------

def _http(scheme, addr, port, path, timeout):
    if scheme == "https":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        conn = http.client.HTTPSConnection(addr, port, timeout=timeout, context=ctx)
    else:
        conn = http.client.HTTPConnection(addr, port, timeout=timeout)
    try:
        conn.request("GET", path, headers={"User-Agent": "range-probe", "Accept": "*/*"})
        r = conn.getresponse()
        r.read(512)
        return r.status
    finally:
        conn.close()


def _tcp(addr, port, send, send_hex, expect, timeout, hold=1.5):
    s = socket.create_connection((addr, port), timeout=timeout)
    try:
        if send_hex:
            s.sendall(bytes.fromhex(send_hex))
        elif send:
            s.sendall(send.encode("latin-1"))
        deadline = time.time() + (timeout if expect else hold)
        data = b""
        rx = re.compile(expect, re.S) if expect else None
        while True:
            left = deadline - time.time()
            if left <= 0:
                break
            s.settimeout(left)
            try:
                chunk = s.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                if rx is None:
                    return False, "connection closed with no data"
                break
            data += chunk
            if rx and rx.search(data.decode("latin-1")):
                return True, "banner matched"
            if rx is None:
                return True, "data received"
        if rx is None:
            return True, "held open"
        return False, "no match in %r" % data[:60]
    finally:
        s.close()


def dns_query(name, qtype=1):
    """A wire-format DNS question for NAME, recursion off."""
    q = b"".join(bytes([len(l)]) + l.encode() for l in name.rstrip(".").split(".") if l) + b"\0"
    return struct.pack(">HHHHHH", 0x5A5A, 0, 1, 0, 0, 0) + q + struct.pack(">HH", qtype, 1)


def _dns_tcp(addr, port, name, timeout):
    s = socket.create_connection((addr, port), timeout=timeout)
    try:
        q = dns_query(name)
        s.sendall(struct.pack(">H", len(q)) + q)
        head = s.recv(2)
        if len(head) < 2:
            return False, "no answer"
        n = struct.unpack(">H", head)[0]
        body = b""
        while len(body) < n:
            c = s.recv(n - len(body))
            if not c:
                break
            body += c
        if len(body) >= 12 and struct.unpack(">H", body[2:4])[0] & 0x8000:
            return True, "dns answered"
        return False, "not a dns answer"
    finally:
        s.close()


def probe_once(probe, addr, remap=None, timeout=4.0):
    """One readiness check. Returns (ok, detail); never raises."""
    port = (remap or {}).get(probe["port"], probe["port"])
    try:
        kind = probe["kind"]
        if kind == "http":
            st = _http(probe.get("scheme", "http"), addr, port, probe.get("path", "/"), timeout)
            return st < probe.get("status_below", 500), "status %d" % st
        if kind == "tcp":
            return _tcp(addr, port, probe.get("send"), probe.get("send_hex"), probe.get("expect"), timeout)
        if kind == "dns-tcp":
            return _dns_tcp(addr, port, probe.get("name", "example.test."), timeout)
        return False, "unknown probe kind " + kind
    except (OSError, http.client.HTTPException, ssl.SSLError, ValueError) as e:
        return False, "%s: %s" % (type(e).__name__, e)


def wait_ready(probe, addr, deadline_s, remap=None, interval=3.0, clock=time.time, sleep=time.sleep, check=probe_once):
    """Polls a probe until it passes or deadline_s seconds pass.
    Returns (ok, seconds, detail)."""
    start = clock()
    detail = "not tried"
    while True:
        ok, detail = check(probe, addr, remap)
        now = clock() - start
        if ok:
            return True, round(now, 1), detail
        if now >= deadline_s:
            return False, round(now, 1), detail
        sleep(interval)


# --- docker output ----------------------------------------------------

_UNITS = {"b": 1, "kb": 1e3, "mb": 1e6, "gb": 1e9, "kib": 1024, "mib": 1024 ** 2, "gib": 1024 ** 3, "tib": 1024 ** 4}


def parse_size_mb(text):
    """'123.4MiB', '1.5GiB / 15GiB' or '0B' -> megabytes (MiB), or None."""
    m = re.match(r"\s*([0-9.]+)\s*([A-Za-z]+)", text or "")
    if not m or m.group(2).lower() not in _UNITS:
        return None
    return float(m.group(1)) * _UNITS[m.group(2).lower()] / 1024 ** 2


def sh(cmd, cwd=None, env=None, timeout=900):
    """Runs a command; returns (returncode, combined output)."""
    e = dict(os.environ)
    e.update(env or {})
    try:
        r = subprocess.run(cmd, cwd=cwd, env=e, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except subprocess.TimeoutExpired:
        return 124, "timed out after %ds" % timeout
    except FileNotFoundError as ex:
        return 127, str(ex)


def compose_cmd(project, directory, override, *args):
    base = os.path.join(directory, "docker-compose.yml")
    return ["docker", "compose", "-p", project, "--project-directory", directory,
            "-f", base, "-f", override, *args]
