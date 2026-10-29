#!/usr/bin/env python3
"""A tiny app whose JavaScript bundle changes between two deploys, for `watch`.

usage: python3 -I app.py PORT STATEFILE
STATEFILE holds "v1" or "v2" (missing means v1); each request reads it, so
writing "v2" into it is the deploy. Do not edit this fixture to make a diff pass.
"""
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT, STATE = int(sys.argv[1]), sys.argv[2]
HERE = os.path.dirname(os.path.abspath(__file__))


def version():
    try:
        return open(STATE).read().strip() or "v1"
    except OSError:
        return "v1"


class H(BaseHTTPRequestHandler):
    def send(self, code, ctype, body):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path in ("/", "/index.html"):
            return self.send(200, "text/html", open(os.path.join(HERE, version(), "index.html"), "rb").read())
        if path == "/main.js":
            return self.send(200, "application/javascript", open(os.path.join(HERE, version(), "main.js"), "rb").read())
        if path.startswith("/api/"):
            return self.send(200, "application/json", json.dumps({"ok": True, "path": path}).encode())
        self.send(404, "text/html", b"<html><title>Not found</title></html>")

    def log_message(self, *a):
        pass


ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
