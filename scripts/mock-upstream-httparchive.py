#!/usr/bin/env python3
"""HTTP mock upstream with HTTP Archive Top 1k median page resources."""
from __future__ import annotations

import os
import sys
from functools import lru_cache
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from httparchive_profile import expand_device, load_profile, validate_profile  # noqa: E402

HOST = os.environ.get("MOCK_HOST", "127.0.0.1")
PORT = int(os.environ.get("MOCK_PORT", "18080"))
DEVICE = os.environ.get("HTTPARCHIVE_DEVICE", "desktop")

PROFILE = load_profile()
validate_profile(PROFILE)
RESOURCES = {r.path: r for r in expand_device(PROFILE, DEVICE)}
BODY_CACHE: dict[str, bytes] = {}


def body_for(path: str) -> bytes:
    if path not in BODY_CACHE:
        res = RESOURCES[path]
        # Deterministic filler; prefix aids debugging without compressing well.
        prefix = f"ha:{res.resource_type}:{res.size_bytes}:".encode()
        pad = max(0, res.size_bytes - len(prefix))
        BODY_CACHE[path] = prefix + (b"\x00" * pad)
    return BODY_CACHE[path]


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        if self.path == "/ping":
            self._respond(200, b"pong", "text/plain")
            return
        if self.path == "/httparchive/manifest":
            manifest = "\n".join(sorted(RESOURCES)).encode()
            self._respond(200, manifest, "text/plain")
            return
        resource = RESOURCES.get(self.path)
        if resource is None:
            self.send_error(404)
            return
        payload = body_for(self.path)
        self.send_response(200)
        self.send_header("Content-Type", resource.mime)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "public, max-age=3600")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        self.wfile.write(payload)

    def _respond(self, code: int, body: bytes, mime: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


def main() -> None:
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    total_bytes = sum(r.size_bytes for r in RESOURCES.values())
    print(
        f"httparchive mock on http://{HOST}:{PORT} device={DEVICE} "
        f"resources={len(RESOURCES)} bytes={total_bytes}",
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
