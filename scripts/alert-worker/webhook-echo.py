#!/usr/bin/env python3
"""Minimal webhook echo receiver for local alert-worker tests."""

from __future__ import annotations

import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        try:
            payload = json.loads(body.decode("utf-8"))
            print(json.dumps(payload, indent=2, ensure_ascii=False), flush=True)
        except Exception as exc:  # noqa: BLE001
            print(f"raw body ({exc}): {body!r}", flush=True)
        self.send_response(204)
        self.end_headers()

    def log_message(self, fmt: str, *args) -> None:  # noqa: A003
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9080
    server = HTTPServer(("0.0.0.0", port), Handler)
    print(f"listening on http://0.0.0.0:{port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
