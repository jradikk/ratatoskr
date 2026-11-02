#!/usr/bin/env python3
"""Fixed tunnel-only marker; private ConfigMap controls only `/exit`."""
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

EXIT_ENABLED = Path("/run/exit-health/exit-enabled")


def exit_available(path=None):
    # ConfigMap projection swaps its symlink atomically; read the path anew
    # for each probe. Missing, malformed or overlong values fail CLOSED.
    if path is None:
        path = EXIT_ENABLED
    try:
        with path.open("rb") as source:
            return source.read(6) == b"true"  # only exact four bytes accepted
    except OSError:
        return False


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/exit":
            if not exit_available():
                self.send_response(503)
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            body = b"10.88.0.1\n"
        elif self.path == "/marker":
            body = b"ratatoskr-synthetic-vpn-v1\n"
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass  # No request path or peer data in Pod logs.


if __name__ == "__main__":
    HTTPServer(("10.88.0.1", 8080), Handler).serve_forever()
