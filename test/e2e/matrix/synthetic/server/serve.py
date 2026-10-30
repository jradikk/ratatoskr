#!/usr/bin/env python3
"""Fixed, non-secret marker; bound to the server-side TUN IPv4 only."""
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/exit":
            body = b"10.88.0.1\n"
        elif self.path == "/marker":
            body = b"ratatoskr-synthetic-vpn-v1\n"
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass  # No request path or peer data in Pod logs.


HTTPServer(("10.88.0.1", 8080), Handler).serve_forever()
