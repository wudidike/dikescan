#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""本地靶站：覆盖 403 / 302 重定向 / 200+PII / POST 表单 / 软404 五种形态。"""
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

SOFT404 = b"<html><head><title>Page Not Found</title></head><body>Sorry, nothing here.</body></html>"


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body=b"", ctype="text/html", location=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        if location:
            self.send_header("Location", location)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        p = self.path.split("?")[0]
        if p == "/":
            body = (b'<html><head><title>Home</title></head><body>'
                    b'<a href="/admin/">admin dir</a>'
                    b'<a href="/api/user">api user</a>'
                    b'<a href="/old">old</a>'
                    b'<a href="/nope-link">nope</a>'
                    b'<form action="/login" method="POST">'
                    b'<input name="username"><input name="password" type="password">'
                    b'<input type="submit"></form></body></html>')
            self._send(200, body)
        elif p == "/admin":
            self._send(403, b"<html><title>Forbidden</title></html>")
        elif p == "/admin/":
            self._send(200, b"<html><title>Admin Panel</title></html>")
        elif p == "/api/user":
            self._send(200, json.dumps({"phone": "13800138000", "idcard": "110101199003071234"}).encode(),
                       ctype="application/json")
        elif p == "/old":
            self._send(302, b"", location="/new")
        elif p == "/new":
            self._send(200, b"<html><title>New Page</title></html>")
        elif p == "/login":
            self._send(200, b"<html><title>Login</title></html>")
        else:
            # 软 404：不存在的路径返回 200
            self._send(200, SOFT404)

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        self._send(200, b"<html><title>Login Result</title>posted:" + raw + b"</html>")


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 8899), H).serve_forever()
