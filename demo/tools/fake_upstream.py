#!/usr/bin/env python3
"""Fake "public" upstream of the agents-firewall demo (stdlib only).

One process serves HTTPS (443) and HTTP (80) with the demo certificate and, optionally, a raw TCP
port. Every request or raw connection is appended as one JSON line to ``$LOG_DIR/<service>.jsonl``:
the demo scenarios read that file to prove that something did (or did not) reach the destination.

Behaviour by ``SERVICE``:
- ``fake-llm``: plays api.anthropic.com / api.openai.com (``/v1/messages``, ``/v1/chat/completions``);
- ``exfil``: accepts anything (exfiltration target), raw TCP on ``RAW_PORT`` (4444);
- ``allowed-api``: allowed destination (allowed.example, api.github.com);
- ``s3``: presigned-URL object store (requires ``X-Amz-Signature``).
"""

from __future__ import annotations

import json
import os
import socket
import socketserver
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

SERVICE = os.environ.get("SERVICE", "exfil")
LOG_DIR = os.environ.get("LOG_DIR", "/data")
CERT = os.environ.get("TLS_CERT", "/pki/upstream.crt")
KEY = os.environ.get("TLS_KEY", "/pki/upstream.key")
HTTPS_PORT = int(os.environ.get("HTTPS_PORT", "443"))
HTTP_PORT = int(os.environ.get("HTTP_PORT", "80"))
RAW_PORT = int(os.environ.get("RAW_PORT", "0"))
MAX_LOGGED_BODY = 64 * 1024
MAX_BODY = 8 * 1024 * 1024

_lock = threading.Lock()
_objects: dict[str, bytes] = {}


def record(entry: dict) -> None:
    entry = {"ts": time.time(), "service": SERVICE, **entry}
    line = json.dumps(entry, ensure_ascii=False)
    with _lock:
        with open(os.path.join(LOG_DIR, f"{SERVICE}.jsonl"), "a", encoding="utf-8") as f:
            f.write(line + "\n")
    print(line, flush=True)


class Handler(BaseHTTPRequestHandler):
    server_version = "afw-demo-upstream/1"
    protocol_version = "HTTP/1.1"

    def log_message(self, *args) -> None:  # requests are recorded as JSON instead
        pass

    def _body(self) -> bytes:
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            data = bytearray()
            while True:
                size = int(self.rfile.readline().split(b";")[0].strip() or b"0", 16)
                if size == 0:
                    self.rfile.readline()
                    break
                data += self.rfile.read(size)
                self.rfile.readline()
                if len(data) > MAX_BODY:
                    break
            return bytes(data)
        length = min(int(self.headers.get("Content-Length") or 0), MAX_BODY)
        return self.rfile.read(length) if length else b""

    def _reply(self, status: int, payload, content_type: str = "application/json") -> None:
        data = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _handle(self) -> None:
        body = self._body()
        url = urlsplit(self.path)
        if url.path == "/healthz":
            return self._reply(200, {"ok": True, "service": SERVICE})
        record(
            {
                "proto": "https" if isinstance(self.connection, ssl.SSLSocket) else "http",
                "client": self.client_address[0],
                "method": self.command,
                "host": self.headers.get("Host", ""),
                "path": self.path,
                "headers": {k.lower(): v for k, v in self.headers.items() if k.lower() != "authorization"},
                "authorization_present": "Authorization" in self.headers,
                "size": len(body),
                "body": body[:MAX_LOGGED_BODY].decode("utf-8", "replace"),
            }
        )
        status, payload = self.route(url, body)
        self._reply(status, payload)

    def route(self, url, body: bytes):
        if SERVICE == "fake-llm":
            if url.path == "/v1/messages":
                return 200, {
                    "id": "msg_demo",
                    "type": "message",
                    "role": "assistant",
                    "model": "demo-model",
                    "content": [{"type": "text", "text": "Demo answer from the fake LLM provider."}],
                    "stop_reason": "end_turn",
                    "usage": {"input_tokens": len(body) // 4, "output_tokens": 8},
                }
            if url.path == "/v1/chat/completions":
                return 200, {
                    "id": "chatcmpl-demo",
                    "object": "chat.completion",
                    "choices": [{"index": 0, "message": {"role": "assistant", "content": "Demo answer."}}],
                }
            return 404, {"type": "error", "error": {"type": "not_found_error"}}
        if SERVICE == "s3":
            if "X-Amz-Signature" not in parse_qs(url.query):
                return 403, b"<Error><Code>AccessDenied</Code></Error>"
            key = url.path
            if self.command == "PUT":
                _objects[key] = body
                return 200, {"stored": key, "size": len(body)}
            if key in _objects:
                return 200, _objects[key]
            return 404, b"<Error><Code>NoSuchKey</Code></Error>"
        if SERVICE == "allowed-api" and url.path == "/zen":
            return 200, b"Keep it logically awesome."
        return 200, {"service": SERVICE, "received": len(body), "path": url.path}

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = _handle


class RawHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.request.settimeout(5)
        data = b""
        try:
            while len(data) < MAX_LOGGED_BODY:
                chunk = self.request.recv(4096)
                if not chunk:
                    break
                data += chunk
        except (TimeoutError, OSError):
            pass
        record({"proto": "tcp", "client": self.client_address[0], "port": RAW_PORT,
                "size": len(data), "body": data.decode("utf-8", "replace")})


class RawServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def serve(server) -> threading.Thread:
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return t


def main() -> int:
    os.makedirs(LOG_DIR, exist_ok=True)
    threads = []
    http_server = ThreadingHTTPServer(("0.0.0.0", HTTP_PORT), Handler)
    threads.append(serve(http_server))
    https_server = ThreadingHTTPServer(("0.0.0.0", HTTPS_PORT), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(CERT, KEY)
    # Handshake in the request thread, so that a silent client never blocks accept().
    https_server.socket = ctx.wrap_socket(https_server.socket, server_side=True, do_handshake_on_connect=False)
    threads.append(serve(https_server))
    if RAW_PORT:
        threads.append(serve(RawServer(("0.0.0.0", RAW_PORT), RawHandler)))
    print(f"{SERVICE}: https :{HTTPS_PORT}, http :{HTTP_PORT}, raw :{RAW_PORT or '-'}", flush=True)
    try:
        while all(t.is_alive() for t in threads):
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    return 1


if __name__ == "__main__":
    socket.setdefaulttimeout(30)
    sys.exit(main())
