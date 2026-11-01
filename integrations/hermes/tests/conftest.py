"""Shared fixtures: a local fake console (HTTP) recording requests."""

from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from afw_hermes.config import Config


class FakeConsole:
    """In-process HTTP server standing in for the agents-firewall console."""

    def __init__(self) -> None:
        self.requests: list[dict] = []
        self.policy: dict | None = None
        self.ingest_status = 202
        self.delay = 0.0
        self.down = False
        self._lock = threading.Lock()
        console = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):  # silence
                pass

            def _record(self, body: bytes | None) -> None:
                with console._lock:
                    console.requests.append(
                        {
                            "method": self.command,
                            "path": self.path,
                            "headers": {k.lower(): v for k, v in self.headers.items()},
                            "body": json.loads(body) if body else None,
                        }
                    )

            def _reply(self, status: int, payload: dict | None = None) -> None:
                data = json.dumps(payload or {}).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):  # noqa: N802
                if console.delay:
                    time.sleep(console.delay)
                self._record(None)
                if console.down:
                    return self._reply(503)
                if self.path == "/api/v1/intent-policy" and console.policy is not None:
                    return self._reply(200, console.policy)
                return self._reply(404)

            def do_POST(self):  # noqa: N802
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length)
                if console.delay:
                    time.sleep(console.delay)
                self._record(body)
                if console.down:
                    return self._reply(503)
                return self._reply(console.ingest_status, {"accepted": True})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def url(self) -> str:
        host, port = self.server.server_address[:2]
        return f"http://{host}:{port}"

    def ingested_events(self) -> list[dict]:
        with self._lock:
            out = []
            for r in self.requests:
                if r["method"] == "POST" and r["path"] == "/api/v1/ingest/tool-calls":
                    out.extend(r["body"]["events"])
            return out

    def ingest_requests(self) -> list[dict]:
        with self._lock:
            return [r for r in self.requests if r["path"] == "/api/v1/ingest/tool-calls"]

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def console():
    c = FakeConsole()
    yield c
    c.close()


@pytest.fixture
def make_config(tmp_path):
    def _make(console_url: str | None = None, **overrides) -> Config:
        base = dict(
            console_url=console_url,
            agent_token="agent-token-123",
            agent_name="daniel-bot",
            ca_file=None,
            state_dir=tmp_path / "state",
            flush_interval=0.05,
            backoff_initial=0.05,
            backoff_max=0.2,
            send_timeout=2.0,
            policy_timeout=2.0,
        )
        base.update(overrides)
        return Config(**base)

    return _make


def wait_until(predicate, timeout: float = 5.0, interval: float = 0.02) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()
