"""Fake Hermes agent for the agents-firewall acceptance demo.

Loads the afw-hermes plugin exactly like Hermes does (``register(ctx)`` + ``ctx.register_hook``),
then exposes a small command server so the acceptance scripts can trigger scenarios:

    POST /run {"tool": "fetch", "args": {"url": "https://..."}, "conversation_id": "conv-1"}
    POST /run {"tool": "terminal", "args": {"command": "curl -s https://..."}, "conversation_id": "c"}
    POST /run {"tool": "delete_ticket", "args": {"id": 3}, "conversation_id": "c"}   # simulated
    GET  /healthz

Real tools: ``fetch`` (urllib GET/POST) and ``terminal`` (only ``curl``, run without a shell).
Any other tool is simulated (no side effect) but still goes through the hooks.
"""

from __future__ import annotations

import json
import logging
import os
import shlex
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import afw_hermes
from afw_hermes.config import Config
from afw_hermes.plugin import AfwPlugin, get_plugin

log = logging.getLogger("fake_hermes")


class BadRequest(Exception):
    pass


class FakeCtx:
    """The subset of Hermes' plugin context used by afw-hermes."""

    def __init__(self) -> None:
        self.hooks: dict[str, list] = {}

    def register_hook(self, name: str, fn) -> None:
        self.hooks.setdefault(name, []).append(fn)


class FakeHermes:
    def __init__(self, config: Config | None = None) -> None:
        self.ctx = FakeCtx()
        if config is None:
            afw_hermes.register(self.ctx)  # real path: configuration from the environment
            self.plugin = get_plugin()
        else:
            self.plugin = AfwPlugin(config)
            self.plugin.start()
            self.ctx.register_hook("pre_tool_call", self.plugin.pre_tool_call)
            self.ctx.register_hook("post_tool_call", self.plugin.post_tool_call)

    def _hooks(self, name: str):
        return self.ctx.hooks.get(name, [])

    def run(self, tool: str, args: Any, conversation_id: str) -> dict:
        if not tool:
            raise BadRequest("tool is required")
        call_id = str(uuid.uuid4())
        common = {"task_id": conversation_id, "session_id": conversation_id, "tool_call_id": call_id}
        for hook in self._hooks("pre_tool_call"):
            directive = hook(tool_name=tool, args=args, **common)
            if isinstance(directive, dict) and directive.get("action") == "block":
                for post in self._hooks("post_tool_call"):
                    post(tool_name=tool, args=args, result=directive["message"], duration_ms=0,
                         status="blocked", **common)
                return {"blocked": True, "message": directive["message"], "tool_call_id": call_id}
        t0 = time.monotonic()
        status, error = "ok", None
        try:
            result = self._execute(tool, args)
        except BadRequest:
            for post in self._hooks("post_tool_call"):
                post(tool_name=tool, args=args, result=None, duration_ms=0, status="error",
                     error_message="refused by demo", **common)
            raise
        except Exception as exc:  # noqa: BLE001
            status, error, result = "error", str(exc), None
        for post in self._hooks("post_tool_call"):
            post(tool_name=tool, args=args, result=result, status=status, error_message=error,
                 duration_ms=int((time.monotonic() - t0) * 1000), **common)
        return {"blocked": False, "status": status, "error": error, "result": result, "tool_call_id": call_id}

    @staticmethod
    def _execute(tool: str, args: Any) -> Any:
        args = args if isinstance(args, dict) else {}
        if tool == "fetch":
            url = str(args.get("url") or "")
            if not url.startswith(("http://", "https://")):
                raise BadRequest("fetch needs an http(s) url")
            body = args.get("body")
            data = body.encode() if isinstance(body, str) else None
            req = urllib.request.Request(url, data=data, method=str(args.get("method") or ("POST" if data else "GET")))
            try:
                with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310 - scheme checked
                    return {"status": resp.status, "bytes": len(resp.read())}
            except urllib.error.HTTPError as exc:
                return {"status": exc.code, "bytes": len(exc.read() or b"")}
        if tool == "terminal":
            argv = shlex.split(str(args.get("command") or ""))
            if not argv or argv[0] != "curl":
                raise BadRequest("the demo terminal only runs curl")
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=30)  # noqa: S603
            return {"exit_code": proc.returncode, "stdout": proc.stdout[-2000:], "stderr": proc.stderr[-2000:]}
        return {"simulated": True, "tool": tool}


def make_server(agent: FakeHermes, host: str, port: int) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *a):
            log.info("%s " + fmt, self.address_string(), *a)

        def _reply(self, status: int, payload: dict) -> None:
            data = json.dumps(payload, ensure_ascii=False).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):  # noqa: N802
            if self.path == "/healthz":
                return self._reply(200, {"ok": True, "agent": agent.plugin.config.agent_name})
            return self._reply(404, {"error": "not found"})

        def do_POST(self):  # noqa: N802
            if self.path != "/run":
                return self._reply(404, {"error": "not found"})
            try:
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
                if not isinstance(body, dict):
                    raise BadRequest("body must be a JSON object")
                out = agent.run(str(body.get("tool") or ""), body.get("args"),
                                str(body.get("conversation_id") or "demo-conversation"))
                return self._reply(200, out)
            except (BadRequest, ValueError) as exc:
                return self._reply(400, {"error": str(exc)})

    server = ThreadingHTTPServer((host, port), Handler)
    server.daemon_threads = True
    return server


def main() -> int:
    logging.basicConfig(level=logging.INFO, stream=sys.stderr, format="%(asctime)s %(name)s %(message)s")
    agent = FakeHermes()
    server = make_server(agent, os.environ.get("DEMO_HOST", "0.0.0.0"), int(os.environ.get("DEMO_PORT", "8080")))
    log.info("fake Hermes agent %s listening on %s", agent.plugin.config.agent_name, server.server_address)
    try:
        server.serve_forever()
    finally:
        agent.plugin.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
