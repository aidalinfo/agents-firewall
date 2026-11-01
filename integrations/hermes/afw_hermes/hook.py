"""Command-line hook, drop-in replacement for egress-guard's ``hook_entry.py``.

Usage (Hermes ``config.yaml``)::

    hooks:
      pre_tool_call:
        - command: "python -m afw_hermes.hook"
          matcher: "terminal|fetch|mail.*|teams.*|glpi.*|coolify.*|freepik.*"
          timeout: 5
      post_tool_call:
        - command: "python -m afw_hermes.hook"

Reads one JSON object on stdin. Accepted shapes:
- Hermes shell hooks: ``{"hook_event_name", "tool_name", "tool_input", "session_id", "extra"}``;
- egress-guard: ``{"tool", "args"}`` (treated as ``pre_tool_call``).

Writes one JSON object on stdout. ``afw_decision`` is always ``allow|log|gate|deny``; when the call
must not run, the object also carries ``{"action": "block", "message"}`` (Hermes) and
``{"decision": "block", "reason"}`` (Claude Code style) and the exit code is 2. Internal errors
exit 1 (Hermes then applies the hook's ``fail_closed`` setting).

The hook never touches the network: it uses the cached intent policy and appends events to the
disk spool; a detached ``python -m afw_hermes.flush`` delivers them and refreshes the policy.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Mapping, TextIO

from .config import Config, load_config
from .events import ToolCallEvent
from .intent import PolicyStore
from .plugin import AfwPlugin, conversation_id
from .sender import Spool

EXIT_BLOCK = 2
_PENDING_TTL_SECS = 24 * 3600
_SPAWN_MIN_INTERVAL = 1.0


def _pending_path(config: Config, key: tuple) -> Path:
    digest = hashlib.sha256(json.dumps(key, ensure_ascii=False, default=str).encode()).hexdigest()
    return config.state_dir / "pending" / f"{digest}.json"


def _write_pending(path: Path, event: ToolCallEvent, blocked: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(f".{os.getpid()}.tmp")
    tmp.write_text(json.dumps({"event": event.to_dict(), "blocked": blocked}), encoding="utf-8")
    os.replace(tmp, path)


def _read_pending(path: Path | None) -> dict | None:
    if path is None:
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        path.unlink(missing_ok=True)
        return data
    except (OSError, ValueError):
        return None


def _gc_pending(config: Config) -> None:
    now = time.time()
    try:
        for p in (config.state_dir / "pending").iterdir():
            if now - p.stat().st_mtime > _PENDING_TTL_SECS:
                p.unlink(missing_ok=True)
    except OSError:
        pass


def _spawn_flusher(config: Config, env: Mapping[str, str]) -> None:
    if not config.console_url or env.get("AFW_HOOK_NO_FLUSH"):
        return
    marker = config.state_dir / ".flush-spawned"
    try:
        if time.time() - marker.stat().st_mtime < _SPAWN_MIN_INTERVAL:
            return
    except OSError:
        pass
    try:
        marker.touch()
        child_env = dict(env)
        pkg_parent = str(Path(__file__).resolve().parent.parent)
        child_env["PYTHONPATH"] = os.pathsep.join(filter(None, [pkg_parent, env.get("PYTHONPATH")]))
        subprocess.Popen(  # noqa: S603 - fixed argv, no shell
            [sys.executable, "-m", "afw_hermes.flush"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True, close_fds=True, env=child_env,
        )
    except OSError:
        pass


def handle(payload: Mapping[str, Any], config: Config) -> tuple[dict, int]:
    """Process one hook invocation; returns ``(stdout_object, exit_code)``."""
    extra = payload.get("extra") if isinstance(payload.get("extra"), Mapping) else {}
    event_name = str(payload.get("hook_event_name") or "pre_tool_call")
    tool = str(payload.get("tool_name") or payload.get("tool") or payload.get("name") or "")
    args = next((payload[k] for k in ("tool_input", "args", "arguments", "input") if k in payload), None)
    context = {**extra, **{k: v for k, v in payload.items() if k != "extra"}}
    conv = conversation_id(context, {})
    try:
        pending: Path | None = _pending_path(config, AfwPlugin._key(conv, tool, args, {}, context))
    except Exception:  # noqa: BLE001 - correlation is best effort, the decision is not
        pending = None
    spool = Spool(config)

    if event_name == "post_tool_call":
        try:
            _report_end(payload, extra, config, conv, tool, args, pending, spool)
        except Exception as exc:  # noqa: BLE001
            print(f"afw-hermes: tool-call event not recorded: {exc}", file=sys.stderr)
        return {}, 0

    if event_name != "pre_tool_call":
        return {}, 0

    return _decide(config, conv, tool, args, pending, spool)


def _report_end(payload, extra, config, conv, tool, args, pending, spool) -> None:
    entry = _read_pending(pending)
    status = extra.get("status") or payload.get("status")
    if not isinstance(status, str) or not status:
        status = "error" if (extra.get("error_type") or extra.get("error_message")) else "ok"
    if entry is None:
        if status != "blocked":
            spool.append([ToolCallEvent.start(config.agent_name, conv, tool, args).finished(status).to_dict()])
    elif not entry.get("blocked"):
        ev = ToolCallEvent(**entry["event"])
        spool.append([ev.finished(status).to_dict()])


def _decide(config: Config, conv: str, tool: str, args: Any, pending: Path | None, spool: Spool) -> tuple[dict, int]:
    # Decision first; the hook never touches the network (no background refresh).
    verdict = PolicyStore(config).evaluate(tool, args, refresh=False)
    out: dict[str, Any] = {
        "afw_decision": verdict.decision,
        "afw_class": verdict.action_class.id if verdict.action_class else None,
    }
    code = 0
    if verdict.blocked:
        msg = verdict.message
        out.update({"action": "block", "message": msg, "decision": "block", "reason": msg})
        code = EXIT_BLOCK
    # Reporting, best effort: a full or read-only disk never changes the answer.
    try:
        event = ToolCallEvent.start(config.agent_name, conv, tool, args)
        if verdict.blocked:
            event = event.finished("gated" if verdict.decision == "gate" else "denied")
        if pending is not None:
            _write_pending(pending, event, verdict.blocked)
        spool.append([event.to_dict()])
    except Exception as exc:  # noqa: BLE001
        print(f"afw-hermes: tool-call event not recorded: {exc}", file=sys.stderr)
    return out, code


def main(argv: list[str] | None = None, stdin: TextIO | None = None, stdout: TextIO | None = None,
         env: Mapping[str, str] | None = None) -> int:
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    env = dict(os.environ if env is None else env)
    try:
        payload = json.loads(stdin.read() or "{}")
        if not isinstance(payload, dict):
            raise ValueError("hook input must be a JSON object")
        config = load_config(env)
        out, code = handle(payload, config)
    except Exception as exc:  # noqa: BLE001
        print(f"afw-hermes: hook error: {exc}", file=sys.stderr)
        return 1
    stdout.write(json.dumps(out, ensure_ascii=False) + "\n")
    stdout.flush()
    _gc_pending(config)
    _spawn_flusher(config, env)
    return code


if __name__ == "__main__":
    sys.exit(main())
