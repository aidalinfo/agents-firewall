"""Configuration of the agents-firewall Hermes plugin.

Sources, by increasing priority: built-in defaults, an optional file (``afw-hermes.yaml`` or
``afw-hermes.json``), then environment variables. The YAML reader only understands flat
``key: value`` lines (no runtime dependency outside the standard library).
"""

from __future__ import annotations

import json
import logging
import os
import socket
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any, Mapping

log = logging.getLogger("afw_hermes")

#: The hook path never waits longer than this on anything (seconds).
MAX_HOOK_TIMEOUT = 0.05


@dataclass(frozen=True)
class Config:
    console_url: str | None = None
    agent_token: str | None = field(default=None, repr=False)
    agent_name: str = field(default_factory=lambda: socket.gethostname() or "hermes-agent")
    ca_file: str | None = None
    state_dir: Path = field(default_factory=lambda: _default_state_dir())
    hook_timeout: float = MAX_HOOK_TIMEOUT
    send_timeout: float = 5.0
    policy_timeout: float = 5.0
    flush_interval: float = 1.0
    batch_size: int = 100
    queue_size: int = 10_000
    spool_max_bytes: int = 5_000_000
    policy_refresh_interval: float = 60.0
    backoff_initial: float = 0.5
    backoff_max: float = 30.0

    @property
    def ingest_url(self) -> str | None:
        return f"{self.console_url}/api/v1/ingest/tool-calls" if self.console_url else None

    @property
    def policy_url(self) -> str | None:
        return f"{self.console_url}/api/v1/intent-policy" if self.console_url else None


# env var -> (file key, converter)
_ENV = {
    "AFW_CONSOLE_URL": ("console_url", str),
    "AFW_AGENT_TOKEN": ("agent_token", str),
    "AFW_AGENT_NAME": ("agent_name", str),
    "AFW_CA_FILE": ("ca_file", str),
    "AFW_STATE_DIR": ("state_dir", str),
    "AFW_HOOK_TIMEOUT_MS": ("hook_timeout_ms", float),
    "AFW_SEND_TIMEOUT_MS": ("send_timeout_ms", float),
    "AFW_POLICY_TIMEOUT_MS": ("policy_timeout_ms", float),
    "AFW_FLUSH_INTERVAL_MS": ("flush_interval_ms", float),
    "AFW_BATCH_SIZE": ("batch_size", int),
    "AFW_QUEUE_SIZE": ("queue_size", int),
    "AFW_SPOOL_MAX_BYTES": ("spool_max_bytes", int),
    "AFW_POLICY_REFRESH_SECS": ("policy_refresh_secs", float),
}


def _hermes_home(env: Mapping[str, str] | None = None) -> Path:
    env = os.environ if env is None else env
    home = env.get("HERMES_HOME")
    return Path(home) if home else Path.home() / ".hermes"


def _default_state_dir(env: Mapping[str, str] | None = None) -> Path:
    """Outside the agent's Hermes home and workspace (ADR 0015): XDG state directory."""
    env = os.environ if env is None else env
    base = env.get("XDG_STATE_HOME")
    if not base:
        home = env.get("HOME")
        base = str(Path(home) / ".local" / "state") if home else str(Path.home() / ".local" / "state")
    return Path(base) / "afw-hermes"


def _parse_flat_yaml(text: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, _, value = line.partition(":")
        value = value.strip()
        if value and value[0] in "\"'" and value[-1] == value[0] and len(value) >= 2:
            value = value[1:-1]
        elif " #" in value:
            value = value.split(" #", 1)[0].strip()
        out[key.strip()] = value
    return out


def _read_file(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return {}
    try:
        if path.suffix == ".json":
            data = json.loads(text)
            return data if isinstance(data, dict) else {}
        return _parse_flat_yaml(text)
    except ValueError as exc:
        log.warning("afw-hermes: unreadable config file %s: %s", path, exc)
        return {}


def load_config(env: Mapping[str, str] | None = None, path: str | Path | None = None,
                search: bool = True) -> Config:
    """Build the configuration from defaults, optional file and environment."""
    env = dict(os.environ if env is None else env)
    values: dict[str, Any] = {}

    candidates: list[Path] = []
    if path:
        candidates.append(Path(path))
    elif env.get("AFW_HERMES_CONFIG"):
        candidates.append(Path(env["AFW_HERMES_CONFIG"]))
    elif search:
        home = _hermes_home(env)
        candidates += [home / "afw-hermes.yaml", home / "afw-hermes.yml", home / "afw-hermes.json"]
    for candidate in candidates:
        if candidate.is_file():
            values.update(_read_file(candidate))
            break

    for name, (key, _conv) in _ENV.items():
        if env.get(name):
            values[key] = env[name]

    def num(key: str, conv=float):
        try:
            return conv(values[key])
        except (KeyError, TypeError, ValueError):
            return None

    kwargs: dict[str, Any] = {}
    for key in ("console_url", "agent_token", "agent_name", "ca_file"):
        if values.get(key):
            kwargs[key] = str(values[key]).strip()
    if "console_url" in kwargs:
        kwargs["console_url"] = kwargs["console_url"].rstrip("/")
    kwargs["state_dir"] = Path(values["state_dir"]) if values.get("state_dir") else _default_state_dir(env)
    for key, attr in (("hook_timeout_ms", "hook_timeout"), ("send_timeout_ms", "send_timeout"),
                      ("policy_timeout_ms", "policy_timeout"), ("flush_interval_ms", "flush_interval")):
        v = num(key)
        if v is not None and v > 0:
            kwargs[attr] = v / 1000.0
    for key in ("batch_size", "queue_size", "spool_max_bytes"):
        v = num(key, int)
        if v is not None and v > 0:
            kwargs[key] = v
    v = num("policy_refresh_secs")
    if v is not None and v > 0:
        kwargs["policy_refresh_interval"] = v
    kwargs["hook_timeout"] = min(kwargs.get("hook_timeout", MAX_HOOK_TIMEOUT), MAX_HOOK_TIMEOUT)

    known = {f.name for f in fields(Config)}
    return Config(**{k: v for k, v in kwargs.items() if k in known})
