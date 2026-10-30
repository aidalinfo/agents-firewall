"""Tool-call events sent to the console for intent <-> flow correlation (ADR 0007).

Wire format (exact): ``{"id", "agent", "conversation_id", "tool", "args_summary", "started_at",
"ended_at", "status"}``. The same ``id`` is sent twice: once when the call starts (``ended_at`` and
``status`` null) and once when it ends.
"""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Any

ARGS_SUMMARY_MAX = 500
MASK = "***"

_SECRET_KEY = re.compile(
    r"(?i)(pass(word|wd)?|pwd|secret|token|api[-_]?key|apikey|auth(orization)?|credential|"
    r"private[-_]?key|cookie|client[-_]?secret|access[-_]?key)"
)

_TEXT_RULES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(-----END [A-Z ]*PRIVATE KEY-----|$)", re.S),
     "-----BEGIN PRIVATE KEY-----" + MASK),
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{6,}"), r"\1 " + MASK),
    (re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://[^:/\s@]+):([^@\s/]+)@"), r"\1:" + MASK + "@"),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{16,}"), MASK),
    (re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})"), MASK),
    (re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), MASK),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), MASK),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}"), MASK),
    (re.compile(
        r"(?i)\b([\w-]*(?:password|passwd|pwd|secret|token|api[-_]?key|apikey|x-api-key|authorization)"
        r"[\w-]*)(\"?'?\s*[:=]\s*\"?'?)(?!\*\*\*)(?!bearer\b|basic\b)([^\s\"'&;,]+)"),
     r"\1\2" + MASK),
]


def mask_secrets(text: str) -> str:
    """Mask obvious secrets (tokens, passwords, keys, URL credentials) in free text."""
    for pattern, repl in _TEXT_RULES:
        text = pattern.sub(repl, text)
    return text


def _mask_structure(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): (MASK if _SECRET_KEY.search(str(k)) and isinstance(v, (str, int, float))
                         else _mask_structure(v)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_mask_structure(v) for v in value]
    return value


def _scalar(value: Any) -> str:
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return str(value)


def summarize_args(args: Any, limit: int = ARGS_SUMMARY_MAX) -> str:
    """Readable, secret-masked summary of tool arguments, at most ``limit`` characters."""
    if args is None:
        return ""
    masked = _mask_structure(args)
    if isinstance(masked, dict):
        text = "; ".join(f"{k}: {_scalar(v)}" for k, v in masked.items())
    else:
        text = _scalar(masked)
    text = mask_secrets(text)
    if len(text) > limit:
        text = text[: limit - 1] + "…"
    return text


def rfc3339(dt: datetime | None = None) -> str:
    """RFC 3339 UTC timestamp with millisecond precision and ``Z`` suffix."""
    dt = dt or datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


@dataclass(frozen=True)
class ToolCallEvent:
    id: str
    agent: str
    conversation_id: str
    tool: str
    args_summary: str
    started_at: str
    ended_at: str | None = None
    status: str | None = None

    @classmethod
    def start(cls, agent: str, conversation_id: str, tool: str, args: Any,
              now: datetime | None = None) -> "ToolCallEvent":
        return cls(
            id=str(uuid.uuid4()),
            agent=agent,
            conversation_id=conversation_id,
            tool=tool,
            args_summary=summarize_args(args),
            started_at=rfc3339(now),
        )

    def finished(self, status: str, now: datetime | None = None) -> "ToolCallEvent":
        return replace(self, ended_at=rfc3339(now), status=status)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "agent": self.agent,
            "conversation_id": self.conversation_id,
            "tool": self.tool,
            "args_summary": self.args_summary,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "status": self.status,
        }
