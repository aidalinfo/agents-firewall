"""Intent stage: action classes inherited from egress-guard and their decision.

The plugin only carries *action classes* (irreversible, access, infra_destructive, paid_generation)
and their "gate"; destinations and data classes are enforced by the gateway (design §15).

A class matches a tool call when
- ``tools`` is empty or one of its globs matches the tool name (case-insensitive), and
- ``patterns`` is empty or one of its regexes matches the *subject*: the tool name on the first
  line, then one line per argument (``key: value`` for scalars, every string of nested structures),
  NFKC-normalised. ``^``/``\\A`` therefore anchor on the tool name.
When several classes match, the strictest decision wins (deny > gate > log > allow); ties go to
the first class in policy order.
"""

from __future__ import annotations

import fnmatch
import json
import logging
import os
import re
import tempfile
import threading
import time
import unicodedata
from dataclasses import dataclass
from typing import Any

from .config import Config
from .transport import request_json

log = logging.getLogger("afw_hermes")

DECISIONS = ("allow", "log", "gate", "deny")
_RANK = {d: i for i, d in enumerate(DECISIONS)}
CACHE_FILE = "intent-policy.json"


class PolicyError(ValueError):
    """The intent policy document is invalid."""


@dataclass(frozen=True)
class ActionClass:
    id: str
    name: str
    tools: tuple[str, ...]
    patterns: tuple[str, ...]
    decision: str
    compiled: tuple[re.Pattern[str], ...] = ()

    def matches(self, tool: str, subject: str) -> bool:
        if self.tools and not any(fnmatch.fnmatchcase(tool.lower(), g.lower()) for g in self.tools):
            return False
        if self.compiled and not any(p.search(subject) for p in self.compiled):
            return False
        return True


@dataclass(frozen=True)
class IntentPolicy:
    version: int
    action_classes: tuple[ActionClass, ...]
    raw: dict

    @classmethod
    def from_json(cls, doc: Any) -> "IntentPolicy":
        if not isinstance(doc, dict):
            raise PolicyError("policy must be an object")
        version = doc.get("version")
        if not isinstance(version, int) or isinstance(version, bool):
            raise PolicyError("version must be an integer")
        items = doc.get("action_classes")
        if not isinstance(items, list):
            raise PolicyError("action_classes must be a list")
        classes = []
        for i, item in enumerate(items):
            if not isinstance(item, dict):
                raise PolicyError(f"action_classes[{i}] must be an object")
            cid, name, decision = item.get("id"), item.get("name", item.get("id")), item.get("decision")
            if not isinstance(cid, str) or not cid:
                raise PolicyError(f"action_classes[{i}].id is required")
            if decision not in DECISIONS:
                raise PolicyError(f"action_classes[{i}].decision must be one of {DECISIONS}")
            tools = item.get("tools", [])
            patterns = item.get("patterns", [])
            if not isinstance(tools, list) or not isinstance(patterns, list):
                raise PolicyError(f"action_classes[{i}]: tools and patterns must be lists")
            if not all(isinstance(t, str) for t in tools) or not all(isinstance(p, str) for p in patterns):
                raise PolicyError(f"action_classes[{i}]: tools and patterns must be strings")
            try:
                compiled = tuple(re.compile(p) for p in patterns)
            except re.error as exc:
                raise PolicyError(f"action_classes[{i}]: invalid pattern: {exc}") from exc
            classes.append(ActionClass(cid, str(name), tuple(tools), tuple(patterns), decision, compiled))
        return cls(version, tuple(classes), doc)


@dataclass(frozen=True)
class Verdict:
    decision: str
    action_class: ActionClass | None
    tool: str

    @property
    def blocked(self) -> bool:
        return self.decision in ("gate", "deny")

    @property
    def message(self) -> str | None:
        if not self.blocked or self.action_class is None:
            return None
        what = f"{self.action_class.name} (outil « {self.tool} »)"
        if self.decision == "gate":
            return (f"action soumise à validation humaine : {what}. L'action n'a pas été exécutée ; "
                    "demandez l'accord explicite d'un humain avant de la retenter.")
        return f"action refusée par la politique d'agents-firewall : {what}. Ne la retentez pas."

    def as_hermes(self) -> dict | None:
        """Hermes ``pre_tool_call`` directive: ``None`` lets the call run."""
        if not self.blocked:
            return None
        return {"action": "block", "message": self.message}


# ------------------------------------------------------------------------------------------
# Built-in default policy (prudent): used when no console policy was ever fetched.
# ------------------------------------------------------------------------------------------

_SEG = r"[^\n;&|]*"  # rest of the same shell command segment

#: Tools that execute commands or code: shell/SQL/HTTP-verb patterns only apply to them.
EXEC_TOOLS = ["terminal", "*terminal*", "shell", "*shell*", "bash", "sh", "zsh", "execute_code",
              "*exec*", "run_command", "*command*", "code_interpreter", "*python*", "process", "*ssh*"]
#: Tools that perform HTTP requests from structured arguments (``method: DELETE``).
HTTP_TOOLS = ["fetch", "*fetch*", "http", "http_*", "*_http", "*request*", "curl", "web_*", "api_call", "*api*"]
#: Name of the tool (first subject line) — applies to every tool.
_TOOL = r"(?i)\A[^\n]*"

DEFAULT_POLICY_DOC: dict = {
    "version": 0,
    "action_classes": [
        {
            "id": "infra_destructive",
            "name": "Infrastructure destructive",
            "tools": EXEC_TOOLS,
            "patterns": [
                rf"(?i)\bkubectl\b{_SEG}\s(?:delete|drain)\b",
                rf"(?i)\bhelm\b{_SEG}\s(?:uninstall|delete|rollback)\b",
                rf"(?i)\bdocker\b{_SEG}\s(?:rm|rmi|kill|prune)\b",
                rf"(?i)\bdocker(?:-compose|\s+compose)\b{_SEG}\s(?:down|rm)\b",
                rf"(?i)\bterraform\b{_SEG}\s-?destroy\b",
                r"(?i)/api/v1/(?:deploy\b|(?:applications|services|databases)/[^\s/]+/(?:restart|stop|deploy)\b)",
            ],
            "decision": "gate",
        },
        {
            "id": "infra_destructive",
            "name": "Infrastructure destructive",
            "tools": [],
            "patterns": [
                _TOOL + r"coolify[^\n]*(?:delete|redeploy|deploy|restart|stop|remove)",
                _TOOL + r"coolify[\s\S]*\b(?:delete|redeploy|deploy|restart|stop|remove)\b",
            ],
            "decision": "gate",
        },
        {
            "id": "infra_destructive",
            "name": "Infrastructure destructive",
            "tools": HTTP_TOOLS,
            "patterns": [
                r"(?i)/api/v1/(?:deploy\b|(?:applications|services|databases)/[^\s/]+/(?:restart|stop|deploy)\b)",
            ],
            "decision": "gate",
        },
        {
            "id": "access",
            "name": "Partage et droits d'accès",
            "tools": [],
            "patterns": [
                _TOOL + r"(?:share|sharing|invite|invitation|permission|grant|collaborator|"
                r"add_member|add_user|set_role|acl)",
                r"(?i)\banyone\s+with\s+the\s+link\b|\btype\s*:\s*[\"']?anyone\b",
            ],
            "decision": "gate",
        },
        {
            "id": "access",
            "name": "Partage et droits d'accès",
            "tools": EXEC_TOOLS,
            "patterns": [
                rf"(?i)\bchmod\b{_SEG}(?:\b0?[0-7]{{2}}[2367]\b|\b[oa]\+[rx]*w)",
                r"(?i)\bchown\b",
                r"(?i)\bgrant\s+[\w\s,]+?\s+on\b",
                r"(?i)\b(?:create|alter)\s+(?:user|role)\b",
                rf"(?i)\bkubectl\b{_SEG}\bcreate\s+(?:cluster)?rolebinding\b",
            ],
            "decision": "gate",
        },
        {
            "id": "irreversible",
            "name": "Suppression irréversible",
            "tools": [],
            "patterns": [
                _TOOL + r"(?:(?<![a-z0-9])(?:delete|purge|destroy)_|[a-z0-9]_(?:delete|purge|destroy)(?![a-z0-9]))",
            ],
            "decision": "gate",
        },
        {
            "id": "irreversible",
            "name": "Suppression irréversible",
            "tools": EXEC_TOOLS,
            "patterns": [
                rf"(?i)(?<![-\w])rm\b{_SEG}?\s(?:-[a-z]*r[a-z]*\b|--recursive\b)",
                r"(?i)(?<![-\w])rmdir\b",
                r"(?i)\bshred\b",
                rf"(?i)\bfind\b{_SEG}\s-delete\b",
                r"(?i)\bshutil\s*\.\s*rmtree\b",
                rf"(?i)\bgit\b{_SEG}\bpush\b{_SEG}\s(?:--force(?:-with-lease)?\b|-[a-z]*f\b|\+\S)",
                r"(?i)(?:\s-X\s*|--request[=\s]+)[\"']?DELETE\b",
                r"(?i)\bdelete\s+from\b",
                r"(?i)\b(?:drop|truncate)\s+(?:table|database|schema|collection)\b",
            ],
            "decision": "gate",
        },
        {
            "id": "irreversible",
            "name": "Suppression irréversible",
            "tools": HTTP_TOOLS,
            "patterns": [r"(?i)\bmethod\s*:\s*[\"']?delete\b"],
            "decision": "gate",
        },
        {
            "id": "paid_generation",
            "name": "Génération payante",
            "tools": [],
            "patterns": [
                _TOOL + r"(?:freepik|image_?gen|generate_image|image_generate|text_to_image|video_?gen|"
                r"generate_video|video_generate|text_to_video|dall_?e|midjourney|runway|elevenlabs|suno)",
                r"(?i)\bfreepik\.com\b",
            ],
            "decision": "log",
        },
    ],
}

#: File-writing tools: their content arguments are data, not commands, and are not scanned.
WRITE_TOOLS = ["write_file", "*write*", "edit_file", "*edit*", "create_file", "*patch*", "str_replace*",
               "*save*", "append_file", "notebook*"]
CONTENT_KEYS = frozenset({"content", "contents", "patch", "text", "body", "new_string", "old_string",
                          "new_str", "old_str", "diff", "data", "file_text", "insert_text"})

DEFAULT_POLICY = IntentPolicy.from_json(DEFAULT_POLICY_DOC)


def _is_write_tool(tool: str) -> bool:
    low = tool.lower()
    return any(fnmatch.fnmatchcase(low, g) for g in WRITE_TOOLS)


def _subject(tool: str, args: Any) -> str:
    lines = [tool]
    skip_content = _is_write_tool(tool)

    def walk(value: Any, depth: int = 0) -> None:
        if depth > 20:
            return
        if isinstance(value, dict):
            for k, v in value.items():
                if depth == 0 and skip_content and str(k).lower() in CONTENT_KEYS:
                    continue
                if isinstance(v, (dict, list, tuple)):
                    lines.append(str(k))
                    walk(v, depth + 1)
                else:
                    lines.append(f"{k}: {'' if v is None else v}")
        elif isinstance(value, (list, tuple)):
            for v in value:
                walk(v, depth + 1)
        elif value is not None:
            lines.append(str(value))

    walk(args)
    return unicodedata.normalize("NFKC", "\n".join(lines))


def evaluate(policy: IntentPolicy, tool: str, args: Any) -> Verdict:
    tool = unicodedata.normalize("NFKC", str(tool or ""))
    subject = _subject(tool, args)
    best: ActionClass | None = None
    for cls in policy.action_classes:
        if cls.matches(tool, subject) and (best is None or _RANK[cls.decision] > _RANK[best.decision]):
            best = cls
    return Verdict(best.decision if best else "allow", best, tool)


# ------------------------------------------------------------------------------------------
# Policy store: console policy, cached in memory and on disk, refreshed in the background.
# ------------------------------------------------------------------------------------------

class PolicyStore:
    """Current intent policy: console > last known (memory, then disk) > built-in default."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self._lock = threading.Lock()
        self._refreshing = False
        self._last_attempt = float("-inf")
        self._policy, self.source = DEFAULT_POLICY, "builtin"
        cached = self._load_cache()
        if cached is not None:
            self._policy, self.source = cached, "cache"

    @property
    def cache_path(self):
        return self.config.state_dir / CACHE_FILE

    def current(self) -> IntentPolicy:
        return self._policy

    def cache_age(self) -> float | None:
        try:
            return max(0.0, time.time() - self.cache_path.stat().st_mtime)
        except OSError:
            return None

    def _load_cache(self) -> IntentPolicy | None:
        try:
            return IntentPolicy.from_json(json.loads(self.cache_path.read_text(encoding="utf-8")))
        except FileNotFoundError:
            return None
        except (OSError, ValueError) as exc:
            log.warning("afw-hermes: ignoring invalid cached intent policy: %s", exc)
            return None

    def _save_cache(self, doc: dict) -> None:
        try:
            self.config.state_dir.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=self.config.state_dir, prefix=".policy-")
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(doc, fh)
            os.replace(tmp, self.cache_path)
        except OSError as exc:
            log.warning("afw-hermes: cannot write intent policy cache: %s", exc)

    def refresh(self) -> bool:
        """Fetch the console policy (blocking). Returns True when a valid policy was applied."""
        self._last_attempt = time.monotonic()
        url = self.config.policy_url
        if not url:
            return False
        try:
            status, body = request_json(self.config, "GET", url, None, self.config.policy_timeout)
            if status != 200:
                log.warning("afw-hermes: intent policy fetch returned HTTP %s", status)
                return False
            doc = json.loads(body)
            policy = IntentPolicy.from_json(doc)
        except (OSError, ValueError) as exc:
            log.warning("afw-hermes: intent policy unavailable, keeping %s policy: %s", self.source, exc)
            return False
        with self._lock:
            self._policy, self.source = policy, "remote"
        self._save_cache(policy.raw)
        return True

    def maybe_refresh(self) -> None:
        """Start a background refresh when the policy is stale. Never blocks."""
        if not self.config.policy_url:
            return
        with self._lock:
            if self._refreshing or time.monotonic() - self._last_attempt < self.config.policy_refresh_interval:
                return
            self._refreshing = True
            self._last_attempt = time.monotonic()

        def run() -> None:
            try:
                self.refresh()
            finally:
                self._refreshing = False

        threading.Thread(target=run, name="afw-hermes-policy", daemon=True).start()

    def evaluate(self, tool: str, args: Any, refresh: bool = True) -> Verdict:
        """Evaluate a call. ``refresh=False`` guarantees no network activity (CLI hook)."""
        if refresh:
            self.maybe_refresh()
        try:
            return evaluate(self._policy, tool, args)
        except Exception:  # noqa: BLE001 - never let a bad policy disable the default guard
            log.exception("afw-hermes: intent evaluation failed, using built-in policy")
            return evaluate(DEFAULT_POLICY, tool, args)
