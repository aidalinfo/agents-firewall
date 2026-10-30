"""Hermes Agent plugin: ``pre_tool_call`` / ``post_tool_call`` hooks.

``pre_tool_call`` evaluates the action classes (intent stage) and reports the start of the call;
it returns ``{"action": "block", "message": ...}`` for "gate"/"deny" (Hermes passes the message
back to the model as the tool result) and ``None`` otherwise. ``post_tool_call`` reports the end
of the call with the same event id. Neither hook ever raises nor waits on the network.
"""

from __future__ import annotations

import atexit
import logging
import threading
from collections import OrderedDict, deque
from typing import Any, Mapping

from .config import Config, load_config
from .events import ToolCallEvent, summarize_args
from .intent import DEFAULT_POLICY, PolicyStore, evaluate
from .sender import EventSender

log = logging.getLogger("afw_hermes")

_MAX_PENDING = 4096
_BLOCKED_STATUS = {"gate": "gated", "deny": "denied"}


def _session_env(name: str) -> str:
    """Hermes session context (only available inside the Hermes gateway runtime)."""
    try:
        from gateway.session_context import get_session_env  # type: ignore[import-not-found]

        return str(get_session_env(name, "") or "")
    except Exception:  # noqa: BLE001
        return ""


def _first(*values: Any) -> str:
    for v in values:
        if v not in (None, ""):
            return str(v)
    return ""


def conversation_id(context: Any, kwargs: Mapping[str, Any]) -> str:
    ctx = context if isinstance(context, Mapping) else {}
    return _first(
        kwargs.get("conversation_id"), kwargs.get("session_id"),
        ctx.get("conversation_id"), ctx.get("session_id"),
        _session_env("HERMES_SESSION_ID"), _session_env("HERMES_SESSION_CHAT_ID"),
        kwargs.get("task_id"), ctx.get("task_id"),
    ) or "unknown"


class AfwPlugin:
    def __init__(self, config: Config | None = None) -> None:
        self.config = config or load_config()
        self.sender = EventSender(self.config)
        self.policy = PolicyStore(self.config)
        self._lock = threading.Lock()
        # key -> deque[(event, blocked)]
        self._pending: OrderedDict[tuple, deque] = OrderedDict()

    def start(self) -> None:
        self.sender.start()
        self.policy.maybe_refresh()

    def close(self, timeout: float = 2.0) -> None:
        self.sender.close(timeout)

    # -- correlation between pre and post -------------------------------------------------
    @staticmethod
    def _key(conv: str, tool: str, args: Any, kwargs: Mapping[str, Any], context: Any) -> tuple:
        ctx = context if isinstance(context, Mapping) else {}
        call_id = _first(kwargs.get("tool_call_id"), ctx.get("tool_call_id"))
        if call_id:
            return ("id", call_id)
        return ("call", conv, tool, summarize_args(args))

    def _remember(self, key: tuple, event: ToolCallEvent, blocked: bool) -> None:
        with self._lock:
            self._pending.setdefault(key, deque()).append((event, blocked))
            self._pending.move_to_end(key)
            while len(self._pending) > _MAX_PENDING:
                self._pending.popitem(last=False)

    def _take(self, key: tuple):
        with self._lock:
            entries = self._pending.get(key)
            if not entries:
                return None
            entry = entries.popleft()
            if not entries:
                del self._pending[key]
            return entry

    # -- hooks ------------------------------------------------------------------------------
    def pre_tool_call(self, tool_name: Any = None, args: Any = None, context: Any = None,
                      **kwargs: Any) -> dict | None:
        tool = str(tool_name or "")
        # 1. Decision first, isolated: nothing that happens afterwards may reopen the gate.
        try:
            verdict = self.policy.evaluate(tool, args)
        except Exception:  # noqa: BLE001
            log.exception("afw-hermes: intent evaluation failed, using built-in policy")
            try:
                verdict = evaluate(DEFAULT_POLICY, tool, args)
            except Exception:  # noqa: BLE001 - a raising pre hook would block every tool in Hermes
                log.exception("afw-hermes: built-in intent evaluation failed")
                return None
        directive = verdict.as_hermes()
        # 2. Reporting, best effort.
        try:
            conv = conversation_id(context, kwargs)
            event = ToolCallEvent.start(self.config.agent_name, conv, tool, args)
            if verdict.blocked:
                event = event.finished(_BLOCKED_STATUS[verdict.decision])
                log.warning("afw-hermes: %s %s (%s)", verdict.decision, tool, verdict.action_class.id)
            elif verdict.decision == "log":
                log.info("afw-hermes: logged action class %s for %s", verdict.action_class.id, tool)
            self._remember(self._key(conv, tool, args, kwargs, context), event, verdict.blocked)
            self.sender.enqueue(event)
        except Exception:  # noqa: BLE001
            log.exception("afw-hermes: tool-call event not recorded")
        return directive

    def post_tool_call(self, tool_name: Any = None, args: Any = None, result: Any = None,
                       context: Any = None, **kwargs: Any) -> None:
        try:
            tool = str(tool_name or "")
            conv = conversation_id(context, kwargs)
            entry = self._take(self._key(conv, tool, args, kwargs, context))
            status = kwargs.get("status")
            if not isinstance(status, str) or not status:
                status = "error" if (kwargs.get("error_type") or kwargs.get("error_message")) else "ok"
            if entry is None:
                if status == "blocked":
                    return  # blocked by another hook: nothing started
                event = ToolCallEvent.start(self.config.agent_name, conv, tool, args)
            else:
                event, blocked = entry
                if blocked:
                    return  # already reported as gated/denied
            self.sender.enqueue(event.finished(status))
        except Exception:  # noqa: BLE001
            log.exception("afw-hermes: post_tool_call failed")


# ------------------------------------------------------------------------------------------
# Module-level entry points used by Hermes.
# ------------------------------------------------------------------------------------------

_plugin: AfwPlugin | None = None
_plugin_lock = threading.Lock()


def get_plugin() -> AfwPlugin:
    global _plugin
    with _plugin_lock:
        if _plugin is None:
            _plugin = AfwPlugin()
            _plugin.start()
            atexit.register(_plugin.close)
        return _plugin


def pre_tool_call(tool_name: Any = None, args: Any = None, context: Any = None, **kwargs: Any):
    return get_plugin().pre_tool_call(tool_name, args, context, **kwargs)


def post_tool_call(tool_name: Any = None, args: Any = None, result: Any = None, context: Any = None,
                   **kwargs: Any) -> None:
    get_plugin().post_tool_call(tool_name, args, result, context, **kwargs)


def register(ctx: Any) -> None:
    """Hermes plugin entry point."""
    register_hook = getattr(ctx, "register_hook", None)
    if register_hook is None:
        log.warning("afw-hermes: this Hermes has no register_hook; tool-call correlation and "
                    "action-class gating are disabled (use the afw-hermes-hook shell hook instead)")
        return
    get_plugin()
    for name, fn in (("pre_tool_call", pre_tool_call), ("post_tool_call", post_tool_call)):
        try:
            register_hook(name, fn)
        except Exception as exc:  # noqa: BLE001
            log.warning("afw-hermes: hook %s not registered: %s", name, exc)
