import time

from conftest import wait_until

import afw_hermes
from afw_hermes.plugin import AfwPlugin


class FakeCtx:
    def __init__(self):
        self.hooks = {}

    def register_hook(self, name, fn):
        self.hooks.setdefault(name, []).append(fn)


def test_register_wires_both_hooks(make_config, monkeypatch):
    monkeypatch.setenv("AFW_STATE_DIR", str(make_config().state_dir))
    ctx = FakeCtx()
    afw_hermes.register(ctx)
    assert set(ctx.hooks) == {"pre_tool_call", "post_tool_call"}


def test_register_tolerates_old_hermes_without_register_hook():
    afw_hermes.register(object())  # must not raise


def make_plugin(console, make_config, **kw):
    p = AfwPlugin(make_config(console.url, **kw))
    p.start()
    return p


def test_allowed_call_sends_start_and_end_with_same_id(console, make_config):
    p = make_plugin(console, make_config)
    try:
        assert p.pre_tool_call(tool_name="terminal", args={"command": "ls"}, task_id="t1",
                               session_id="sess-42", tool_call_id="call-1") is None
        p.post_tool_call(tool_name="terminal", args={"command": "ls"}, result="ok", task_id="t1",
                         session_id="sess-42", tool_call_id="call-1", duration_ms=5)
        assert p.sender.flush(timeout=5)
    finally:
        p.close()
    evs = console.ingested_events()
    assert len(evs) == 2
    start, end = evs
    assert start["id"] == end["id"]
    assert start["ended_at"] is None and start["status"] is None
    assert end["ended_at"] is not None and end["status"] == "ok"
    assert start["conversation_id"] == "sess-42"
    assert start["agent"] == "daniel-bot"


def test_correlation_without_tool_call_id(console, make_config):
    p = make_plugin(console, make_config)
    try:
        p.pre_tool_call(tool_name="fetch", args={"url": "https://a"}, task_id="t1")
        p.post_tool_call(tool_name="fetch", args={"url": "https://a"}, result="x", task_id="t1",
                         status="error", error_message="boom")
        p.sender.flush(timeout=5)
    finally:
        p.close()
    start, end = console.ingested_events()
    assert start["id"] == end["id"]
    assert start["conversation_id"] == "t1"
    assert end["status"] == "error"


def test_context_dict_conversation_id(console, make_config):
    p = make_plugin(console, make_config)
    try:
        p.pre_tool_call("terminal", {"command": "ls"}, {"conversation_id": "conv-9"})
        p.sender.flush(timeout=5)
    finally:
        p.close()
    assert console.ingested_events()[0]["conversation_id"] == "conv-9"


def test_gated_call_blocked_and_reported(console, make_config):
    p = make_plugin(console, make_config)
    try:
        out = p.pre_tool_call(tool_name="terminal", args={"command": "kubectl delete ns prod"},
                              session_id="s", tool_call_id="c")
        assert out["action"] == "block"
        assert out["message"].startswith("action soumise à validation humaine")
        # Hermes still emits post_tool_call for blocked calls: it must not create a 2nd event
        p.post_tool_call(tool_name="terminal", args={"command": "kubectl delete ns prod"},
                         result=out["message"], session_id="s", tool_call_id="c", status="blocked")
        p.sender.flush(timeout=5)
    finally:
        p.close()
    evs = console.ingested_events()
    assert len(evs) == 1
    assert evs[0]["status"] == "gated"
    assert evs[0]["ended_at"] is not None


def test_hooks_never_raise(make_config):
    p = AfwPlugin(make_config(None))
    assert p.pre_tool_call(tool_name=None, args=object()) is None
    p.post_tool_call(tool_name=None, args=object(), result=object())


def test_pre_hook_fast_when_console_sleeps(console, make_config):
    console.delay = 2.0
    p = make_plugin(console, make_config)
    try:
        t0 = time.perf_counter()
        for _ in range(20):
            p.pre_tool_call(tool_name="terminal", args={"command": "ls"}, session_id="s")
        assert (time.perf_counter() - t0) / 20 < 0.05
    finally:
        p.close(timeout=0.2)


def test_remote_policy_used_by_plugin(console, make_config):
    console.policy = {"version": 2, "action_classes": [
        {"id": "custom", "name": "Mail", "tools": ["send_mail"], "patterns": [], "decision": "gate"}]}
    p = make_plugin(console, make_config)
    try:
        assert wait_until(lambda: p.policy.current().version == 2)
        assert p.pre_tool_call(tool_name="send_mail", args={})["action"] == "block"
    finally:
        p.close()
