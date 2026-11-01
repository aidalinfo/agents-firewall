import json
import os
import subprocess
import sys
import time

from conftest import wait_until

from afw_hermes import flush


def run_hook(payload, state_dir, console_url=None, extra_env=None, raw=None):
    env = {k: v for k, v in os.environ.items() if not k.startswith("AFW_")}
    env.update({"AFW_STATE_DIR": str(state_dir), "AFW_AGENT_NAME": "daniel-bot", "AFW_AGENT_TOKEN": "tok",
                "AFW_HOOK_NO_FLUSH": "1", "HERMES_HOME": str(state_dir)})
    if console_url:
        env["AFW_CONSOLE_URL"] = console_url
    env.update(extra_env or {})
    data = raw if raw is not None else json.dumps(payload)
    return subprocess.run([sys.executable, "-m", "afw_hermes.hook"], input=data, capture_output=True,
                          text=True, env=env, timeout=20)


def spool_events(state_dir):
    p = state_dir / "spool.jsonl"
    return [json.loads(line) for line in p.read_text().splitlines()] if p.exists() else []


def test_egress_guard_style_gate(tmp_path):
    r = run_hook({"tool": "terminal", "args": {"command": "rm -rf /data"}}, tmp_path)
    assert r.returncode == 2, r.stderr
    out = json.loads(r.stdout)
    assert out["action"] == "block" and out["decision"] == "block"
    assert out["message"] == out["reason"]
    assert out["message"].startswith("action soumise à validation humaine")
    assert out["afw_decision"] == "gate"
    assert out["afw_class"] == "irreversible"
    evs = spool_events(tmp_path)
    assert len(evs) == 1 and evs[0]["status"] == "gated"


def test_hermes_shell_hook_allow_then_post_correlates(tmp_path):
    pre = {"hook_event_name": "pre_tool_call", "tool_name": "terminal",
           "tool_input": {"command": "curl https://example.com"}, "session_id": "sess-1",
           "cwd": "/w", "extra": {"task_id": "t"}}
    r = run_hook(pre, tmp_path)
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout)
    assert "action" not in out and "decision" not in out
    assert out["afw_decision"] == "allow"
    post = dict(pre, hook_event_name="post_tool_call", extra={"task_id": "t", "status": "ok"})
    r = run_hook(post, tmp_path)
    assert r.returncode == 0, r.stderr
    start, end = spool_events(tmp_path)
    assert start["id"] == end["id"]
    assert start["conversation_id"] == "sess-1"
    assert start["ended_at"] is None
    assert end["status"] == "ok" and end["ended_at"]


def test_tool_call_id_in_extra_used_for_correlation(tmp_path):
    base = {"tool_name": "fetch", "tool_input": {"url": "https://a"}, "session_id": "s"}
    run_hook(dict(base, hook_event_name="pre_tool_call", extra={"tool_call_id": "c1"}), tmp_path)
    run_hook(dict(base, hook_event_name="pre_tool_call", extra={"tool_call_id": "c2"}), tmp_path)
    run_hook(dict(base, hook_event_name="post_tool_call", extra={"tool_call_id": "c2"}), tmp_path)
    evs = spool_events(tmp_path)
    assert evs[2]["id"] == evs[1]["id"] != evs[0]["id"]


def test_invalid_stdin_exits_nonzero(tmp_path):
    r = run_hook(None, tmp_path, raw="{nope")
    assert r.returncode == 1
    assert "afw-hermes" in r.stderr


def test_hook_is_fast(tmp_path):
    t0 = time.monotonic()
    run_hook({"tool": "terminal", "args": {"command": "ls"}}, tmp_path, console_url="http://10.255.255.1:9")
    # process startup included; the hook itself never waits on the network
    assert time.monotonic() - t0 < 5


def test_flush_delivers_spool_and_caches_policy(tmp_path, console):
    console.policy = {"version": 5, "action_classes": [
        {"id": "custom", "name": "Mail", "tools": ["send_mail"], "patterns": [], "decision": "gate"}]}
    run_hook({"tool": "terminal", "args": {"command": "ls"}}, tmp_path)
    assert len(spool_events(tmp_path)) == 1
    env = {"AFW_STATE_DIR": str(tmp_path), "AFW_CONSOLE_URL": console.url, "AFW_AGENT_TOKEN": "tok",
           "HERMES_HOME": str(tmp_path)}
    assert flush.main(env=env) == 0
    assert len(console.ingested_events()) == 1
    assert console.ingest_requests()[0]["headers"]["authorization"] == "Bearer tok"
    assert spool_events(tmp_path) == []
    # the hook now applies the cached remote policy, without network
    r = run_hook({"tool": "send_mail", "args": {}}, tmp_path)
    assert r.returncode == 2
    assert json.loads(r.stdout)["afw_class"] == "custom"


def test_hook_spawns_detached_flusher(tmp_path, console):
    r = run_hook({"tool": "terminal", "args": {"command": "ls"}}, tmp_path, console_url=console.url,
                 extra_env={"AFW_HOOK_NO_FLUSH": ""})
    assert r.returncode == 0, r.stderr
    assert wait_until(lambda: len(console.ingested_events()) == 1, timeout=15)
