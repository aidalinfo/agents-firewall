import io, json, os, time, http.server, threading
from pathlib import Path
from afw_hermes.config import Config
from afw_hermes.plugin import AfwPlugin
from afw_hermes.events import summarize_args
from afw_hermes.intent import IntentPolicy, evaluate, DEFAULT_POLICY
from afw_hermes import hook

def cfg(tmp, **kw):
    return Config(console_url=None, agent_token=None, agent_name="a", state_dir=tmp, **kw)

# 1. fail-open: an exception in bookkeeping after the verdict drops the gate
def test_gate_survives_event_failure(tmp_path, monkeypatch):
    p = AfwPlugin(cfg(tmp_path))
    import afw_hermes.plugin as pl
    monkeypatch.setattr(pl.ToolCallEvent, "start", classmethod(lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))))
    r = p.pre_tool_call(tool_name="terminal", args={"command": "rm -rf /srv"}, session_id="s")
    assert r and r["action"] == "block", r

def test_gate_deep_args_recursion(tmp_path):
    p = AfwPlugin(cfg(tmp_path))
    deep = cur = []
    for _ in range(5000):
        nxt = []; cur.append(nxt); cur = nxt
    r = p.pre_tool_call(tool_name="terminal", args={"command": "rm -rf /srv", "x": deep}, session_id="s")
    assert r and r["action"] == "block", r

# 2. CLI hook: unwritable state dir -> exit 1 instead of 2 on a gated command
def test_cli_gate_readonly_state(tmp_path):
    sd = tmp_path / "ro"; sd.mkdir(); os.chmod(sd, 0o500)
    out = io.StringIO()
    code = hook.main(stdin=io.StringIO(json.dumps({"tool": "terminal", "args": {"command": "rm -rf /"}})),
                     stdout=out, env={"AFW_STATE_DIR": str(sd), "HOME": str(tmp_path)})
    assert code == 2, (code, out.getvalue())

# 3. masking gaps
import pytest
@pytest.mark.parametrize("args", [
    {"command": "mysql --password hunter2secret -h db"},
    {"command": "curl -u admin:hunter2secret https://x"},
    {"command": "psql postgresql://u:hunter2secret@db/x"},
    {"command": "gh --token hunter2secret"},
    {"token": ["hunter2secret"]},
    {"headers": {"X-Auth-Token": {"v": "hunter2secret"}}},
    {"command": "export AWS_SECRET_ACCESS_KEY hunter2secret"},
])
def test_masking(args):
    assert "hunter2secret" not in summarize_args(args), summarize_args(args)

# 4. false positives of the default policy on file writes
@pytest.mark.parametrize("args", [
    {"path": "models.py", "content": "owner = models.ForeignKey(User, on_delete=models.CASCADE)"},
    {"path": "README.md", "content": "Run `rm -rf node_modules` then npm install"},
    {"path": "api.md", "content": "Use HTTP DELETE to remove a resource"},
])
def test_no_gate_on_write_file(args):
    v = evaluate(DEFAULT_POLICY, "write_file", args)
    assert not v.blocked, (v.decision, v.action_class.id)

# 5. non-list tools/patterns accepted
def test_policy_rejects_string_tools():
    with pytest.raises(ValueError):
        IntentPolicy.from_json({"version": 1, "action_classes": [{"id": "x", "tools": "delete_*", "decision": "gate"}]})

# 6. CLI hook does network (starts refresh thread)
def test_cli_no_network(tmp_path, monkeypatch):
    import afw_hermes.intent as it
    calls = []
    monkeypatch.setattr(it, "request_json", lambda *a, **k: calls.append(a) or (503, b""))
    hook.main(stdin=io.StringIO(json.dumps({"tool": "terminal", "args": {"command": "ls"}})),
              stdout=io.StringIO(), env={"AFW_STATE_DIR": str(tmp_path), "AFW_CONSOLE_URL": "http://127.0.0.1:9", "AFW_HOOK_NO_FLUSH": "1"})
    time.sleep(0.3)
    assert not calls, calls

# 7. common irreversible deletions not covered by builtin
@pytest.mark.parametrize("tool,args", [
    ("execute_code", {"code": "import shutil; shutil.rmtree('/srv/data')"}),
    ("terminal", {"command": "git push --force origin main"}),
    ("terminal", {"command": "rmdir /srv/x && shred -u f"}),
])
def test_builtin_coverage(tool, args):
    assert evaluate(DEFAULT_POLICY, tool, args).blocked

# 8. redirect: token not replayed
def test_redirect_not_followed(tmp_path):
    seen = []
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append((self.path, self.headers.get("Authorization")))
            if self.path.startswith("/api"):
                self.send_response(302); self.send_header("Location", f"http://127.0.0.1:{srv.server_port}/evil"); self.end_headers()
            else:
                self.send_response(200); self.end_headers(); self.wfile.write(b"{}")
        def log_message(self, *a): pass
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    from afw_hermes.intent import PolicyStore
    c = Config(console_url=f"http://127.0.0.1:{srv.server_port}", agent_token="SECRET", agent_name="a", state_dir=tmp_path)
    assert PolicyStore(c).refresh() is False
    srv.shutdown()
    assert [p for p, _ in seen] == ["/api/v1/intent-policy"], seen
