"""Complementary tests for the review of PR #3."""

import io
import json
import logging

import pytest

from afw_hermes import hook
from afw_hermes.config import Config, load_config
from afw_hermes.events import summarize_args
from afw_hermes.intent import DEFAULT_POLICY, PolicyStore, evaluate
from afw_hermes.sender import Spool


def test_cli_gate_kept_when_spool_write_fails(tmp_path, monkeypatch):
    def boom(self, events):
        raise OSError("read-only file system")

    monkeypatch.setattr(Spool, "append", boom)
    monkeypatch.setattr(hook, "_write_pending", lambda *a, **k: (_ for _ in ()).throw(OSError("ro")))
    out = io.StringIO()
    code = hook.main(stdin=io.StringIO(json.dumps({"tool": "terminal", "args": {"command": "rm -rf /"}})),
                     stdout=out, env={"AFW_STATE_DIR": str(tmp_path), "AFW_HOOK_NO_FLUSH": "1"})
    assert code == 2
    assert json.loads(out.getvalue())["action"] == "block"


def test_mask_depth_limited():
    deep = cur = []
    for _ in range(5000):
        nxt = []
        cur.append(nxt)
        cur = nxt
    s = summarize_args({"x": deep})
    assert "[…]" in s and len(s) <= 500


@pytest.mark.parametrize("cmd,secret", [
    ("mysql -uroot -phunter2secret db", "hunter2secret"),
    ("vault login --secret=hunter2secret", "hunter2secret"),
    ("tool --secret hunter2secret", "hunter2secret"),
])
def test_more_cli_secret_forms(cmd, secret):
    assert secret not in summarize_args({"command": cmd})


def test_any_value_type_under_sensitive_key_masked():
    s = summarize_args({"password": 123456789, "client_secret": {"a": "b"}, "url": "https://x"})
    assert "123456789" not in s and '"b"' not in s and "https://x" in s


def test_token_not_in_repr():
    c = Config(agent_token="SUPERSECRET")
    assert "SUPERSECRET" not in repr(c)


def test_default_state_dir_outside_hermes_home(tmp_path):
    cfg = load_config(env={"HERMES_HOME": str(tmp_path / "hermes"), "HOME": str(tmp_path / "home")})
    assert not str(cfg.state_dir).startswith(str(tmp_path / "hermes"))


@pytest.mark.parametrize("url,allowed", [
    ("http://127.0.0.1:9", True),
    ("http://localhost:9", True),
    ("http://10.1.2.3:9", True),
    ("http://192.168.1.5:9", True),
    ("http://afw-api:8080", True),
    ("http://console.example.com", False),
    ("http://8.8.8.8", False),
    ("https://console.example.com", True),
])
def test_cleartext_token_only_to_local_hosts(url, allowed, tmp_path, caplog):
    from afw_hermes import transport

    c = Config(console_url=url, agent_token="SECRET", state_dir=tmp_path)
    assert transport.token_allowed(url) is allowed
    if not allowed:
        with caplog.at_level(logging.WARNING, logger="afw_hermes"):
            with pytest.raises(transport.InsecureTransportError):
                transport.request_json(c, "GET", url + "/api/v1/intent-policy", None, 0.5)
            with pytest.raises(transport.InsecureTransportError):
                transport.request_json(c, "GET", url + "/api/v1/intent-policy", None, 0.5)
        assert sum("clear" in r.getMessage() for r in caplog.records) == 1
        assert PolicyStore(c).refresh() is False


@pytest.mark.parametrize("tool,args", [
    ("send_mail", {"to": "a@b.c", "body": "please rm -rf the old folder"}),
    ("terminal", {"command": "echo 'use the DELETE verb'"}),
    ("edit_file", {"path": "x.sql", "new_string": "DROP TABLE users;"}),
    ("write_file", {"path": "doc.md", "content": "chown and chmod 777 explained"}),
])
def test_command_patterns_scoped(tool, args):
    assert not evaluate(DEFAULT_POLICY, tool, args).blocked


@pytest.mark.parametrize("tool,args", [
    ("terminal", {"command": "curl -X DELETE https://x/y"}),
    ("terminal", {"command": "http --request=DELETE https://x/y"}),
    ("shell", {"command": "rm -rf /x"}),
    ("bash", {"command": "kubectl delete ns x"}),
    ("execute_code", {"code": "os.system('docker rm -f web')"}),
    ("delete_file", {"path": "/tmp/a"}),
])
def test_scoped_patterns_still_catch(tool, args):
    v = evaluate(DEFAULT_POLICY, tool, args)
    assert v.blocked, (tool, args)
