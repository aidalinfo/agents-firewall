import json

import pytest

from afw_hermes.intent import (
    DEFAULT_POLICY,
    IntentPolicy,
    PolicyError,
    PolicyStore,
    evaluate,
)


def decide(tool, args, policy=DEFAULT_POLICY):
    return evaluate(policy, tool, args)


# --- Each class is detected ------------------------------------------------------------

@pytest.mark.parametrize(
    "tool,args",
    [
        ("terminal", {"command": "rm -rf /data/backups"}),
        ("terminal", {"command": "curl -X DELETE https://api.example.com/items/3"}),
        ("terminal", {"command": "psql -c 'drop table customers'"}),
        ("glpi_delete_ticket", {"id": 42}),
        ("delete_file", {"path": "/tmp/a"}),
        ("fetch", {"url": "https://api.example.com/x", "method": "delete"}),
    ],
)
def test_irreversible_detected(tool, args):
    v = decide(tool, args)
    assert v.action_class is not None and v.action_class.id == "irreversible"
    assert v.decision == "gate"


@pytest.mark.parametrize(
    "tool,args",
    [
        ("gdrive_share_file", {"file": "x", "email": "a@b.c"}),
        ("teams_invite_member", {"team": "t", "user": "u"}),
        ("terminal", {"command": "chmod -R 777 /srv"}),
        ("terminal", {"command": "psql -c 'GRANT ALL ON db TO bob'"}),
    ],
)
def test_access_detected(tool, args):
    v = decide(tool, args)
    assert v.action_class is not None and v.action_class.id == "access"
    assert v.decision == "gate"


@pytest.mark.parametrize(
    "tool,args",
    [
        ("terminal", {"command": "kubectl delete deployment api"}),
        ("terminal", {"command": "docker rm -f web"}),
        ("terminal", {"command": "terraform destroy -auto-approve"}),
        ("coolify_redeploy", {"uuid": "abc"}),
        ("coolify", {"action": "delete", "uuid": "abc"}),
        ("terminal", {"command": "helm uninstall api"}),
    ],
)
def test_infra_destructive_detected(tool, args):
    v = decide(tool, args)
    assert v.action_class is not None and v.action_class.id == "infra_destructive"
    assert v.decision == "gate"


@pytest.mark.parametrize(
    "tool,args",
    [
        ("freepik_generate_image", {"prompt": "a cat"}),
        ("image_generate", {"prompt": "a dog"}),
        ("terminal", {"command": "curl https://api.freepik.com/v1/ai/text-to-image -d x"}),
        ("generate_video", {"prompt": "x"}),
    ],
)
def test_paid_generation_detected(tool, args):
    v = decide(tool, args)
    assert v.action_class is not None and v.action_class.id == "paid_generation"
    assert v.decision == "log"
    assert not v.blocked


@pytest.mark.parametrize(
    "tool,args",
    [
        ("terminal", {"command": "ls -la /srv"}),
        ("terminal", {"command": "docker run --rm alpine echo hi"}),
        ("fetch", {"url": "https://example.com/doc.pdf"}),
        ("send_mail", {"to": "a@b.c", "body": "please do not delete anything"}),
        ("terminal", {"command": "kubectl get pods"}),
        ("terminal", {"command": "rm notes.txt"}),
    ],
)
def test_benign_calls_allowed(tool, args):
    v = decide(tool, args)
    assert v.decision == "allow", (tool, args, v.action_class and v.action_class.id)
    assert v.as_hermes() is None


# --- Bypass attempts (textual variants must still be caught) ---------------------------

@pytest.mark.parametrize(
    "tool,args,klass",
    [
        ("terminal", {"command": "rm -fr /data"}, "irreversible"),
        ("terminal", {"command": "rm -r -f /data"}, "irreversible"),
        ("terminal", {"command": "rm --recursive --force /data"}, "irreversible"),
        ("terminal", {"command": "rm -Rf /data"}, "irreversible"),
        ("terminal", {"command": "cd /x && sudo rm  -rfv ./y"}, "irreversible"),
        ("terminal", {"command": "find / -name '*.log' -delete"}, "irreversible"),
        ("terminal", {"command": "psql -c 'DROP   TABLE users'"}, "irreversible"),
        ("terminal", {"command": "psql -c 'Drop Database prod'"}, "irreversible"),
        ("terminal", {"command": "curl --request DELETE https://x/y"}, "irreversible"),
        ("Terminal", {"command": "RM -RF /data"}, "irreversible"),
        ("terminal", {"steps": [{"cmd": "echo ok"}, {"cmd": "rm -rf /"}]}, "irreversible"),
        ("terminal", "rm -rf /data", "irreversible"),
        ("terminal", {"command": "kubectl -n prod delete pod x"}, "infra_destructive"),
        ("terminal", {"command": "kubectl --context=p delete ns x"}, "infra_destructive"),
        ("terminal", {"command": "docker container rm web"}, "infra_destructive"),
        ("terminal", {"command": "docker system prune -af"}, "infra_destructive"),
        ("terminal", {"command": "docker compose down -v"}, "infra_destructive"),
        ("terminal", {"command": "terraform apply -destroy"}, "infra_destructive"),
        ("terminal", {"command": "curl -X POST https://coolify.local/api/v1/applications/abc/restart"},
         "infra_destructive"),
        ("Coolify_Delete_Application", {"uuid": "x"}, "infra_destructive"),
        ("terminal", {"command": "ｒｍ -rf /data"}, "irreversible"),  # full-width (NFKC)
    ],
)
def test_bypass_variants_are_caught(tool, args, klass):
    v = decide(tool, args)
    assert v.action_class is not None, (tool, args)
    assert v.action_class.id == klass
    assert v.blocked


def test_strictest_decision_wins():
    # both irreversible (gate) and paid_generation (log) match: gate wins
    v = decide("freepik_delete_asset", {"id": 1})
    assert v.decision == "gate"
    pol = IntentPolicy.from_json({
        "version": 3,
        "action_classes": [
            {"id": "a", "name": "A", "tools": [], "patterns": ["foo"], "decision": "log"},
            {"id": "b", "name": "B", "tools": [], "patterns": ["foo"], "decision": "deny"},
            {"id": "c", "name": "C", "tools": [], "patterns": ["foo"], "decision": "gate"},
        ],
    })
    assert evaluate(pol, "t", {"x": "foo"}).action_class.id == "b"


# --- Gate / deny messages -------------------------------------------------------------

def test_gate_returns_clear_message_to_agent():
    v = decide("terminal", {"command": "rm -rf /data"})
    out = v.as_hermes()
    assert out["action"] == "block"
    assert out["message"].startswith("action soumise à validation humaine : ")
    assert "terminal" in out["message"]


def test_deny_returns_refusal_message():
    pol = IntentPolicy.from_json({"version": 1, "action_classes": [
        {"id": "x", "name": "Interdit", "tools": ["terminal"], "patterns": ["shutdown"], "decision": "deny"}]})
    out = evaluate(pol, "terminal", {"command": "shutdown now"}).as_hermes()
    assert out["action"] == "block"
    assert "refusée" in out["message"]


def test_tools_globs_restrict_class():
    pol = IntentPolicy.from_json({"version": 1, "action_classes": [
        {"id": "x", "name": "X", "tools": ["mail_*"], "patterns": [], "decision": "gate"}]})
    assert evaluate(pol, "mail_send", {}).decision == "gate"
    assert evaluate(pol, "MAIL_SEND", {}).decision == "gate"
    assert evaluate(pol, "terminal", {"command": "mail_send"}).decision == "allow"


# --- Policy validation ------------------------------------------------------------------

@pytest.mark.parametrize(
    "doc",
    [
        {},
        {"version": "x", "action_classes": []},
        {"version": 1, "action_classes": [{"id": "a", "name": "A", "decision": "maybe"}]},
        {"version": 1, "action_classes": [{"id": "a", "name": "A", "patterns": ["("], "decision": "gate"}]},
        {"version": 1, "action_classes": [{"name": "A", "decision": "gate"}]},
        {"version": 1, "action_classes": "nope"},
    ],
)
def test_invalid_policies_rejected(doc):
    with pytest.raises(PolicyError):
        IntentPolicy.from_json(doc)


def test_default_policy_is_prudent():
    ids = {c.id: c.decision for c in DEFAULT_POLICY.action_classes}
    assert ids["irreversible"] == "gate"
    assert ids["infra_destructive"] == "gate"
    assert ids["access"] == "gate"
    assert set(ids) == {"irreversible", "access", "infra_destructive", "paid_generation"}


# --- Remote policy, cache and fallback -----------------------------------------------

REMOTE = {
    "version": 7,
    "action_classes": [
        {"id": "irreversible", "name": "Suppression", "tools": [], "patterns": [r"\brm\b"], "decision": "deny"},
        {"id": "custom", "name": "Envoi de mail", "tools": ["send_mail"], "patterns": [], "decision": "gate"},
    ],
}


def test_remote_policy_applied(console, make_config):
    console.policy = REMOTE
    store = PolicyStore(make_config(console.url))
    assert store.source == "builtin"
    assert store.refresh() is True
    assert store.source == "remote"
    assert store.current().version == 7
    assert store.evaluate("send_mail", {"to": "x"}).decision == "gate"
    assert store.evaluate("terminal", {"command": "rm a"}).decision == "deny"
    req = [r for r in console.requests if r["path"] == "/api/v1/intent-policy"][0]
    assert req["headers"]["authorization"] == "Bearer agent-token-123"


def test_fallback_to_cache_when_console_down(console, make_config):
    console.policy = REMOTE
    cfg = make_config(console.url)
    assert PolicyStore(cfg).refresh()
    console.down = True
    store = PolicyStore(cfg)  # new process: loads the disk cache
    assert store.source == "cache"
    assert store.refresh() is False
    assert store.current().version == 7
    assert store.evaluate("send_mail", {}).decision == "gate"


def test_last_known_policy_kept_in_memory_when_console_goes_down(console, make_config):
    console.policy = REMOTE
    store = PolicyStore(make_config(console.url))
    store.refresh()
    console.down = True
    assert store.refresh() is False
    assert store.current().version == 7


def test_invalid_remote_policy_keeps_previous(console, make_config):
    console.policy = REMOTE
    store = PolicyStore(make_config(console.url))
    store.refresh()
    console.policy = {"version": 8, "action_classes": [{"id": "a", "name": "A", "decision": "allow-all"}]}
    assert store.refresh() is False
    assert store.current().version == 7


def test_builtin_when_no_cache_and_console_unreachable(make_config):
    store = PolicyStore(make_config("http://127.0.0.1:9"))
    assert store.refresh() is False
    assert store.source == "builtin"
    assert store.evaluate("terminal", {"command": "rm -rf /x"}).decision == "gate"


def test_corrupt_cache_ignored(make_config):
    cfg = make_config(None)
    cfg.state_dir.mkdir(parents=True)
    (cfg.state_dir / "intent-policy.json").write_text("{not json")
    store = PolicyStore(cfg)
    assert store.source == "builtin"


def test_cache_tampered_with_invalid_policy_ignored(make_config):
    cfg = make_config(None)
    cfg.state_dir.mkdir(parents=True)
    (cfg.state_dir / "intent-policy.json").write_text(json.dumps({"version": 1, "action_classes": [
        {"id": "x", "name": "x", "decision": "nope"}]}))
    assert PolicyStore(cfg).source == "builtin"


def test_maybe_refresh_is_non_blocking(console, make_config):
    import time

    console.policy = REMOTE
    console.delay = 1.0
    store = PolicyStore(make_config(console.url))
    t0 = time.monotonic()
    store.evaluate("terminal", {"command": "ls"})  # triggers async refresh
    assert time.monotonic() - t0 < 0.05
    from conftest import wait_until

    assert wait_until(lambda: store.current().version == 7, timeout=5)
