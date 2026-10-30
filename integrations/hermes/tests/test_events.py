import json
import re
import uuid
from datetime import datetime, timezone

from afw_hermes.events import ToolCallEvent, mask_secrets, rfc3339, summarize_args

RFC3339_Z = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")


def test_serialization_exact_keys_order_and_types():
    ev = ToolCallEvent.start(
        agent="daniel-bot",
        conversation_id="conv-1",
        tool="terminal",
        args={"command": "ls -la"},
        now=datetime(2026, 10, 30, 12, 0, 0, 123456, tzinfo=timezone.utc),
    )
    d = ev.to_dict()
    assert list(d.keys()) == [
        "id", "agent", "conversation_id", "tool", "args_summary", "started_at", "ended_at", "status",
    ]
    assert uuid.UUID(d["id"]).version == 4
    assert d["agent"] == "daniel-bot"
    assert d["conversation_id"] == "conv-1"
    assert d["tool"] == "terminal"
    assert d["args_summary"] == "command: ls -la"
    assert d["started_at"] == "2026-10-30T12:00:00.123Z"
    assert d["ended_at"] is None and d["status"] is None
    # JSON form has explicit nulls
    assert '"ended_at": null' in json.dumps(d)


def test_finished_keeps_id_and_sets_end():
    ev = ToolCallEvent.start("a", "c", "fetch", {"url": "https://x"})
    end = ev.finished("ok", now=datetime(2026, 10, 30, 12, 0, 1, tzinfo=timezone.utc))
    assert end.id == ev.id
    assert end.started_at == ev.started_at
    assert end.ended_at == "2026-10-30T12:00:01.000Z"
    assert end.status == "ok"
    assert RFC3339_Z.match(ev.started_at)


def test_rfc3339_converts_to_utc():
    from datetime import timedelta

    dt = datetime(2026, 10, 30, 14, 0, 0, tzinfo=timezone(timedelta(hours=2)))
    assert rfc3339(dt) == "2026-10-30T12:00:00.000Z"


def test_args_summary_truncated_to_500():
    s = summarize_args({"command": "x" * 5000})
    assert len(s) <= 500


def test_masks_bearer_token():
    s = summarize_args({"command": "curl -H 'Authorization: Bearer abcdef0123456789abcdef' https://api.x"})
    assert "abcdef0123456789abcdef" not in s
    assert "https://api.x" in s


def test_masks_secret_keys_in_args():
    s = summarize_args({"url": "https://x", "api_key": "k-very-secret-value", "headers": {"X-Api-Token": "zzz111"}})
    assert "k-very-secret-value" not in s
    assert "zzz111" not in s
    assert "https://x" in s


def test_masks_known_token_shapes():
    secrets = [
        "sk-proj-AbCdEf0123456789AbCdEf0123456789",
        "ghp_0123456789abcdefghijABCDEFGHIJ012345",
        "AKIAIOSFODNN7EXAMPLE",
        "xoxb-1234567890-abcdefghij",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
    ]
    for secret in secrets:
        out = mask_secrets(f"run --token-less {secret} done")
        assert secret not in out, secret
        assert "done" in out


def test_masks_password_assignments_and_url_credentials():
    out = mask_secrets("psql postgres://admin:hunter2pass@db:5432/x PASSWORD=s3cr3t-value")
    assert "hunter2pass" not in out
    assert "s3cr3t-value" not in out
    assert "db:5432" in out


def test_masks_private_key_block():
    out = mask_secrets("-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg\n-----END PRIVATE KEY-----")
    assert "MIIEvQIBADANBg" not in out


def test_summary_of_non_dict_args():
    assert summarize_args("echo hi") == "echo hi"
    assert summarize_args(None) == ""
    assert summarize_args(["a", 1]) == '["a", 1]'
