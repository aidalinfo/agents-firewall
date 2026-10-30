import importlib.util
import json
import threading
import urllib.request
from pathlib import Path

DEMO = Path(__file__).resolve().parents[1] / "demo" / "fake_hermes.py"


def load_demo():
    spec = importlib.util.spec_from_file_location("fake_hermes", DEMO)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def post(url, body):
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def test_demo_server_runs_scenarios(console, make_config):
    mod = load_demo()
    agent = mod.FakeHermes(make_config(console.url))
    server = mod.make_server(agent, "127.0.0.1", 0)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        status, body = post(base + "/run", {"tool": "delete_ticket", "args": {"id": 3}, "conversation_id": "c1"})
        assert status == 200 and body["blocked"] is True
        assert body["message"].startswith("action soumise à validation humaine")
        status, body = post(base + "/run", {"tool": "fetch", "args": {"url": console.url + "/nothing"},
                                            "conversation_id": "c1"})
        assert status == 200 and body["blocked"] is False
        assert body["result"]["status"] == 404
        status, body = post(base + "/run", {"tool": "terminal", "args": {"command": "uname -a"},
                                            "conversation_id": "c1"})
        assert status == 400  # demo only runs curl
        with urllib.request.urlopen(base + "/healthz", timeout=5) as r:
            assert r.status == 200
        agent.plugin.sender.flush(timeout=5)
    finally:
        server.shutdown()
        agent.plugin.close()
    evs = console.ingested_events()
    assert {e["conversation_id"] for e in evs} == {"c1"}
    assert any(e["status"] == "gated" for e in evs)
