import json
import time

from conftest import wait_until

from afw_hermes.events import ToolCallEvent
from afw_hermes.sender import EventSender


def ev(tool="terminal"):
    return ToolCallEvent.start("daniel-bot", "conv-1", tool, {"command": "ls"})


def test_batch_sent_with_bearer_header_and_body_shape(console, make_config):
    s = EventSender(make_config(console.url))
    s.start()
    try:
        events = [ev(), ev("fetch"), ev("mail")]
        for e in events:
            assert s.enqueue(e)
        assert s.flush(timeout=5)
    finally:
        s.close()
    reqs = console.ingest_requests()
    assert reqs, "no ingest request"
    r = reqs[0]
    assert r["method"] == "POST"
    assert r["headers"]["authorization"] == "Bearer agent-token-123"
    assert r["headers"]["content-type"].startswith("application/json")
    assert set(r["body"].keys()) == {"events"}
    got = console.ingested_events()
    assert [g["id"] for g in got] == [e.id for e in events]
    assert got[0] == events[0].to_dict()


def test_enqueue_never_blocks_when_console_sleeps(console, make_config):
    console.delay = 3.0
    s = EventSender(make_config(console.url, send_timeout=5.0))
    s.start()
    try:
        durations = []
        for _ in range(200):
            t0 = time.perf_counter()
            s.enqueue(ev())
            durations.append(time.perf_counter() - t0)
        durations.sort()
        # p99 under the 50 ms hook budget; the max only guards against real blocking (the console
        # sleeps 3 s) while tolerating an OS scheduling hiccup on a loaded CI host.
        assert durations[197] < 0.05
        assert durations[-1] < 0.5
    finally:
        t0 = time.perf_counter()
        s.close(timeout=0.2)
        assert time.perf_counter() - t0 < 1.0


def test_queue_is_bounded_and_drops_oldest(make_config):
    s = EventSender(make_config(None, queue_size=5))  # not started
    for _ in range(12):
        s.enqueue(ev())
    assert s.queued() == 5
    assert s.dropped == 7


def test_spooled_to_disk_when_console_down_then_delivered(console, make_config):
    console.down = True
    cfg = make_config(console.url)
    s = EventSender(cfg)
    s.start()
    try:
        e1, e2 = ev(), ev()
        s.enqueue(e1)
        s.enqueue(e2)
        spool = cfg.state_dir / "spool.jsonl"
        assert wait_until(lambda: spool.exists() and len(spool.read_text().splitlines()) == 2)
        console.down = False
        assert wait_until(lambda: {x["id"] for x in console.ingested_events()} >= {e1.id, e2.id}, timeout=5)
        assert wait_until(lambda: not spool.exists() or spool.read_text() == "")
    finally:
        s.close()


def test_spool_is_bounded(make_config):
    cfg = make_config("http://127.0.0.1:9", spool_max_bytes=600)
    s = EventSender(cfg)
    s.spool([ev().to_dict() for _ in range(50)])
    assert (cfg.state_dir / "spool.jsonl").stat().st_size <= 600
    assert s.dropped > 0


def test_close_spools_pending_events(make_config):
    cfg = make_config("http://127.0.0.1:9", backoff_initial=10, backoff_max=10)
    s = EventSender(cfg)
    s.start()
    e = ev()
    s.enqueue(e)
    s.close(timeout=1)
    lines = (cfg.state_dir / "spool.jsonl").read_text().splitlines()
    assert e.id in {json.loads(line)["id"] for line in lines}


def test_permanent_client_error_drops_batch(console, make_config):
    console.ingest_status = 422
    cfg = make_config(console.url)
    s = EventSender(cfg)
    s.start()
    try:
        s.enqueue(ev())
        assert s.flush(timeout=5)
    finally:
        s.close()
    assert not (cfg.state_dir / "spool.jsonl").exists()


def test_no_console_configured_spools_nothing_sent(make_config):
    cfg = make_config(None)
    s = EventSender(cfg)
    s.start()
    s.enqueue(ev())
    s.close(timeout=1)
    # without console URL, events are discarded (nothing to send to), no crash
    assert s.sent == 0
