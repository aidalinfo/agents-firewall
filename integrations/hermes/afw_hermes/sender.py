"""Background, batched delivery of tool-call events to the console.

- ``enqueue`` is O(1) and never blocks: bounded in-memory queue, oldest event dropped when full.
- A daemon thread sends batches (``POST {console}/api/v1/ingest/tool-calls``, body
  ``{"events": [...]}``, ``Authorization: Bearer <agent token>``), with exponential backoff.
- While the console is unreachable, batches go to a bounded on-disk spool (JSON lines) that is
  replayed first once the console answers again. The CLI hook writes to the same spool.
"""

from __future__ import annotations

import glob
import json
import logging
import os
import queue
import threading
import time
from pathlib import Path
from typing import Iterable

from .config import Config
from .events import ToolCallEvent
from .transport import build_opener, request_json

log = logging.getLogger("afw_hermes")

SPOOL_FILE = "spool.jsonl"
_STALE_SENDING_SECS = 120


class DeliveryError(Exception):
    """The console did not accept the batch (retryable)."""


def post_events(config: Config, events: list[dict], timeout: float, opener=None) -> None:
    """POST one batch. Raises ``DeliveryError`` on retryable failure; drops permanent rejects."""
    if not config.ingest_url:
        raise DeliveryError("no console configured")
    try:
        status, _ = request_json(config, "POST", config.ingest_url, {"events": events}, timeout, opener)
    except (OSError, ValueError) as exc:
        raise DeliveryError(str(exc)) from exc
    if 200 <= status < 300:
        return
    if 400 <= status < 500 and status not in (401, 403, 408, 409, 425, 429):
        log.error("afw-hermes: console rejected %d tool-call events (HTTP %s), dropping them",
                  len(events), status)
        return
    raise DeliveryError(f"HTTP {status}")


class Spool:
    """Bounded JSON-lines spool shared by the in-process sender and the CLI hook."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self.path: Path = config.state_dir / SPOOL_FILE
        self._lock = threading.Lock()

    def append(self, events: Iterable[dict]) -> int:
        """Append events; returns how many were dropped because the spool is full."""
        dropped = 0
        with self._lock:
            lines: list[str] = []
            try:
                self.config.state_dir.mkdir(parents=True, exist_ok=True)
                size = self.path.stat().st_size if self.path.exists() else 0
                for ev in events:
                    line = json.dumps(ev, ensure_ascii=False, separators=(",", ":")) + "\n"
                    n = len(line.encode("utf-8"))
                    if size + n > self.config.spool_max_bytes:
                        dropped += 1
                        continue
                    size += n
                    lines.append(line)
                if lines:
                    # O_APPEND: one write per call keeps lines intact across processes.
                    fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
                    try:
                        os.write(fd, "".join(lines).encode("utf-8"))
                    finally:
                        os.close(fd)
            except OSError as exc:
                log.warning("afw-hermes: cannot write spool: %s", exc)
                return dropped + len(lines)
        if dropped:
            log.warning("afw-hermes: spool full, %d tool-call events dropped", dropped)
        return dropped

    def pending(self) -> bool:
        return self.path.exists() or bool(glob.glob(str(self.path) + ".sending.*"))

    def drain(self, send) -> int:
        """Send every spooled event with ``send(batch)``; unsent events are put back. Returns count sent."""
        claimed: list[Path] = []
        now = time.time()
        for stale in glob.glob(str(self.path) + ".sending.*"):
            try:
                if now - os.stat(stale).st_mtime > _STALE_SENDING_SECS:
                    claimed.append(Path(stale))
            except OSError:
                pass
        if self.path.exists():
            target = Path(f"{self.path}.sending.{os.getpid()}.{threading.get_ident()}")
            try:
                os.replace(self.path, target)
                claimed.append(target)
            except OSError:
                pass
        sent = 0
        for path in claimed:
            try:
                events = []
                for line in path.read_text(encoding="utf-8").splitlines():
                    try:
                        events.append(json.loads(line))
                    except ValueError:
                        continue
            except OSError:
                continue
            size = max(1, self.config.batch_size)
            for i in range(0, len(events), size):
                try:
                    send(events[i:i + size])
                except Exception:
                    self.append(events[i:])
                    path.unlink(missing_ok=True)
                    raise
                sent += len(events[i:i + size])
            path.unlink(missing_ok=True)
        return sent


class EventSender:
    def __init__(self, config: Config) -> None:
        self.config = config
        self.spool_store = Spool(config)
        self._q: queue.Queue[dict] = queue.Queue(maxsize=max(1, config.queue_size))
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._opener = build_opener(config)
        self.dropped = 0
        self.sent = 0

    # -- producer side (hook thread) ------------------------------------------------------
    def enqueue(self, event: ToolCallEvent | dict) -> bool:
        item = event.to_dict() if isinstance(event, ToolCallEvent) else event
        try:
            self._q.put_nowait(item)
            return True
        except queue.Full:
            try:
                self._q.get_nowait()
                self._q.task_done()
            except queue.Empty:
                pass
            self.dropped += 1
            try:
                self._q.put_nowait(item)
                return True
            except queue.Full:
                self.dropped += 1
                return False

    def queued(self) -> int:
        return self._q.qsize()

    def spool(self, events: list[dict]) -> None:
        self.dropped += self.spool_store.append(events)

    # -- consumer side ---------------------------------------------------------------------
    def start(self) -> None:
        if self._thread is None:
            self._thread = threading.Thread(target=self._run, name="afw-hermes-sender", daemon=True)
            self._thread.start()

    def _collect(self, wait: float) -> list[dict]:
        batch: list[dict] = []
        try:
            batch.append(self._q.get(timeout=wait))
        except queue.Empty:
            return batch
        while len(batch) < self.config.batch_size:
            try:
                batch.append(self._q.get_nowait())
            except queue.Empty:
                break
        return batch

    def _send(self, batch: list[dict]) -> None:
        post_events(self.config, batch, self.config.send_timeout, self._opener)
        self.sent += len(batch)

    def _run(self) -> None:
        backoff = 0.0
        next_attempt = 0.0
        while not self._stop.is_set():
            batch = self._collect(self.config.flush_interval)
            try:
                if not self.config.ingest_url:
                    continue  # nowhere to send: events are discarded
                if time.monotonic() < next_attempt:
                    if batch:
                        self.spool(batch)
                    continue
                try:
                    if self.spool_store.pending():
                        self.spool_store.drain(self._send)
                    if batch:
                        self._send(batch)
                    backoff = 0.0
                except Exception as exc:  # noqa: BLE001
                    if batch:
                        self.spool(batch)
                    backoff = min(self.config.backoff_max, backoff * 2 if backoff else self.config.backoff_initial)
                    next_attempt = time.monotonic() + backoff
                    log.info("afw-hermes: console unreachable (%s), retry in %.1fs", exc, backoff)
            finally:
                for _ in batch:
                    self._q.task_done()

    def flush(self, timeout: float = 5.0) -> bool:
        """Wait until every queued event was sent or spooled (for tests and shutdown)."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._q.unfinished_tasks == 0:
                return True
            time.sleep(0.01)
        return self._q.unfinished_tasks == 0

    def close(self, timeout: float = 2.0) -> None:
        """Stop the thread; whatever could not be sent is spooled to disk (never lost silently)."""
        if self._thread is not None:
            self.flush(timeout)
            self._stop.set()
            self._thread.join(timeout)
            self._thread = None
        rest: list[dict] = []
        while True:
            try:
                rest.append(self._q.get_nowait())
            except queue.Empty:
                break
        if rest and self.config.ingest_url:
            self.spool(rest)
