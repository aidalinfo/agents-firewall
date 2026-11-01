"""Detached worker for the CLI hook: deliver the disk spool and refresh the intent policy.

Run as ``python -m afw_hermes.flush``. A lock file keeps at most one worker per state directory.
"""

from __future__ import annotations

import logging
import os
import sys
import time
from typing import Mapping

from .config import load_config
from .intent import PolicyStore
from .sender import DeliveryError, Spool, post_events

log = logging.getLogger("afw_hermes")
_LOCK_STALE_SECS = 120


def _acquire(path) -> bool:
    for _ in range(2):
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.write(fd, str(os.getpid()).encode())
            os.close(fd)
            return True
        except FileExistsError:
            try:
                if time.time() - path.stat().st_mtime > _LOCK_STALE_SECS:
                    path.unlink(missing_ok=True)
                    continue
            except OSError:
                continue
            return False
    return False


def main(env: Mapping[str, str] | None = None) -> int:
    config = load_config(dict(os.environ if env is None else env))
    if not config.console_url:
        return 0
    config.state_dir.mkdir(parents=True, exist_ok=True)
    lock = config.state_dir / "flush.lock"
    if not _acquire(lock):
        return 0
    try:
        store = PolicyStore(config)
        age = store.cache_age()
        if age is None or age >= config.policy_refresh_interval:
            store.refresh()
        spool = Spool(config)
        if spool.pending():
            try:
                spool.drain(lambda batch: post_events(config, batch, config.send_timeout))
            except DeliveryError as exc:
                log.info("afw-hermes: console unreachable, events kept in spool: %s", exc)
        return 0
    finally:
        lock.unlink(missing_ok=True)


if __name__ == "__main__":
    sys.exit(main())
