"""Minimal HTTP client for the console (stdlib only).

- Only ``http``/``https`` handlers: ``file://``, ``ftp://`` or ``data:`` are never opened.
- Redirects are never followed: urllib would replay ``Authorization`` to the new host.
- ``AFW_CA_FILE`` adds a private CA (the console's) to the trust store used for HTTPS.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import ssl
import threading
import urllib.parse
import urllib.error
import urllib.request
from typing import Any

from .config import Config

USER_AGENT = "afw-hermes/0.1"
log = logging.getLogger("afw_hermes")
_warned_lock = threading.Lock()
_warned: set[str] = set()


class InsecureTransportError(urllib.error.URLError):
    """Refused: the agent token would travel in clear text to a non-local host."""


def token_allowed(url: str) -> bool:
    """``https`` always; ``http`` only to loopback, private IPs or dot-less (Docker service) names."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme == "https":
        return True
    if parts.scheme != "http":
        return False
    host = (parts.hostname or "").lower()
    if not host:
        return False
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return "." not in host
    return ip.is_loopback or ip.is_private or ip.is_link_local


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        raise urllib.error.HTTPError(req.full_url, code, f"redirect refused: {msg}", headers, fp)


def _ssl_context(config: Config) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if config.ca_file:
        ctx.load_verify_locations(cafile=config.ca_file)
    return ctx


def build_opener(config: Config) -> urllib.request.OpenerDirector:
    opener = urllib.request.OpenerDirector()
    for handler in (
        urllib.request.ProxyHandler(),
        urllib.request.HTTPHandler(),
        urllib.request.HTTPSHandler(context=_ssl_context(config)),
        urllib.request.HTTPDefaultErrorHandler(),
        urllib.request.HTTPErrorProcessor(),
        _NoRedirect(),
    ):
        opener.add_handler(handler)
    return opener


def request_json(config: Config, method: str, url: str, payload: Any | None, timeout: float,
                 opener: urllib.request.OpenerDirector | None = None) -> tuple[int, bytes]:
    """Send a request; return ``(status, body)``. HTTP errors are returned, network errors raised."""
    if not url.startswith(("http://", "https://")):
        raise ValueError(f"unsupported console URL scheme: {url!r}")
    if config.agent_token and not token_allowed(url):
        host = urllib.parse.urlsplit(url).hostname or url
        with _warned_lock:
            first = host not in _warned
            _warned.add(host)
        if first:
            log.warning("afw-hermes: refusing to send the agent token in clear text (http) to %s; "
                        "use https", host)
        raise InsecureTransportError(f"clear-text token refused for {host}")
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if config.agent_token:
        headers["Authorization"] = f"Bearer {config.agent_token}"
    data = None
    if payload is not None:
        data = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    opener = opener or build_opener(config)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read()
        except Exception:  # noqa: BLE001
            body = b""
        return exc.code, body
