"""Broker-owned DevTools endpoint.

The agent never supplies a CDP URL. The broker reads one from a root-owned
config file, refuses anything that is not loopback, and refuses any
``webSocketDebuggerUrl`` a tab advertises unless its host:port is exactly the
configured endpoint. Nothing in this module handles a password; it only decides
where a password is allowed to travel.

Root-owned means ``uid 0`` and not writable by group/other. The service user
(vaultd) may *read* the file (root:vaultd 0640) but must never be able to
change it, otherwise an agent that reaches the broker process could repoint
itself.
"""

from __future__ import annotations

import ipaddress
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

DEFAULT_CONFIG_PATH = "/etc/hermes-vault-broker/cdp.json"


class EndpointError(Exception):
    """Configuration or target validation failure. Never contains a secret."""


@dataclass(frozen=True)
class Endpoint:
    """A validated, loopback-only DevTools HTTP endpoint."""

    base: str
    host: str
    port: int

    @property
    def list_url(self) -> str:
        return self.base + "/json/list"


def _canonical_host(host: str) -> str:
    """Normalise the two spellings of the IPv4 loopback to one value."""
    return "127.0.0.1" if host.lower() == "localhost" else host.lower()


def _is_loopback(host: str) -> bool:
    """IPv4 loopback only: the HTTP base URL is rebuilt as host:port without
    brackets, so an IPv6 literal would produce a malformed URL."""
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    return addr.version == 4 and addr.is_loopback


def validate_base(url: str) -> Endpoint:
    """Accept only ``http://<loopback>:<port>`` with no path, query or userinfo."""
    if not isinstance(url, str) or not url:
        raise EndpointError("the DevTools endpoint must be a non-empty URL")
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as exc:
        raise EndpointError("the DevTools endpoint has an invalid port") from exc
    if parts.scheme != "http":
        raise EndpointError("the DevTools endpoint must use http://")
    if port is None:
        raise EndpointError("the DevTools endpoint must include an explicit port")
    if parts.username or parts.password:
        raise EndpointError("the DevTools endpoint must not carry credentials")
    if parts.path not in ("", "/"):
        raise EndpointError("the DevTools endpoint must not carry a path")
    if parts.query or parts.fragment:
        raise EndpointError("the DevTools endpoint must not carry a query or fragment")
    host = _canonical_host(parts.hostname or "")
    if not host or not _is_loopback(host):
        raise EndpointError("the DevTools endpoint must be on loopback")
    return Endpoint(base="http://%s:%d" % (host, port), host=host, port=port)


def validate_ws_url(ws_url: str, endpoint: Endpoint) -> str:
    """Refuse a tab's websocket unless it points at the configured host:port.

    This is the last gate before the plaintext password leaves the broker: only
    the configured endpoint can receive the write.
    """
    if not isinstance(ws_url, str) or not ws_url:
        raise EndpointError("the tab did not supply a websocket URL")
    try:
        parts = urlsplit(ws_url)
        port = parts.port
    except ValueError as exc:
        raise EndpointError("the tab supplied a websocket URL with an invalid port") from exc
    if parts.scheme != "ws":
        raise EndpointError("the tab supplied a non-ws websocket URL")
    if parts.username or parts.password:
        raise EndpointError("the tab supplied a websocket URL with credentials")
    if parts.query or parts.fragment:
        raise EndpointError("the tab supplied a websocket URL with a query or fragment")
    host = _canonical_host(parts.hostname or "")
    if host != endpoint.host or port != endpoint.port:
        raise EndpointError(
            "the tab's websocket host:port (%s:%s) differs from the configured "
            "DevTools endpoint (%s:%d) — refusing to send anything"
            % (host or "?", port if port is not None else "?", endpoint.host, endpoint.port)
        )
    # Rebuild from the validated IP literal rather than returning the browser's
    # original string: a "localhost" spelling could otherwise resolve somewhere
    # other than the endpoint we just checked (check A, connect B).
    return "ws://%s:%d%s" % (endpoint.host, endpoint.port, parts.path or "/")


def _check_stat(st: os.stat_result) -> None:
    """Validate a stat taken from the very fd we are about to read."""
    if stat.S_ISLNK(st.st_mode):
        raise EndpointError("the DevTools config must not be a symlink")
    if not stat.S_ISREG(st.st_mode):
        raise EndpointError("the DevTools config must be a regular file")
    if st.st_uid != 0:
        raise EndpointError("the DevTools config must be owned by root")
    if st.st_mode & 0o022:
        raise EndpointError("the DevTools config must not be group- or world-writable")


def _check_parent(path: Path) -> None:
    """The containing directory must not be writable by the service user."""
    try:
        st = os.stat(path.parent)
    except OSError as exc:
        raise EndpointError("cannot stat the DevTools config directory") from exc
    if st.st_uid != 0 or st.st_mode & 0o022:
        raise EndpointError("the DevTools config directory must be root-owned and not writable")


def _check_config_file(path: Path) -> None:
    """Path-based check kept for tests; production uses the fd path below."""
    try:
        st = path.lstat()
    except OSError as exc:
        raise EndpointError("cannot stat the DevTools config: %s" % type(exc).__name__) from exc
    _check_stat(st)


def load_config(path: str = DEFAULT_CONFIG_PATH) -> Endpoint:
    """Read ``{"cdp": "http://127.0.0.1:9223"}`` from a root-owned file.

    ``O_NOFOLLOW`` + ``fstat(fd)`` + reading through that same fd removes the
    check/use race: the bytes we validate are the bytes we parse, so a path
    swapped between stat and open cannot repoint the broker.
    """
    p = Path(path)
    _check_parent(p)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(p, flags)
    except OSError as exc:
        raise EndpointError("cannot open the DevTools config: %s" % type(exc).__name__) from exc
    try:
        _check_stat(os.fstat(fd))
        with os.fdopen(fd, "r", encoding="utf-8") as handle:
            fd = -1  # fdopen owns it now
            doc = json.load(handle)
    except EndpointError:
        raise
    except (OSError, ValueError) as exc:
        raise EndpointError("the DevTools config is unreadable") from exc
    finally:
        if fd != -1:
            os.close(fd)
    if not isinstance(doc, dict):
        raise EndpointError("the DevTools config must be a JSON object")
    url = doc.get("cdp")
    if not isinstance(url, str):
        raise EndpointError("the DevTools config must contain a string 'cdp'")
    try:
        return validate_base(url)
    except EndpointError as exc:
        raise EndpointError("invalid DevTools config: %s" % exc) from exc
