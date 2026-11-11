"""Blocking client for the broker socket, one request per connection."""

from __future__ import annotations

import json
import socket
from typing import Any

DEFAULT_SOCKET = "/run/hermes-vault-broker/sock"


class BrokerUnavailable(Exception):
    pass


def call(request: dict, socket_path: str = DEFAULT_SOCKET, timeout: float = 30.0) -> dict:
    payload = (json.dumps(request) + "\n").encode("utf-8")
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect(socket_path)
    except OSError as exc:
        sock.close()
        raise BrokerUnavailable(
            "vault broker is not reachable at %s (%s)" % (socket_path, type(exc).__name__)
        ) from exc
    try:
        sock.sendall(payload)
        chunks = []
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
            if b"\n" in chunk:
                break
    finally:
        sock.close()
    raw = b"".join(chunks).decode("utf-8", "replace").strip()
    if not raw:
        raise BrokerUnavailable("vault broker closed the connection without a reply")
    try:
        reply: Any = json.loads(raw.splitlines()[0])
    except ValueError as exc:
        raise BrokerUnavailable("vault broker returned an unreadable reply") from exc
    if not isinstance(reply, dict):
        raise BrokerUnavailable("vault broker returned an unexpected reply")
    return reply
