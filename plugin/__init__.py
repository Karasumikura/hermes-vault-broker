"""Hermes plugin: fill saved logins from an out-of-process vault broker.

This file is a thin client. It opens a Unix socket, sends one JSON line, and
returns the reply. It never receives, holds, or forwards a password — the
broker resolves the secret and performs the page write itself.
"""

from __future__ import annotations

import json
import os
import socket

SOCKET_ENV = "HERMES_VAULT_BROKER_SOCKET"
DEFAULT_SOCKET = "/run/hermes-vault-broker/sock"
TIMEOUT_S = 30.0


def _socket_path() -> str:
    return os.environ.get(SOCKET_ENV) or DEFAULT_SOCKET


def _call(request: dict) -> dict:
    path = _socket_path()
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.settimeout(TIMEOUT_S)
        sock.connect(path)
    except OSError as exc:
        sock.close()
        return {
            "ok": False,
            "error": "vault broker is not reachable at %s (%s). Start it with "
                     "`systemctl --user start hermes-vault-broker`." % (path, type(exc).__name__),
        }
    try:
        sock.sendall((json.dumps(request) + "\n").encode("utf-8"))
        chunks = []
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
            if b"\n" in chunk:
                break
    except OSError as exc:
        return {"ok": False, "error": "vault broker call failed (%s)" % type(exc).__name__}
    finally:
        sock.close()

    raw = b"".join(chunks).decode("utf-8", "replace").strip()
    if not raw:
        return {"ok": False, "error": "vault broker closed the connection without a reply"}
    try:
        reply = json.loads(raw.splitlines()[0])
    except ValueError:
        return {"ok": False, "error": "vault broker returned an unreadable reply"}
    return reply if isinstance(reply, dict) else {"ok": False, "error": "unexpected reply"}


def _status(args: dict, **_kwargs) -> str:
    return json.dumps(_call({"op": "status"}), ensure_ascii=False)


def _list(args: dict, **_kwargs) -> str:
    return json.dumps(_call({"op": "list"}), ensure_ascii=False)


def _fill(args: dict, **_kwargs) -> str:
    handle = str(args.get("handle") or "").strip()
    origin = str(args.get("origin") or "").strip()
    if not handle or not origin:
        return json.dumps({"ok": False, "error": "handle and origin are required"})
    return json.dumps(
        _call(
            {
                "op": "fill",
                "handle": handle,
                "origin": origin,
                "submit": bool(args.get("submit")),
            }
        ),
        ensure_ascii=False,
    )


_STATUS_SCHEMA = {"type": "object", "properties": {}, "additionalProperties": False}

_LIST_SCHEMA = {"type": "object", "properties": {}, "additionalProperties": False}

_FILL_SCHEMA = {
    "type": "object",
    "properties": {
        "handle": {"type": "string", "description": "Handle from vault_broker_list, e.g. vault_d4f81b2c9e10."},
        "origin": {
            "type": "string",
            "description": "Origin of the page holding the login form, e.g. https://www.kaggle.com. "
                           "Must match the origin the login was saved for.",
        },
        "submit": {"type": "boolean", "description": "Submit the form after the password is written."},
    },
    "required": ["handle", "origin"],
    "additionalProperties": False,
}


def register(ctx) -> None:
    ctx.register_tool(
        name="vault_broker_status",
        toolset="vault_broker",
        schema=_STATUS_SCHEMA,
        handler=_status,
        description="Report whether the out-of-process vault broker is unlocked and how many logins it holds.",
        emoji="\U0001F510",
    )
    ctx.register_tool(
        name="vault_broker_list",
        toolset="vault_broker",
        schema=_LIST_SCHEMA,
        handler=_list,
        description=(
            "List saved logins in the vault broker: handle, label, bound origin and identifier. "
            "Passwords are never returned. The identifier is ordinary metadata and may be typed "
            "into the page directly."
        ),
        emoji="\U0001F510",
    )
    ctx.register_tool(
        name="vault_broker_fill",
        toolset="vault_broker",
        schema=_FILL_SCHEMA,
        handler=_fill,
        description=(
            "Fill the password of a saved login into the browser tab on the given origin. The broker "
            "resolves the secret and writes it itself, so the password never enters this process. "
            "The DevTools endpoint is fixed by the broker's root-owned config and is not a parameter. "
            "Returns {filled, submitted}. Use submit=true to also submit the form. If the broker "
            "reports origin_mismatch or 'no open tab', navigate the browser to the login page first."
        ),
        emoji="\U0001F510",
    )
