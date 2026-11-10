"""Command line for the vault broker.

    python -m broker init                     create an empty store (asks twice)
    python -m broker daemon                   run the socket service (systemd uses this)
    python -m broker unlock                   unlock over the socket (asks once)
    python -m broker unlock-form --cert ...   one-time HTTPS passphrase page
    python -m broker list
    python -m broker add --label kaggle --origin https://www.kaggle.com --identifier me@example.com
    python -m broker remove --handle vault_...
    python -m broker fill --handle vault_... --origin https://www.kaggle.com [--submit]
    python -m broker migrate --key vault.key --enc vault.json.enc

``add`` and ``init`` read the secret from the terminal (getpass), never from
argv, so it does not land in the process list or the shell history.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys

from . import daemon as daemon_module
from .client import BrokerUnavailable, call
from .store import Store, VaultError


def _ask(prompt: str) -> str:
    return getpass.getpass(prompt)


def _print(payload: dict) -> int:
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0 if payload.get("ok", True) else 1


def _cmd_init(args) -> int:
    store = Store(args.state)
    first = _ask("New passphrase: ")
    if first != _ask("Repeat passphrase: "):
        print("passphrases do not match", file=sys.stderr)
        return 2
    try:
        store.create(first)
    except VaultError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print("store created at %s" % args.state)
    return 0


def _cmd_unlock(args) -> int:
    passphrase = _ask("Passphrase: ")
    try:
        reply = call({"op": "unlock", "passphrase": passphrase}, socket_path=args.socket)
    except BrokerUnavailable as exc:
        print(str(exc), file=sys.stderr)
        return 1
    finally:
        passphrase = ""
    return _print(reply)


def _cmd_add(args) -> int:
    password = args.password_file and open(args.password_file, encoding="utf-8").read().strip()
    if not password:
        password = _ask("Password for %s: " % args.label)
    request = {
        "op": "add",
        "label": args.label,
        "origin": args.origin,
        "identifier_type": args.identifier_type,
        "identifier": args.identifier,
        "password": password,
    }
    try:
        reply = call(request, socket_path=args.socket)
    except BrokerUnavailable as exc:
        print(str(exc), file=sys.stderr)
        return 1
    finally:
        password = ""
    return _print(reply)


def _cmd_migrate(args) -> int:
    """Import items from a Hermes ``vault.key`` + ``vault.json.enc`` pair (or plain JSON)."""
    if args.json:
        items = json.load(open(args.json, encoding="utf-8")).get("items", [])
    else:
        from cryptography.fernet import Fernet

        key = open(args.key, "rb").read().strip()
        blob = open(args.enc, "rb").read()
        items = json.loads(Fernet(key).decrypt(blob).decode("utf-8")).get("items", [])

    migrated = 0
    for item in items:
        if item.get("kind", "login") != "login":
            continue
        request = {
            "op": "add",
            "label": item.get("label") or "imported",
            "origin": item.get("origin") or "",
            "identifier_type": item.get("identifier_type") or "email",
            "identifier": item.get("identifier") or "",
            "password": (item.get("secret") or {}).get("password") or "",
        }
        try:
            reply = call(request, socket_path=args.socket)
        except BrokerUnavailable as exc:
            print(str(exc), file=sys.stderr)
            return 1
        if reply.get("ok"):
            migrated += 1
            print("imported %s -> %s" % (request["label"], reply.get("handle")))
        else:
            print("skipped %s: %s" % (request["label"], reply.get("error")), file=sys.stderr)
    print("migrated %d/%d items" % (migrated, len(items)))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="broker")
    parser.add_argument("--state", default=daemon_module.DEFAULT_STATE)
    parser.add_argument("--socket", default=daemon_module.DEFAULT_SOCKET)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init").set_defaults(func=_cmd_init)
    sub.add_parser("unlock").set_defaults(func=_cmd_unlock)

    daemon_parser = sub.add_parser("daemon")
    daemon_parser.add_argument("--allow-uid", action="append", type=int, default=None)
    daemon_parser.set_defaults(func=lambda a: daemon_module.main(
        ["--socket", a.socket, "--state", a.state]
        + sum([["--allow-uid", str(u)] for u in (a.allow_uid or [])], [])
    ))

    form = sub.add_parser("unlock-form")
    form.add_argument("--cert", required=True)
    form.add_argument("--key", required=True)
    form.add_argument("--host", default="127.0.0.1")
    form.add_argument("--port", type=int, default=0)
    form.add_argument("--public-url", default="")
    form.set_defaults(func=lambda a: __import__("broker.unlock_form", fromlist=["main"]).main(
        ["--socket", a.socket, "--cert", a.cert, "--key", a.key,
         "--host", a.host, "--port", str(a.port), "--public-url", a.public_url]
    ))

    sub.add_parser("list").set_defaults(func=lambda a: _print(call({"op": "list"}, socket_path=a.socket)))
    sub.add_parser("lock").set_defaults(func=lambda a: _print(call({"op": "lock"}, socket_path=a.socket)))
    sub.add_parser("status").set_defaults(func=lambda a: _print(call({"op": "status"}, socket_path=a.socket)))

    add = sub.add_parser("add")
    add.add_argument("--label", required=True)
    add.add_argument("--origin", required=True)
    add.add_argument("--identifier", required=True)
    add.add_argument("--identifier-type", default="email", choices=("email", "username", "phone"))
    add.add_argument("--password-file", default="")
    add.set_defaults(func=_cmd_add)

    remove = sub.add_parser("remove")
    remove.add_argument("--handle", required=True)
    remove.set_defaults(func=lambda a: _print(call({"op": "remove", "handle": a.handle}, socket_path=a.socket)))

    fill = sub.add_parser("fill")
    fill.add_argument("--handle", required=True)
    fill.add_argument("--origin", required=True)
    fill.add_argument("--cdp", default="http://127.0.0.1:9223")
    fill.add_argument("--submit", action="store_true")
    fill.set_defaults(func=lambda a: _print(call(
        {"op": "fill", "handle": a.handle, "origin": a.origin, "cdp": a.cdp, "submit": a.submit},
        socket_path=a.socket,
    )))

    migrate = sub.add_parser("migrate")
    migrate.add_argument("--key", default="")
    migrate.add_argument("--enc", default="")
    migrate.add_argument("--json", default="")
    migrate.set_defaults(func=_cmd_migrate)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except BrokerUnavailable as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
