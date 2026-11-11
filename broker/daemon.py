"""Unix-socket daemon: the only way to reach the credential store.

Wire format is one JSON object per line in each direction. Ops:

    {"op": "status"}                       -> {"ok": true, "unlocked": bool, "items": n}
    {"op": "unlock", "passphrase": "..."}  -> {"ok": true}
    {"op": "lock"}                         -> {"ok": true}
    {"op": "list"}                         -> {"ok": true, "items": [...]}
    {"op": "add", ...}                     -> {"ok": true, "handle": "vault_..."}
    {"op": "remove", "handle": "..."}      -> {"ok": true, "removed": bool}
    {"op": "fill", "handle": "...", "origin": "...", "submit": bool}
                                           -> {"ok": true, "filled": 1, "submitted": false}

The DevTools endpoint is NOT part of the wire protocol: it is read by the broker
from a root-owned config file and validated as loopback. A request that tries to
supply one is refused, so a prompt-injected agent cannot repoint the write.

Only ``status/list/fill`` are available to the gateway uid; ``init/unlock/lock/
add/remove`` stay with root and the broker's own uid (``SO_PEERCRED``). The
password never appears in a response, a log line, or an error message.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import socket
import socketserver
import struct
import sys
import threading
import time

from . import cdp as cdp_module
from .endpoint import DEFAULT_CONFIG_PATH, Endpoint, EndpointError, load_config
from .store import LockedError, Store, VaultError

log = logging.getLogger("hermes-vault-broker")

DEFAULT_SOCKET = "/run/hermes-vault-broker/sock"
DEFAULT_STATE = "/var/lib/hermes-vault-broker/store.json"
MAX_LINE = 64 * 1024

# The gateway uid gets these and nothing else. Everything that changes the
# store or unlocks it is reserved for root / the broker's own uid.
GATEWAY_OPS = frozenset(("status", "list", "fill"))

# Brute-force brake: after this many wrong passphrases the daemon stops
# answering unlock for a while, so a compromised agent cannot grind offline.
UNLOCK_ATTEMPTS = 5
UNLOCK_COOLDOWN_S = 60.0


def peer_uid(sock: socket.socket) -> int:
    try:
        raw = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        _pid, uid, _gid = struct.unpack("3i", raw)
        return uid
    except OSError:
        return -1


class Broker:
    """Request handling, separated from the socket so tests can call it directly."""

    def __init__(
        self,
        store: Store,
        allowed_uids: tuple[int, ...] = (0,),
        admin_uids: tuple[int, ...] | None = None,
        endpoint: Endpoint | None = None,
    ):
        self.store = store
        self.allowed_uids = tuple(allowed_uids)
        # Only root and the broker's own uid may mutate or unlock the store.
        self.admin_uids = tuple(admin_uids) if admin_uids is not None else (0, os.getuid())
        self.endpoint = endpoint
        self._failures = 0
        self._blocked_until = 0.0
        self._mutex = threading.Lock()

    # -- entry point ------------------------------------------------------
    def handle(self, request: dict, uid: int) -> dict:
        if uid not in self.allowed_uids:
            log.warning("rejected request from uid %s", uid)
            return {"ok": False, "error": "not permitted"}
        op = str(request.get("op") or "")
        if uid not in self.admin_uids and op not in GATEWAY_OPS:
            log.warning("uid %s attempted privileged op %s", uid, op)
            return {"ok": False, "error": "not permitted"}
        handler = getattr(self, "_op_" + op, None)
        if handler is None:
            return {"ok": False, "error": "unknown op %r" % op}
        try:
            return handler(request)
        except LockedError as exc:
            return {"ok": False, "error": str(exc), "locked": True}
        except VaultError as exc:
            return {"ok": False, "error": str(exc)}
        except cdp_module.CdpError as exc:
            return {"ok": False, "error": str(exc)}
        except Exception as exc:  # noqa: BLE001 - never let a handler kill the daemon
            log.exception("handler %s failed", op)
            return {"ok": False, "error": "internal error: %s" % type(exc).__name__}

    # -- ops --------------------------------------------------------------
    def _op_status(self, _request: dict) -> dict:
        items = 0
        if self.store.unlocked:
            try:
                items = len(self.store.list_items())
            except VaultError:
                items = 0
        return {
            "ok": True,
            "initialized": self.store.initialized,
            "unlocked": self.store.unlocked,
            "items": items,
        }

    def _op_init(self, request: dict) -> dict:
        if self.store.initialized:
            return {"ok": False, "error": "store already exists"}
        self.store.create(request.get("passphrase") or "")
        log.info("store created")
        return {"ok": True}

    def _op_unlock(self, request: dict) -> dict:
        with self._mutex:
            if time.monotonic() < self._blocked_until:
                return {"ok": False, "error": "too many attempts; wait and try again"}
        passphrase = request.get("passphrase") or ""
        try:
            self.store.unlock(passphrase)
        except VaultError:
            with self._mutex:
                self._failures += 1
                if self._failures >= UNLOCK_ATTEMPTS:
                    self._blocked_until = time.monotonic() + UNLOCK_COOLDOWN_S
                    self._failures = 0
            log.warning("unlock failed")
            return {"ok": False, "error": "wrong passphrase"}
        with self._mutex:
            self._failures = 0
        log.info("store unlocked")
        return {"ok": True}

    def _op_lock(self, _request: dict) -> dict:
        self.store.lock()
        log.info("store locked")
        return {"ok": True}

    def _op_list(self, _request: dict) -> dict:
        return {"ok": True, "items": [item.to_dict() for item in self.store.list_items()]}

    def _op_add(self, request: dict) -> dict:
        meta = self.store.add(
            label=request.get("label") or "",
            origin=request.get("origin") or "",
            identifier_type=request.get("identifier_type") or "email",
            identifier=request.get("identifier") or "",
            password=request.get("password") or "",
        )
        log.info("item added: %s", meta.id)
        return {"ok": True, "handle": meta.id, "label": meta.label, "origin": meta.origin}

    def _op_remove(self, request: dict) -> dict:
        removed = self.store.remove(request.get("handle") or "")
        log.info("item removed: %s (%s)", request.get("handle"), removed)
        return {"ok": True, "removed": removed}

    def _op_fill(self, request: dict) -> dict:
        # A model-supplied endpoint was the original exfiltration path. Reject it
        # outright rather than silently ignoring it, so a stale or injected client
        # fails loudly.
        if "cdp" in request:
            return {"ok": False, "error": "cdp is not accepted; the broker owns its DevTools endpoint"}
        if self.endpoint is None:
            return {"ok": False, "error": "no DevTools endpoint configured"}
        handle = request.get("handle") or ""
        origin = request.get("origin") or ""
        meta, password = self.store.resolve(handle, origin)
        result = cdp_module.fill_login(
            origin=meta.origin,
            password=password,
            endpoint=self.endpoint,
            submit=bool(request.get("submit")),
        )
        log.info("filled %s on %s (%s fields)", meta.id, meta.origin, result.get("filled"))
        return {"ok": True, "handle": meta.id, "origin": meta.origin, **result}


class Handler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        broker = self.server.broker
        uid = peer_uid(self.connection)
        try:
            line = self.rfile.readline(MAX_LINE)
        except OSError:
            return
        if not line:
            return
        try:
            request = json.loads(line.decode("utf-8", "replace"))
        except ValueError:
            self._reply({"ok": False, "error": "malformed request"})
            return
        if not isinstance(request, dict):
            self._reply({"ok": False, "error": "malformed request"})
            return
        self._reply(broker.handle(request, uid))

    def _reply(self, payload: dict) -> None:
        try:
            self.wfile.write((json.dumps(payload) + "\n").encode("utf-8"))
            self.wfile.flush()
        except OSError:
            pass


class Server(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, path: str, broker: Broker):
        self.broker = broker
        if os.path.exists(path):
            os.unlink(path)
        super().__init__(path, Handler)
        os.chmod(path, 0o660)

    def process_request(self, request, client_address):
        # A slow or hostile client must not stall the loop.
        request.settimeout(10)
        super().process_request(request, client_address)


def serve(
    socket_path: str,
    state_path: str,
    allowed_uids: tuple[int, ...],
    endpoint: Endpoint,
) -> None:
    store = Store(state_path)
    broker = Broker(store, allowed_uids=allowed_uids, endpoint=endpoint)
    server = Server(socket_path, broker)
    log.info("listening on %s (state %s)", socket_path, state_path)
    try:
        server.serve_forever()
    finally:
        server.server_close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="broker.daemon")
    parser.add_argument("--socket", default=DEFAULT_SOCKET)
    parser.add_argument("--state", default=DEFAULT_STATE)
    parser.add_argument(
        "--cdp-config",
        default=DEFAULT_CONFIG_PATH,
        help="root-owned JSON file holding the loopback DevTools endpoint",
    )
    parser.add_argument(
        "--allow-uid",
        action="append",
        type=int,
        default=None,
        help="uid allowed to call status/list/fill (the Hermes gateway uid)",
    )
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )
    try:
        endpoint = load_config(args.cdp_config)
    except EndpointError as exc:
        log.error("refusing to start: %s", exc)
        return 2
    admins = (0, os.getuid())
    allowed = tuple(dict.fromkeys(admins + tuple(args.allow_uid or [])))
    try:
        serve(args.socket, args.state, allowed, endpoint)
    except KeyboardInterrupt:
        return 0
    return 0
