"""One-time HTTPS form that hands the passphrase straight to the broker.

The broker starts locked. Nothing on disk can decrypt the store without the
passphrase, so the operator types it here, once per boot: the value goes from
this page's POST body to the broker socket and nowhere else — not to the agent,
not to a log, not to disk.

Security shape:
  * single-use random token in the URL; anything else is 403
  * one page, one field, no autocomplete, no-store
  * ``log_message`` is disabled, so not even the request line is recorded
  * self-signed TLS (the box has no public certificate for this port)
  * the server exits after one successful submission or the timeout
"""

from __future__ import annotations

import argparse
import hmac
import os
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

from .client import BrokerUnavailable, call

# The form has exactly one field. Reject oversized (or malformed) bodies before
# reading them so a remote caller cannot make us buffer an arbitrary amount.
MAX_POST_BYTES = 4096

PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Vault broker unlock</title>
<style>
body{background:#111;color:#eee;font:16px/1.6 system-ui,sans-serif;padding:24px;max-width:520px;margin:0 auto}
h2{font-size:19px;margin:0 0 6px}
p{color:#aaa;font-size:14px;margin:6px 0 18px}
input[type=password]{width:100%;box-sizing:border-box;font-size:18px;padding:14px;border-radius:10px;
 border:1px solid #555;background:#1c1c1c;color:#fff}
button{margin-top:16px;width:100%;font-size:18px;padding:14px;border:0;border-radius:10px;
 background:#c33;color:#fff;font-weight:700}
.ok{color:#7f7;font-size:18px}
code{color:#8cf;font-size:13px}
</style></head><body>
<h2>Unlock the vault broker</h2>
<p>Passphrase only. It is passed to the broker socket and nowhere else.</p>
<form method="post" action="/?t=__TOKEN__">
<input type="password" name="pw" placeholder="Passphrase" autocomplete="off" required autofocus>
<button type="submit">Unlock</button>
</form></body></html>"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="broker.unlock_form")
    parser.add_argument("--socket", default="/run/hermes-vault-broker/sock")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--timeout", type=float, default=900.0)
    parser.add_argument("--public-url", default="", help="printed as-is so the operator can open it")
    args = parser.parse_args(argv)

    token = os.urandom(16).hex()
    done = threading.Event()
    html = PAGE.replace("__TOKEN__", token)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):  # noqa: D401 - silence request lines (they carry the token)
            return

        def _send(self, body: str, code: int = 200) -> None:
            raw = body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(raw)

        def _token_ok(self) -> bool:
            query = self.path.split("?", 1)[-1] if "?" in self.path else ""
            supplied = parse_qs(query).get("t", [""])[0]
            # compare_digest only accepts ASCII str; encode so a non-ASCII token
            # cannot raise TypeError and turn into a 500.
            return hmac.compare_digest(supplied.encode("utf-8", "replace"), token.encode("ascii"))

        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            if not self._token_ok():
                self._send("<h2>link expired</h2>", 403)
                return
            self._send(html)

        def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            if not self._token_ok():
                self._send("<h2>link expired</h2>", 403)
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self._send("<h2>bad request</h2>", 400)
                return
            if length < 0 or length > MAX_POST_BYTES:
                self._send("<h2>request too large</h2>", 413)
                return
            body = self.rfile.read(length)
            passphrase = parse_qs(body.decode("utf-8", "replace")).get("pw", [""])[0]
            if not passphrase:
                self._send("<h2>empty</h2>", 400)
                return
            try:
                status = call({"op": "status"}, socket_path=args.socket)
                op = "init" if not status.get("initialized") else "unlock"
                reply = call({"op": op, "passphrase": passphrase}, socket_path=args.socket)
            except BrokerUnavailable as exc:
                self._send("<h2>broker unavailable</h2><p>%s</p>" % exc, 503)
                return
            finally:
                passphrase = ""
                body = b""
            if not reply.get("ok"):
                self._send("<h2>unlock failed</h2><p>%s</p>" % reply.get("error", ""), 400)
                return
            self._send(
                '<h2 class="ok">%s</h2><p>You can close this page.</p>'
                % ("Store created." if op == "init" else "Unlocked.")
            )
            done.set()

    server = HTTPServer((args.host, args.port), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(args.cert, args.key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    port = server.server_address[1]
    base = args.public_url or "https://%s:%d" % (args.host, port)
    print("URL=%s/?t=%s" % (base.rstrip("/"), token), flush=True)

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        done.wait(timeout=args.timeout)
    finally:
        server.shutdown()
        server.server_close()
    print("FORM_CLOSED", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
