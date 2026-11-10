"""Minimal Chrome DevTools Protocol client.

The broker does the write itself: it finds the tab whose origin matches the
item, asks that tab to run one self-contained script that re-asserts the origin
and sets the password, and reports only a count. The caller never sees a value.
"""

from __future__ import annotations

import json
import urllib.request
from urllib.parse import urlsplit

DEFAULT_CDP = "http://127.0.0.1:9223"


class CdpError(Exception):
    """Failure safe to surface; never contains the password."""


def origin_of(url: str) -> str:
    parts = urlsplit(url or "")
    scheme = (parts.scheme or "").lower()
    host = (parts.hostname or "").lower()
    if not scheme or not host:
        return ""
    port = parts.port
    if port is None or port == {"http": 80, "https": 443}.get(scheme):
        return "%s://%s" % (scheme, host)
    return "%s://%s:%d" % (scheme, host, port)


_FILL_JS = """(() => {
  const expect = %(origin)s;
  const value = %(password)s;
  if (window.location.origin !== expect) {
    return JSON.stringify({refused: "origin_changed", found: window.location.origin});
  }
  const roots = [];
  (function walk(root) {
    roots.push(root);
    for (const el of root.querySelectorAll("*")) if (el.shadowRoot) walk(el.shadowRoot);
  })(document);
  const find = (sel) => roots.flatMap((r) => Array.from(r.querySelectorAll(sel)));
  const visible = (el) => !!(el.offsetParent || el.getClientRects().length);
  const candidates = find("input[type=password]").filter(visible);
  const excluded = /new|confirm|repeat|create/i;
  const target = candidates.find((el) =>
      !excluded.test((el.name || "") + (el.id || "") + (el.getAttribute("autocomplete") || ""))
    ) || candidates[0];
  if (!target) return JSON.stringify({filled: 0, error: "no password field"});
  target.focus();
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value");
  if (setter && setter.set) setter.set.call(target, value); else target.value = value;
  target.dispatchEvent(new InputEvent("input", {bubbles: true, composed: true, inputType: "insertText"}));
  target.dispatchEvent(new Event("change", {bubbles: true, composed: true}));
  let submitted = false;
  if (%(submit)s && target.form) {
    try { target.form.requestSubmit(); submitted = true; }
    catch (err) { target.form.submit(); submitted = true; }
  }
  return JSON.stringify({filled: target.value.length > 0 ? 1 : 0, submitted: submitted});
})()"""


def list_tabs(cdp_url: str = DEFAULT_CDP) -> list[dict]:
    url = cdp_url.rstrip("/") + "/json/list"
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            tabs = json.load(response)
    except Exception as exc:  # noqa: BLE001 - any transport failure is the same story for the caller
        raise CdpError("cannot reach the browser DevTools endpoint at %s" % cdp_url) from exc
    if not isinstance(tabs, list):
        raise CdpError("DevTools endpoint returned an unexpected payload")
    return tabs


def find_tab(origin: str, cdp_url: str = DEFAULT_CDP) -> dict:
    wanted = origin.rstrip("/")
    pages = [t for t in list_tabs(cdp_url) if t.get("type") == "page"]
    for tab in pages:
        if origin_of(tab.get("url", "")) == wanted:
            return tab
    seen = ", ".join(sorted({origin_of(t.get("url", "")) for t in pages})) or "none"
    raise CdpError("no open tab on %s (open tabs: %s)" % (wanted, seen))


def _evaluate(ws_url: str, expression: str, timeout: float = 15.0) -> dict:
    from websockets.sync.client import connect

    try:
        with connect(ws_url, open_timeout=timeout, close_timeout=2, max_size=None) as ws:
            ws.send(json.dumps({
                "id": 1,
                "method": "Runtime.evaluate",
                "params": {"expression": expression, "returnByValue": True, "awaitPromise": True},
            }))
            while True:
                message = json.loads(ws.recv(timeout=timeout))
                if message.get("id") == 1:
                    return message
    except CdpError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise CdpError("DevTools evaluation failed: %s" % type(exc).__name__) from exc


def fill_login(
    origin: str,
    password: str,
    cdp_url: str = DEFAULT_CDP,
    submit: bool = False,
) -> dict:
    """Write *password* into the login form of the tab on *origin*.

    Returns ``{"filled": n, "submitted": bool}``. Raises :class:`CdpError` when
    the tab cannot be reached, the page moved off the origin, or no password
    field matched — in every case nothing is written.
    """
    if not password:
        raise CdpError("no password to fill")
    tab = find_tab(origin, cdp_url)
    ws_url = tab.get("webSocketDebuggerUrl")
    if not ws_url:
        raise CdpError("the DevTools endpoint did not offer a websocket for this tab")

    expression = _FILL_JS % {
        "origin": json.dumps(origin),
        "password": json.dumps(password),
        "submit": "true" if submit else "false",
    }
    reply = _evaluate(ws_url, expression)
    if "error" in reply:
        raise CdpError("DevTools error: %s" % (reply["error"].get("message") or "unknown"))
    result = reply.get("result", {}).get("result", {})
    raw = result.get("value")
    try:
        parsed = json.loads(raw) if isinstance(raw, str) else {}
    except ValueError:
        raise CdpError("the page returned an unreadable result") from None
    if parsed.get("refused"):
        raise CdpError(
            "refused: the page is on %s, not %s — nothing was written"
            % (parsed.get("found") or "unknown", origin)
        )
    if parsed.get("error"):
        raise CdpError(parsed["error"])
    return {"filled": int(parsed.get("filled", 0)), "submitted": bool(parsed.get("submitted"))}
