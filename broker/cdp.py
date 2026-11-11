"""Minimal Chrome DevTools Protocol client.

The broker does the write itself: it finds the tab whose origin matches the
item, asks that tab to run one self-contained script that re-asserts the origin
and sets the password, and reports only a count. The caller never sees a value.

The endpoint is never a request parameter. It comes from the broker's own
root-owned config (:mod:`broker.endpoint`); this module refuses non-loopback
endpoints, refuses redirects, and refuses any ``webSocketDebuggerUrl`` whose
host:port differs from the configured endpoint *before* the password is sent.
"""

from __future__ import annotations

import http.client
import inspect
import json
from urllib.parse import urlsplit

from .endpoint import Endpoint, EndpointError, validate_ws_url

# Cap the /json/list response so the broker always reads a bounded amount.
MAX_TABS_BYTES = 1024 * 1024


class CdpError(Exception):
    """Failure safe to surface; never contains the password."""


def origin_of(url: str) -> str:
    try:
        parts = urlsplit(url or "")
        scheme = (parts.scheme or "").lower()
        host = (parts.hostname or "").lower()
        port = parts.port
    except ValueError:
        # A malicious tab can put an invalid port in its URL; that is not a
        # reason to let a ValueError escape into the daemon's generic handler.
        return ""
    if not scheme or not host:
        return ""
    if port is None or port == {"http": 80, "https": 443}.get(scheme):
        return "%s://%s" % (scheme, host)
    return "%s://%s:%d" % (scheme, host, port)


def _safe_message(value, limit: int = 160) -> str:
    """Text controlled by a tab/endpoint, bounded before it reaches the agent."""
    text = value if isinstance(value, str) else str(value)
    return " ".join(text.split())[:limit]


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


def list_tabs(endpoint: Endpoint) -> list[dict]:
    """Fetch ``/json/list`` over a direct loopback connection.

    ``http.client`` is deliberate: no urllib opener, so there is no environment
    proxy to honour and no redirect handler to follow. Only the validated
    endpoint's host/port is ever dialled.
    """
    if not isinstance(endpoint, Endpoint):
        raise CdpError("no validated DevTools endpoint configured")
    try:
        conn = http.client.HTTPConnection(endpoint.host, endpoint.port, timeout=5)
        try:
            conn.request("GET", "/json/list")
            response = conn.getresponse()
            if response.status != 200:
                raise CdpError(
                    "the DevTools endpoint returned HTTP %d (redirects are not followed)" % response.status
                )
            raw = response.read(MAX_TABS_BYTES + 1)
        finally:
            conn.close()
        if len(raw) > MAX_TABS_BYTES:
            raise CdpError("the DevTools endpoint returned an oversized payload")
        tabs = json.loads(raw)
    except CdpError:
        raise
    except Exception as exc:  # noqa: BLE001 - any transport failure is the same story for the caller
        raise CdpError("cannot reach the configured DevTools endpoint") from exc
    if not isinstance(tabs, list):
        raise CdpError("DevTools endpoint returned an unexpected payload")
    return tabs


def find_tab(origin: str, endpoint: Endpoint) -> dict:
    wanted = origin.rstrip("/")
    pages = [t for t in list_tabs(endpoint) if t.get("type") == "page"]
    for tab in pages:
        if origin_of(tab.get("url", "")) == wanted:
            return tab
    seen = ", ".join(sorted({origin_of(t.get("url", "")) for t in pages})[:5])[:200] or "none"
    raise CdpError("no open tab on %s (open tabs: %s)" % (wanted, seen))


def _evaluate(ws_url: str, expression: str, timeout: float = 15.0) -> dict:
    from websockets.sync.client import connect

    # websockets >=14 defaults to proxy=True and honours http_proxy from the
    # environment — that would bypass the loopback check even for a ws:// URL
    # on 127.0.0.1. Disable the proxy when this version supports it; 13.x has
    # no such argument (and no env-proxy support either).
    kwargs = {"open_timeout": timeout, "close_timeout": 2, "max_size": None}
    try:
        if "proxy" in inspect.signature(connect).parameters:
            kwargs["proxy"] = None
    except (TypeError, ValueError):  # pragma: no cover - exotic build
        pass
    try:
        with connect(ws_url, **kwargs) as ws:
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
    endpoint: Endpoint,
    submit: bool = False,
) -> dict:
    """Write *password* into the login form of the tab on *origin*.

    ``endpoint`` is the broker-owned, validated loopback endpoint, never a value
    taken from a socket request. Returns ``{"filled": n, "submitted": bool}``.
    Raises :class:`CdpError` when the tab cannot be reached, the page moved off
    the origin, the advertised websocket is not the configured endpoint, or no
    password field matched — in every case nothing is written.
    """
    if not password:
        raise CdpError("no password to fill")
    if not isinstance(endpoint, Endpoint):
        raise CdpError("no validated DevTools endpoint configured")
    tab = find_tab(origin, endpoint)
    ws_url = tab.get("webSocketDebuggerUrl")
    if not ws_url:
        raise CdpError("the DevTools endpoint did not offer a websocket for this tab")
    try:
        ws_url = validate_ws_url(ws_url, endpoint)
    except EndpointError as exc:
        raise CdpError(str(exc)) from exc

    expression = _FILL_JS % {
        "origin": json.dumps(origin),
        "password": json.dumps(password),
        "submit": "true" if submit else "false",
    }
    reply = _evaluate(ws_url, expression)
    return _parse_reply(reply, origin)


def _parse_reply(reply: dict, origin: str) -> dict:
    """Turn a Runtime.evaluate reply into ``{filled, submitted}``."""
    if not isinstance(reply, dict):
        raise CdpError("the DevTools endpoint returned an unexpected reply")
    if "error" in reply:
        detail = reply["error"]
        if isinstance(detail, dict):
            detail = detail.get("message") or "unknown"
        raise CdpError("DevTools error: %s" % _safe_message(detail))
    result = reply.get("result", {}).get("result", {})
    if not isinstance(result, dict):
        raise CdpError("the DevTools endpoint returned an unexpected result")
    raw = result.get("value")
    try:
        parsed = json.loads(raw) if isinstance(raw, str) else {}
    except ValueError:
        raise CdpError("the page returned an unreadable result") from None
    if not isinstance(parsed, dict):
        raise CdpError("the page returned an unreadable result")
    if parsed.get("refused"):
        raise CdpError(
            "refused: the page is on %s, not %s — nothing was written"
            % (_safe_message(parsed.get("found") or "unknown"), origin)
        )
    if parsed.get("error"):
        raise CdpError(_safe_message(parsed["error"]))
    try:
        filled = int(parsed.get("filled", 0))
    except (TypeError, ValueError):
        raise CdpError("the page returned an unreadable result") from None
    return {"filled": filled, "submitted": bool(parsed.get("submitted"))}


def fill_login_pipe(origin: str, password: str, transport, submit: bool = False) -> dict:
    """Fill through a broker-owned browser speaking CDP over a pipe.

    There is no websocket URL and no TCP port: the tab is addressed by its
    target id inside the browser the broker itself launched.
    """
    if not password:
        raise CdpError("no password to fill")
    wanted = origin.rstrip("/")
    pages = [t for t in transport.list_tabs() if t.get("type") == "page"]
    tab = next((t for t in pages if origin_of(t.get("url", "")) == wanted), None)
    if tab is None and pages and getattr(transport, "navigate", None):
        # The broker owns this browser, so it opens the credential's bound
        # origin itself; the destination comes from the store, not the model.
        try:
            transport.navigate(pages[0].get("id"), origin)
            pages = [t for t in transport.list_tabs() if t.get("type") == "page"]
            tab = next((t for t in pages if origin_of(t.get("url", "")) == wanted), None)
        except Exception as exc:  # noqa: BLE001 - surface by type, never by content
            raise CdpError("DevTools navigation failed: %s" % type(exc).__name__) from exc
    if tab is None:
        seen = ", ".join(sorted({origin_of(t.get("url", "")) for t in pages})[:5])[:200] or "none"
        raise CdpError("no open tab on %s (open tabs: %s)" % (wanted, seen))
    expression = _FILL_JS % {
        "origin": json.dumps(origin),
        "password": json.dumps(password),
        "submit": "true" if submit else "false",
    }
    try:
        reply = transport.evaluate(tab.get("id"), expression)
    except Exception as exc:  # noqa: BLE001 - transport failures are safe to surface by type
        raise CdpError("DevTools evaluation failed: %s" % type(exc).__name__) from exc
    return _parse_reply(reply, origin)
