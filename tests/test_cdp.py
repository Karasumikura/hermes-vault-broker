import inspect
import json
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from broker import cdp  # noqa: E402
from broker.endpoint import validate_base  # noqa: E402


def _serve(handler_cls):
    server = HTTPServer(("127.0.0.1", 0), handler_cls)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    endpoint = validate_base("http://127.0.0.1:%d" % server.server_address[1])
    return server, endpoint


def _fake_devtools(tabs):
    return _fake_devtools_with(lambda _endpoint: tabs)


def _fake_devtools_with(tabs_fn):
    """Like _fake_devtools, but tabs are built after the port is known."""
    box = {}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):  # noqa: A002
            return

        def do_GET(self):  # noqa: N802
            body = json.dumps(box["tabs"]).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server, endpoint = _serve(Handler)
    box["tabs"] = tabs_fn(endpoint)
    return server, endpoint


class OriginTest(unittest.TestCase):
    def test_forms(self):
        self.assertEqual(cdp.origin_of("https://www.kaggle.com/account/login"), "https://www.kaggle.com")
        self.assertEqual(cdp.origin_of("https://example.com:443/x"), "https://example.com")
        self.assertEqual(cdp.origin_of("http://127.0.0.1:8080/login"), "http://127.0.0.1:8080")
        self.assertEqual(cdp.origin_of("about:blank"), "")


class TabLookupTest(unittest.TestCase):
    def test_picks_the_tab_on_the_origin(self):
        server, endpoint = _fake_devtools(
            [
                {"type": "page", "url": "https://www.kaggle.com/account/login", "webSocketDebuggerUrl": "ws://127.0.0.1:1/a"},
                {"type": "page", "url": "https://www.google.com/", "webSocketDebuggerUrl": "ws://127.0.0.1:1/b"},
                {"type": "service_worker", "url": "https://www.kaggle.com/sw.js"},
            ]
        )
        try:
            tab = cdp.find_tab("https://www.kaggle.com", endpoint)
        finally:
            server.shutdown()
            server.server_close()
        self.assertEqual(tab["webSocketDebuggerUrl"], "ws://127.0.0.1:1/a")

    def test_no_tab_means_error(self):
        server, endpoint = _fake_devtools([{"type": "page", "url": "https://www.google.com/"}])
        try:
            with self.assertRaises(cdp.CdpError) as caught:
                cdp.find_tab("https://www.kaggle.com", endpoint)
        finally:
            server.shutdown()
            server.server_close()
        self.assertIn("no open tab", str(caught.exception))

    def test_unreachable_endpoint(self):
        with self.assertRaises(cdp.CdpError):
            cdp.find_tab("https://www.kaggle.com", validate_base("http://127.0.0.1:9"))


class ExpressionTest(unittest.TestCase):
    def test_password_is_escaped_not_interpolated(self):
        tricky = 'p@ss"word\\n</script>'
        expression = cdp._FILL_JS % {
            "origin": json.dumps("https://www.kaggle.com"),
            "password": json.dumps(tricky),
            "submit": "false",
        }
        self.assertIn(json.dumps(tricky), expression)
        self.assertNotIn('"password"', expression)  # no field names leak into the page
        self.assertIn("window.location.origin", expression)
        self.assertIn("requestSubmit", expression)


class EndpointPinningTest(unittest.TestCase):
    """The original exfiltration path: a fake DevTools endpoint receives the password."""

    def test_fill_takes_no_cdp_url_from_any_caller(self):
        names = set(inspect.signature(cdp.fill_login).parameters)
        self.assertIn("endpoint", names)
        self.assertNotIn("cdp_url", names)
        self.assertNotIn("cdp", names)

    def test_mismatched_websocket_never_sends_the_password(self):
        # A tab advertising a websocket on a DIFFERENT host:port must be
        # refused before anything is sent.
        server, endpoint = _fake_devtools(
            [{
                "type": "page",
                "url": "https://www.kaggle.com/account/login",
                "webSocketDebuggerUrl": "ws://attacker.example:9223/devtools/page/X",
            }]
        )
        try:
            with mock.patch.object(cdp, "_evaluate") as evaluate:
                with self.assertRaises(cdp.CdpError) as caught:
                    cdp.fill_login("https://www.kaggle.com", "super-secret", endpoint)
                evaluate.assert_not_called()
        finally:
            server.shutdown()
            server.server_close()
        self.assertIn("differs from the configured", str(caught.exception))
        self.assertNotIn("super-secret", str(caught.exception))

    def test_matching_websocket_is_used(self):
        server, endpoint = _fake_devtools_with(
            lambda e: [{
                "type": "page",
                "url": "https://www.kaggle.com/account/login",
                "webSocketDebuggerUrl": "ws://127.0.0.1:%d/devtools/page/OK" % e.port,
            }]
        )
        reply = {"id": 1, "result": {"result": {"value": json.dumps({"filled": 1, "submitted": False})}}}
        try:
            with mock.patch.object(cdp, "_evaluate", return_value=reply) as evaluate:
                out = cdp.fill_login("https://www.kaggle.com", "pw-value", endpoint)
            ws_url, expression = evaluate.call_args.args
            self.assertIn(":%d/" % endpoint.port, ws_url)
            self.assertIn(json.dumps("pw-value"), expression)
        finally:
            server.shutdown()
            server.server_close()
        self.assertEqual(out, {"filled": 1, "submitted": False})

    def test_redirect_is_refused(self):
        class RedirectHandler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):  # noqa: A002
                return

            def do_GET(self):  # noqa: N802
                self.send_response(302)
                self.send_header("Location", "http://127.0.0.1:9/json/list")
                self.end_headers()

        server, endpoint = _serve(RedirectHandler)
        try:
            with self.assertRaises(cdp.CdpError) as caught:
                cdp.list_tabs(endpoint)
        finally:
            server.shutdown()
            server.server_close()
        self.assertIn("redirect", str(caught.exception))

    def test_unvalidated_endpoint_is_refused(self):
        with self.assertRaises(cdp.CdpError):
            cdp.fill_login("https://www.kaggle.com", "pw", "http://127.0.0.1:9223")  # type: ignore[arg-type]

    def test_environment_proxy_cannot_bypass_the_loopback_check(self):
        import os
        from websockets.sync.client import connect

        # http.client dials the validated host:port directly, so a poisoned
        # proxy environment cannot reroute /json/list off the box.
        with mock.patch.dict(
            os.environ,
            {"http_proxy": "http://127.0.0.1:9", "HTTP_PROXY": "http://127.0.0.1:9", "no_proxy": ""},
        ):
            server, endpoint = _fake_devtools([{"type": "page", "url": "https://www.kaggle.com/"}])
            try:
                self.assertEqual(len(cdp.list_tabs(endpoint)), 1)
            finally:
                server.shutdown()
                server.server_close()

        if "proxy" not in inspect.signature(connect).parameters:
            self.skipTest("websockets <14 has no env-proxy support")
        reply = {"id": 1, "result": {"result": {"value": "{}"}}}
        with mock.patch("websockets.sync.client.connect") as conn:
            ws = conn.return_value.__enter__.return_value
            ws.recv.return_value = json.dumps(reply)
            cdp._evaluate("ws://127.0.0.1:9223/devtools/page/X", "1+1")
        self.assertIsNone(conn.call_args.kwargs.get("proxy"))


if __name__ == "__main__":
    unittest.main()
