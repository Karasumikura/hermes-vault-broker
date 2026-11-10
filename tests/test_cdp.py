import json
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from broker import cdp  # noqa: E402


def _fake_devtools(tabs):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            return

        def do_GET(self):  # noqa: N802
            body = json.dumps(tabs).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, "http://127.0.0.1:%d" % server.server_address[1]


class OriginTest(unittest.TestCase):
    def test_forms(self):
        self.assertEqual(cdp.origin_of("https://www.kaggle.com/account/login"), "https://www.kaggle.com")
        self.assertEqual(cdp.origin_of("https://example.com:443/x"), "https://example.com")
        self.assertEqual(cdp.origin_of("http://127.0.0.1:8080/login"), "http://127.0.0.1:8080")
        self.assertEqual(cdp.origin_of("about:blank"), "")


class TabLookupTest(unittest.TestCase):
    def test_picks_the_tab_on_the_origin(self):
        server, url = _fake_devtools(
            [
                {"type": "page", "url": "https://www.kaggle.com/account/login", "webSocketDebuggerUrl": "ws://127.0.0.1:1/a"},
                {"type": "page", "url": "https://www.google.com/", "webSocketDebuggerUrl": "ws://127.0.0.1:1/b"},
                {"type": "service_worker", "url": "https://www.kaggle.com/sw.js"},
            ]
        )
        try:
            tab = cdp.find_tab("https://www.kaggle.com", cdp_url=url)
        finally:
            server.shutdown()
            server.server_close()
        self.assertEqual(tab["webSocketDebuggerUrl"], "ws://127.0.0.1:1/a")

    def test_no_tab_means_error(self):
        server, url = _fake_devtools([{"type": "page", "url": "https://www.google.com/"}])
        try:
            with self.assertRaises(cdp.CdpError) as caught:
                cdp.find_tab("https://www.kaggle.com", cdp_url=url)
        finally:
            server.shutdown()
            server.server_close()
        self.assertIn("no open tab", str(caught.exception))

    def test_unreachable_endpoint(self):
        with self.assertRaises(cdp.CdpError):
            cdp.find_tab("https://www.kaggle.com", cdp_url="http://127.0.0.1:9")


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


if __name__ == "__main__":
    unittest.main()
