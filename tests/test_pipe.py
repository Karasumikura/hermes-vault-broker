"""Broker-owned browser: CDP over a pipe, with a real Chromium round trip."""

import json
import os
import sys
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from broker import cdp  # noqa: E402
from broker.pipe import PipeTransport  # noqa: E402

BROWSER = "/usr/bin/chromium"


class PipeUnitTest(unittest.TestCase):
    def test_fill_uses_the_matching_tab_and_never_a_websocket(self):
        transport = mock.Mock()
        transport.list_tabs.return_value = [
            {"type": "page", "url": "https://www.kaggle.com/account/login", "id": "T1"},
            {"type": "page", "url": "https://other.example/", "id": "T2"},
        ]
        transport.evaluate.return_value = {
            "id": 1,
            "result": {"result": {"value": json.dumps({"filled": 1, "submitted": False})}},
        }
        out = cdp.fill_login_pipe("https://www.kaggle.com", "pw-value", transport)
        self.assertEqual(out, {"filled": 1, "submitted": False})
        self.assertEqual(transport.evaluate.call_args.args[0], "T1")
        self.assertIn(json.dumps("pw-value"), transport.evaluate.call_args.args[1])
        self.assertIn("window.location.origin", transport.evaluate.call_args.args[1])

    def test_no_matching_tab_writes_nothing(self):
        transport = mock.Mock(spec=["list_tabs", "evaluate"])
        transport.list_tabs.return_value = [
            {"type": "page", "url": "https://other.example/", "id": "T1"}
        ]
        with self.assertRaises(cdp.CdpError) as caught:
            cdp.fill_login_pipe("https://www.kaggle.com", "pw", transport)
        self.assertIn("no open tab", str(caught.exception))
        transport.evaluate.assert_not_called()

    def test_auto_navigate_opens_the_bound_origin(self):
        transport = mock.Mock(spec=["list_tabs", "evaluate", "navigate"])
        transport.list_tabs.side_effect = [
            [{"type": "page", "url": "about:blank", "id": "T1"}],
            [{"type": "page", "url": "https://www.kaggle.com/account/login", "id": "T1"}],
        ]
        transport.evaluate.return_value = {
            "id": 1,
            "result": {"result": {"value": json.dumps({"filled": 1, "submitted": False})}},
        }
        out = cdp.fill_login_pipe("https://www.kaggle.com", "pw-value", transport)
        self.assertEqual(out, {"filled": 1, "submitted": False})
        self.assertEqual(
            transport.navigate.call_args.args, ("T1", "https://www.kaggle.com")
        )

    def test_transport_failure_is_reported_by_type(self):
        transport = mock.Mock(spec=["list_tabs", "evaluate"])
        transport.list_tabs.return_value = [
            {"type": "page", "url": "https://www.kaggle.com/login", "id": "T1"}
        ]
        transport.evaluate.side_effect = RuntimeError("internal detail")
        with self.assertRaises(cdp.CdpError) as caught:
            cdp.fill_login_pipe("https://www.kaggle.com", "pw", transport)
        self.assertIn("RuntimeError", str(caught.exception))
        self.assertNotIn("internal detail", str(caught.exception))


@unittest.skipUnless(
    os.path.isfile(BROWSER) and os.access(BROWSER, os.X_OK),
    "needs an executable Chromium",
)
class PipeEndToEndTest(unittest.TestCase):
    """Real browser, real fd 3/4 pipe, real password field."""

    @classmethod
    def setUpClass(cls):
        cls.transport: PipeTransport | None = PipeTransport(BROWSER, ("about:blank",))

    @classmethod
    def tearDownClass(cls):
        if cls.transport is not None:
            cls.transport.close()

    def _pipe(self) -> PipeTransport:
        assert self.transport is not None
        return self.transport

    def _form(self, tid: str) -> None:
        self._pipe().evaluate(
            tid, "document.body.innerHTML='<form><input type=password name=pw></form>'"
        )

    def _current_origin(self, tid: str) -> str:
        reply = self._pipe().evaluate(tid, "window.location.origin")
        return reply["result"]["result"]["value"]

    def test_password_is_written_into_the_page_over_the_pipe(self):
        pipe = self._pipe()
        tid = pipe.list_tabs()[0]["id"]
        self._form(tid)
        expression = cdp._FILL_JS % {
            "origin": json.dumps(self._current_origin(tid)),
            "password": json.dumps("pipe-secret-42"),
            "submit": "false",
        }
        reply = pipe.evaluate(tid, expression)
        self.assertEqual(json.loads(reply["result"]["result"]["value"]), {"filled": 1, "submitted": False})
        check = pipe.evaluate(tid, "document.querySelector('input[type=password]').value")
        self.assertEqual(check["result"]["result"]["value"], "pipe-secret-42")

    def test_navigate_reaches_a_real_page(self):
        import tempfile

        page = Path(tempfile.mkdtemp(prefix="vb-nav-")) / "login.html"
        page.write_text(
            "<!doctype html><html><body>NAVIGATED<input type=password></body></html>",
            encoding="utf-8",
        )
        pipe = self._pipe()
        tid = pipe.list_tabs()[0]["id"]
        pipe.navigate(tid, page.as_uri())
        reply = pipe.evaluate(tid, "document.body.innerText")
        self.assertIn("NAVIGATED", reply["result"]["result"]["value"])

    def test_exact_origin_is_reasserted_inside_the_real_page(self):
        pipe = self._pipe()
        tid = pipe.list_tabs()[0]["id"]
        self._form(tid)
        expression = cdp._FILL_JS % {
            "origin": json.dumps("https://expected.example"),
            "password": json.dumps("must-not-appear"),
            "submit": "false",
        }
        reply = pipe.evaluate(tid, expression)
        parsed = json.loads(reply["result"]["result"]["value"])
        self.assertEqual(parsed.get("refused"), "origin_changed")
        check = pipe.evaluate(tid, "document.querySelector('input[type=password]').value")
        self.assertEqual(check["result"]["result"]["value"], "")


class PipeHardeningTest(unittest.TestCase):
    def test_oversized_pipe_message_is_rejected(self):
        from broker import pipe

        transport = object.__new__(pipe.PipeTransport)
        transport._r = 999
        transport._buf = b""
        with mock.patch.object(pipe.select, "select", return_value=([999], [], [])), mock.patch.object(
            pipe.os, "read", return_value=b"x" * (pipe._MAX_MESSAGE_BYTES + 1)
        ):
            with self.assertRaises(pipe.PipeError) as caught:
                transport._read_message(time.monotonic() + 5)
        self.assertIn("oversized", str(caught.exception))

    def test_attach_reuses_one_session(self):
        from broker import pipe

        transport = object.__new__(pipe.PipeTransport)
        transport._sessions = {}
        transport._session_lock = threading.Lock()
        calls = []

        def fake_command(method, params=None, session_id=None, timeout=None):
            calls.append(method)
            return {"sessionId": "S1"} if method == "Target.attachToTarget" else {"result": {}}

        transport.command = fake_command
        self.assertEqual(transport._attach("T1"), "S1")
        self.assertEqual(transport._attach("T1"), "S1")
        self.assertEqual(calls.count("Target.attachToTarget"), 1)

    def test_navigation_failure_writes_nothing(self):
        transport = mock.Mock(spec=["list_tabs", "evaluate", "navigate"])
        transport.list_tabs.return_value = [
            {"type": "page", "url": "about:blank", "id": "T1"}
        ]
        transport.navigate.side_effect = RuntimeError("no route")
        with self.assertRaises(cdp.CdpError) as caught:
            cdp.fill_login_pipe("https://www.kaggle.com", "pw", transport)
        self.assertIn("navigation failed", str(caught.exception))
        transport.evaluate.assert_not_called()


if __name__ == "__main__":
    unittest.main()
