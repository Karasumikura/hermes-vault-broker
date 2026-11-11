import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from broker import daemon  # noqa: E402
from broker.endpoint import PipeConfig, validate_base  # noqa: E402
from broker.store import Store  # noqa: E402

PASS = "correct horse battery staple"
ENDPOINT = validate_base("http://127.0.0.1:9")


class BrokerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(os.path.join(self.tmp.name, "store.json"))
        self.store.create(PASS)
        self.broker = daemon.Broker(self.store, allowed_uids=(0,), endpoint=ENDPOINT)

    def tearDown(self):
        self.tmp.cleanup()

    def _add(self, password="pw"):
        return self.broker.handle(
            {
                "op": "add",
                "label": "kaggle",
                "origin": "https://www.kaggle.com",
                "identifier_type": "email",
                "identifier": "me@example.com",
                "password": password,
            },
            0,
        )

    def test_status_reports_lock_state(self):
        reply = self.broker.handle({"op": "status"}, 0)
        self.assertEqual(reply, {"ok": True, "initialized": True, "unlocked": True, "items": 0})

    def test_init_refuses_when_a_store_exists(self):
        reply = self.broker.handle({"op": "init", "passphrase": "another passphrase"}, 0)
        self.assertFalse(reply["ok"])
        self.assertIn("already exists", reply["error"])

    def test_foreign_uid_is_refused(self):
        reply = self.broker.handle({"op": "list"}, 1234)
        self.assertFalse(reply["ok"])
        self.assertEqual(reply["error"], "not permitted")

    def test_unknown_op(self):
        self.assertFalse(self.broker.handle({"op": "rm -rf"}, 0)["ok"])

    def test_add_then_list(self):
        reply = self._add()
        self.assertTrue(reply["ok"])
        self.assertTrue(reply["handle"].startswith("vault_"))
        listing = self.broker.handle({"op": "list"}, 0)
        self.assertEqual(len(listing["items"]), 1)
        self.assertNotIn("pw", str(listing))

    def test_fill_calls_cdp_with_the_saved_secret_and_the_pinned_endpoint(self):
        handle = self._add("pw-value")["handle"]
        with mock.patch.object(daemon.cdp_module, "fill_login", return_value={"filled": 1, "submitted": True}) as filled:
            out = self.broker.handle(
                {"op": "fill", "handle": handle, "origin": "https://www.kaggle.com"}, 0
            )
        self.assertTrue(out["ok"])
        self.assertEqual(out["filled"], 1)
        self.assertEqual(filled.call_args.kwargs["password"], "pw-value")
        self.assertEqual(filled.call_args.kwargs["endpoint"], ENDPOINT)
        self.assertNotIn("cdp_url", filled.call_args.kwargs)
        self.assertNotIn("cdp", filled.call_args.kwargs)

    def test_request_supplying_cdp_is_refused_without_touching_the_browser(self):
        handle = self._add("pw-value")["handle"]
        with mock.patch.object(daemon.cdp_module, "fill_login") as filled:
            out = self.broker.handle(
                {
                    "op": "fill",
                    "handle": handle,
                    "origin": "https://www.kaggle.com",
                    "cdp": "http://127.0.0.1:6666",
                },
                0,
            )
        self.assertFalse(out["ok"])
        self.assertIn("not accepted", out["error"])
        filled.assert_not_called()

    def test_fill_without_a_configured_endpoint_is_refused(self):
        broker = daemon.Broker(self.store, allowed_uids=(0,), endpoint=None)
        handle = self._add("pw-value")["handle"]
        with mock.patch.object(daemon.cdp_module, "fill_login") as filled:
            out = broker.handle({"op": "fill", "handle": handle, "origin": "https://www.kaggle.com"}, 0)
        self.assertFalse(out["ok"])
        filled.assert_not_called()

    def test_fill_on_wrong_origin_never_reaches_the_browser(self):
        handle = self._add("pw-value")["handle"]
        with mock.patch.object(daemon.cdp_module, "fill_login") as filled:
            out = self.broker.handle(
                {"op": "fill", "handle": handle, "origin": "https://evil.example"}, 0
            )
        self.assertFalse(out["ok"])
        filled.assert_not_called()

    def test_fill_reports_broker_down(self):
        handle = self._add("pw-value")["handle"]
        with mock.patch.object(
            daemon.cdp_module, "fill_login", side_effect=daemon.cdp_module.CdpError("no open tab on https://www.kaggle.com")
        ):
            out = self.broker.handle(
                {"op": "fill", "handle": handle, "origin": "https://www.kaggle.com"}, 0
            )
        self.assertFalse(out["ok"])
        self.assertIn("no open tab", out["error"])

    def test_unlock_brake_after_repeated_failures(self):
        locked = Store(os.path.join(self.tmp.name, "other.json"))
        locked.create(PASS)
        locked.lock()
        broker = daemon.Broker(locked, allowed_uids=(0,), endpoint=ENDPOINT)
        for _ in range(daemon.UNLOCK_ATTEMPTS):
            self.assertFalse(broker.handle({"op": "unlock", "passphrase": "nope"}, 0)["ok"])
        blocked = broker.handle({"op": "unlock", "passphrase": PASS}, 0)
        self.assertFalse(blocked["ok"])
        self.assertIn("too many", blocked["error"])

    def test_lock_after_unlock(self):
        self.assertTrue(self.broker.handle({"op": "lock"}, 0)["ok"])
        self.assertFalse(self.broker.handle({"op": "status"}, 0)["unlocked"])


class PerOperationUidTest(unittest.TestCase):
    """The gateway uid may read and fill; it may not unlock or mutate."""

    GATEWAY_UID = 4242

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        store = Store(os.path.join(self.tmp.name, "store.json"))
        store.create(PASS)
        self.broker = daemon.Broker(
            store,
            allowed_uids=(0, self.GATEWAY_UID),
            admin_uids=(0,),
            endpoint=ENDPOINT,
        )

    def tearDown(self):
        self.tmp.cleanup()

    def test_gateway_uid_gets_status_and_list(self):
        self.assertTrue(self.broker.handle({"op": "status"}, self.GATEWAY_UID)["ok"])
        self.assertTrue(self.broker.handle({"op": "list"}, self.GATEWAY_UID)["ok"])

    def test_gateway_uid_can_fill(self):
        handle = self.broker.handle(
            {"op": "add", "label": "k", "origin": "https://www.kaggle.com", "identifier": "a@b.c", "password": "pw"},
            0,
        )["handle"]
        with mock.patch.object(daemon.cdp_module, "fill_login", return_value={"filled": 1, "submitted": False}):
            reply = self.broker.handle(
                {"op": "fill", "handle": handle, "origin": "https://www.kaggle.com"},
                self.GATEWAY_UID,
            )
        self.assertTrue(reply["ok"])

    def test_gateway_uid_cannot_unlock_lock_add_remove_or_init(self):
        for op in ("unlock", "lock", "add", "remove", "init"):
            with self.subTest(op=op):
                reply = self.broker.handle({"op": op, "passphrase": "x" * 12}, self.GATEWAY_UID)
                self.assertFalse(reply["ok"])
                self.assertEqual(reply["error"], "not permitted")

    def test_admin_uid_can_mutate(self):
        reply = self.broker.handle(
            {"op": "add", "label": "k", "origin": "https://www.kaggle.com", "identifier": "a@b.c", "password": "pw"},
            0,
        )
        self.assertTrue(reply["ok"])


class PipeDispatchTest(unittest.TestCase):
    """Pipe mode routes fills to the broker-owned browser, never to HTTP/WS."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        store = Store(os.path.join(self.tmp.name, "store.json"))
        store.create(PASS)
        self.broker = daemon.Broker(
            store,
            allowed_uids=(0,),
            pipe_config=PipeConfig("/bin/true", ("about:blank",)),
        )

    def tearDown(self):
        self.tmp.cleanup()

    def _handle(self):
        return self.broker.handle(
            {
                "op": "add",
                "label": "kaggle",
                "origin": "https://www.kaggle.com",
                "identifier_type": "email",
                "identifier": "me@example.com",
                "password": "pw-value",
            },
            0,
        )["handle"]

    def test_fill_goes_through_the_broker_owned_browser(self):
        handle = self._handle()
        browser = object()
        with mock.patch.object(self.broker, "_browser", return_value=browser), mock.patch.object(
            daemon.cdp_module, "fill_login_pipe", return_value={"filled": 1, "submitted": False}
        ) as fill:
            out = self.broker.handle(
                {"op": "fill", "handle": handle, "origin": "https://www.kaggle.com"}, 0
            )
        self.assertTrue(out["ok"])
        self.assertIs(fill.call_args.kwargs["transport"], browser)
        self.assertEqual(fill.call_args.kwargs["password"], "pw-value")

    def test_http_fill_is_not_used_in_pipe_mode(self):
        handle = self._handle()
        with mock.patch.object(self.broker, "_browser", return_value=object()), mock.patch.object(
            daemon.cdp_module, "fill_login_pipe", return_value={"filled": 1, "submitted": False}
        ), mock.patch.object(daemon.cdp_module, "fill_login") as http_fill:
            self.broker.handle(
                {"op": "fill", "handle": handle, "origin": "https://www.kaggle.com"}, 0
            )
        http_fill.assert_not_called()


if __name__ == "__main__":
    unittest.main()
