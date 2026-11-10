import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from broker import daemon  # noqa: E402
from broker.store import Store  # noqa: E402

PASS = "correct horse battery staple"


class BrokerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(os.path.join(self.tmp.name, "store.json"))
        self.store.create(PASS)
        self.broker = daemon.Broker(self.store, allowed_uids=(0,))

    def tearDown(self):
        self.tmp.cleanup()

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
        reply = self.broker.handle(
            {
                "op": "add",
                "label": "kaggle",
                "origin": "https://www.kaggle.com",
                "identifier_type": "email",
                "identifier": "me@example.com",
                "password": "pw",
            },
            0,
        )
        self.assertTrue(reply["ok"])
        self.assertTrue(reply["handle"].startswith("vault_"))
        listing = self.broker.handle({"op": "list"}, 0)
        self.assertEqual(len(listing["items"]), 1)
        self.assertNotIn("pw", str(listing))

    def test_fill_calls_cdp_with_the_saved_secret(self):
        reply = self.broker.handle(
            {
                "op": "add",
                "label": "kaggle",
                "origin": "https://www.kaggle.com",
                "identifier_type": "email",
                "identifier": "me@example.com",
                "password": "pw-value",
            },
            0,
        )
        handle = reply["handle"]
        with mock.patch.object(daemon.cdp_module, "fill_login", return_value={"filled": 1, "submitted": True}) as filled:
            out = self.broker.handle(
                {"op": "fill", "handle": handle, "origin": "https://www.kaggle.com"}, 0
            )
        self.assertTrue(out["ok"])
        self.assertEqual(out["filled"], 1)
        self.assertEqual(filled.call_args.kwargs["password"], "pw-value")

    def test_fill_on_wrong_origin_never_reaches_the_browser(self):
        reply = self.broker.handle(
            {
                "op": "add",
                "label": "kaggle",
                "origin": "https://www.kaggle.com",
                "identifier_type": "email",
                "identifier": "me@example.com",
                "password": "pw-value",
            },
            0,
        )
        with mock.patch.object(daemon.cdp_module, "fill_login") as filled:
            out = self.broker.handle(
                {"op": "fill", "handle": reply["handle"], "origin": "https://evil.example"}, 0
            )
        self.assertFalse(out["ok"])
        filled.assert_not_called()

    def test_fill_reports_broker_down(self):
        reply = self.broker.handle(
            {
                "op": "add",
                "label": "kaggle",
                "origin": "https://www.kaggle.com",
                "identifier_type": "email",
                "identifier": "me@example.com",
                "password": "pw-value",
            },
            0,
        )
        with mock.patch.object(
            daemon.cdp_module, "fill_login", side_effect=daemon.cdp_module.CdpError("no open tab on https://www.kaggle.com")
        ):
            out = self.broker.handle(
                {"op": "fill", "handle": reply["handle"], "origin": "https://www.kaggle.com"}, 0
            )
        self.assertFalse(out["ok"])
        self.assertIn("no open tab", out["error"])

    def test_unlock_brake_after_repeated_failures(self):
        locked = Store(os.path.join(self.tmp.name, "other.json"))
        locked.create(PASS)
        locked.lock()
        broker = daemon.Broker(locked, allowed_uids=(0,))
        for _ in range(daemon.UNLOCK_ATTEMPTS):
            self.assertFalse(broker.handle({"op": "unlock", "passphrase": "nope"}, 0)["ok"])
        blocked = broker.handle({"op": "unlock", "passphrase": PASS}, 0)
        self.assertFalse(blocked["ok"])
        self.assertIn("too many", blocked["error"])

    def test_lock_after_unlock(self):
        self.assertTrue(self.broker.handle({"op": "lock"}, 0)["ok"])
        self.assertFalse(self.broker.handle({"op": "status"}, 0)["unlocked"])


if __name__ == "__main__":
    unittest.main()
