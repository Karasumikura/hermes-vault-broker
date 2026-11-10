import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from broker import client, daemon  # noqa: E402
from broker.store import Store  # noqa: E402

PASS = "correct horse battery staple"


class SocketTest(unittest.TestCase):
    """Real AF_UNIX round trip, because the peer-credential path only exists there."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.socket_path = os.path.join(self.tmp.name, "sock")
        store = Store(os.path.join(self.tmp.name, "store.json"))
        store.create(PASS)
        self.server = daemon.Server(self.socket_path, daemon.Broker(store, allowed_uids=(0, os.getuid())))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.tmp.cleanup()

    def test_status_over_the_socket(self):
        reply = client.call({"op": "status"}, socket_path=self.socket_path)
        self.assertTrue(reply["ok"])
        self.assertTrue(reply["unlocked"])

    def test_add_and_list_over_the_socket(self):
        added = client.call(
            {
                "op": "add",
                "label": "kaggle",
                "origin": "https://www.kaggle.com",
                "identifier_type": "email",
                "identifier": "me@example.com",
                "password": "pw",
            },
            socket_path=self.socket_path,
        )
        self.assertTrue(added["ok"])
        listing = client.call({"op": "list"}, socket_path=self.socket_path)
        self.assertEqual(listing["items"][0]["handle"], added["handle"])
        self.assertNotIn("pw", str(listing))

    def test_malformed_request_does_not_kill_the_daemon(self):
        import socket as socket_module

        sock = socket_module.socket(socket_module.AF_UNIX, socket_module.SOCK_STREAM)
        sock.connect(self.socket_path)
        sock.sendall(b"not json\n")
        reply = sock.recv(4096)
        sock.close()
        self.assertIn(b"malformed", reply)
        self.assertTrue(client.call({"op": "status"}, socket_path=self.socket_path)["ok"])

    def test_missing_socket_is_reported(self):
        with self.assertRaises(client.BrokerUnavailable):
            client.call({"op": "status"}, socket_path=os.path.join(self.tmp.name, "nope"))


if __name__ == "__main__":
    unittest.main()
