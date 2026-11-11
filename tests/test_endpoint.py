"""The DevTools endpoint is broker-owned: root-owned config, loopback only."""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from broker import endpoint as ep  # noqa: E402


class BaseValidationTest(unittest.TestCase):
    def test_accepts_ipv4_loopback_with_explicit_port(self):
        self.assertEqual(
            ep.validate_base("http://127.0.0.1:9223"),
            ep.Endpoint(base="http://127.0.0.1:9223", host="127.0.0.1", port=9223),
        )
        self.assertEqual(ep.validate_base("http://localhost:9223/").host, "127.0.0.1")
        self.assertEqual(ep.validate_base("http://127.0.0.2:9223").host, "127.0.0.2")

    def test_rejects_anything_not_loopback_http_with_a_port(self):
        bad = [
            "http://example.com:9223",
            "http://169.254.169.254:9223",
            "https://127.0.0.1:9223",
            "http://127.0.0.1",
            "http://127.0.0.1:9223/json/list",
            "http://127.0.0.1:9223?x=1",
            "http://user:pw@127.0.0.1:9223",
            "http://[::1]:9223",
            "file:///etc/passwd",
            "",
        ]
        for url in bad:
            with self.subTest(url=url), self.assertRaises(ep.EndpointError):
                ep.validate_base(url)

    def test_list_url_is_derived_from_the_validated_base(self):
        self.assertEqual(
            ep.validate_base("http://localhost:9223/").list_url,
            "http://127.0.0.1:9223/json/list",
        )


class WebSocketValidationTest(unittest.TestCase):
    def setUp(self):
        self.endpoint = ep.validate_base("http://127.0.0.1:9223")

    def test_accepts_matching_host_and_port(self):
        # The URL is rebuilt from the validated IP literal, so "check A,
        # connect B" (a localhost spelling resolving elsewhere) is impossible.
        self.assertEqual(
            ep.validate_ws_url("ws://127.0.0.1:9223/devtools/page/ABC", self.endpoint),
            "ws://127.0.0.1:9223/devtools/page/ABC",
        )
        self.assertEqual(
            ep.validate_ws_url("ws://localhost:9223/devtools/page/ABC", self.endpoint),
            "ws://127.0.0.1:9223/devtools/page/ABC",
        )

    def test_refuses_a_websocket_on_any_other_host_or_port(self):
        bad = [
            "ws://evil.example:9223/devtools/page/X",
            "ws://127.0.0.1:9224/devtools/page/X",
            "ws://127.0.0.2:9223/devtools/page/X",
            "wss://127.0.0.1:9223/devtools/page/X",
            "ws://user:pw@127.0.0.1:9223/devtools/page/X",
            "ws://127.0.0.1:9223/page?x=1",
            "ws://127.0.0.1/devtools/page/X",
            "",
        ]
        for url in bad:
            with self.subTest(url=url), self.assertRaises(ep.EndpointError):
                ep.validate_ws_url(url, self.endpoint)


class ConfigFileTest(unittest.TestCase):
    def test_load_config_reads_a_valid_endpoint(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "cdp.json"
            path.write_text(json.dumps({"cdp": "http://127.0.0.1:9223"}), encoding="utf-8")
            with mock.patch.object(ep, "_check_parent", return_value=None), mock.patch.object(ep, "_check_stat", return_value=None):
                loaded = ep.load_config(str(path))
            self.assertEqual(loaded.port, 9223)

    def test_load_config_rejects_bad_documents(self):
        documents = [
            {"cdp": "http://example.com:9223"},
            {"cdp": 9223},
            {},
            ["http://127.0.0.1:9223"],
            {"cdp": "not a url"},
        ]
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "cdp.json"
            for doc in documents:
                with self.subTest(doc=doc):
                    path.write_text(json.dumps(doc), encoding="utf-8")
                    with mock.patch.object(ep, "_check_parent", return_value=None), mock.patch.object(ep, "_check_stat", return_value=None):
                        with self.assertRaises(ep.EndpointError):
                            ep.load_config(str(path))
            path.write_text("not json", encoding="utf-8")
            with mock.patch.object(ep, "_check_parent", return_value=None), mock.patch.object(ep, "_check_stat", return_value=None):
                with self.assertRaises(ep.EndpointError):
                    ep.load_config(str(path))

    def test_symlink_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            real = Path(d) / "real.json"
            real.write_text("{}", encoding="utf-8")
            link = Path(d) / "link.json"
            link.symlink_to(real)
            with self.assertRaises(ep.EndpointError) as caught:
                ep._check_config_file(link)
            self.assertIn("symlink", str(caught.exception))

    def test_group_or_world_writable_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "cdp.json"
            path.write_text("{}", encoding="utf-8")
            path.chmod(0o666)
            with self.assertRaises(ep.EndpointError) as caught:
                ep._check_config_file(path)
            self.assertIn("writable", str(caught.exception))

    @unittest.skipUnless(os.geteuid() == 0, "needs root to create a root-owned file")
    def test_root_owned_readonly_config_is_accepted_and_non_root_owner_refused(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "cdp.json"
            path.write_text("{}", encoding="utf-8")
            path.chmod(0o640)
            os.chown(path, 0, 0)
            ep._check_config_file(path)  # must not raise
            os.chown(path, 65534, 65534)
            with self.assertRaises(ep.EndpointError) as caught:
                ep._check_config_file(path)
            self.assertIn("owned by root", str(caught.exception))

    def test_load_config_does_not_follow_a_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            real = Path(d) / "real.json"
            real.write_text(json.dumps({"cdp": "http://127.0.0.1:9223"}), encoding="utf-8")
            link = Path(d) / "link.json"
            link.symlink_to(real)
            with mock.patch.object(ep, "_check_parent", return_value=None):
                with self.assertRaises(ep.EndpointError):
                    ep.load_config(str(link))

    def test_parent_directory_writable_by_group_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "cdp.json"
            path.write_text("{}", encoding="utf-8")
            os.chmod(d, 0o770)
            with self.assertRaises(ep.EndpointError):
                ep._check_parent(path)

    def test_missing_config_is_refused(self):
        with self.assertRaises(ep.EndpointError):
            ep._check_config_file(Path("/definitely/not/here/cdp.json"))


if __name__ == "__main__":
    unittest.main()
