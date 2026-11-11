"""CLI/plugin surface must not reintroduce a model-supplied endpoint or a
direct read of Hermes's credential stores."""

import json
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from broker.__main__ import build_parser  # noqa: E402
import plugin  # noqa: E402


class ParserTest(unittest.TestCase):
    def test_migrate_requires_an_explicit_export_file(self):
        with self.assertRaises(SystemExit):
            build_parser().parse_args(["migrate"])

    def test_migrate_has_no_vault_key_or_enc_options(self):
        for argv in (
            ["migrate", "--key", "vault.key", "--enc", "vault.json.enc"],
            ["migrate", "--json", "x.json", "--key", "vault.key"],
        ):
            with self.subTest(argv=argv), self.assertRaises(SystemExit):
                build_parser().parse_args(argv)

    def test_migrate_accepts_only_json(self):
        args = build_parser().parse_args(["migrate", "--json", "my-export.json"])
        self.assertEqual(args.json, "my-export.json")
        self.assertFalse(hasattr(args, "key"))
        self.assertFalse(hasattr(args, "enc"))

    def test_fill_has_no_cdp_option(self):
        args = build_parser().parse_args(["fill", "--handle", "vault_1", "--origin", "https://www.kaggle.com"])
        self.assertFalse(hasattr(args, "cdp"))
        with self.assertRaises(SystemExit):
            build_parser().parse_args(
                ["fill", "--handle", "vault_1", "--origin", "https://www.kaggle.com", "--cdp", "http://evil"]
            )

    def test_daemon_takes_the_broker_owned_config_path(self):
        args = build_parser().parse_args(["daemon", "--cdp-config", "/etc/hermes-vault-broker/cdp.json"])
        self.assertEqual(args.cdp_config, "/etc/hermes-vault-broker/cdp.json")

    def test_systemd_execstart_is_a_valid_cli_invocation(self):
        """Regression: --cdp-config belongs AFTER the `daemon` subcommand.
        Getting this wrong makes the service exit 2 in a restart loop."""
        import shlex

        unit = Path(__file__).resolve().parents[1] / "systemd" / "hermes-vault-broker.service"
        parts = []
        collecting = False
        for line in unit.read_text(encoding="utf-8").splitlines():
            if line.startswith("ExecStart="):
                collecting = True
                parts.append(line[len("ExecStart="):])
            elif collecting:
                parts.append(line)
                if not line.rstrip().endswith("\\"):
                    break
        self.assertTrue(parts)
        command = " ".join(p.rstrip("\\").strip() for p in parts)
        argv = shlex.split(command.replace("${BROKER_ALLOW_UID}", "1000"))
        args = build_parser().parse_args(argv[argv.index("-m") + 2:])
        self.assertEqual(args.command, "daemon")
        self.assertEqual(args.cdp_config, "/etc/hermes-vault-broker/cdp.json")
        self.assertEqual(args.allow_uid, [1000])


class PluginSurfaceTest(unittest.TestCase):
    def test_fill_schema_has_no_cdp_and_rejects_extra_properties(self):
        self.assertNotIn("cdp", plugin._FILL_SCHEMA["properties"])
        self.assertTrue(plugin._FILL_SCHEMA["additionalProperties"] is False)

    def test_fill_request_never_contains_a_cdp_url(self):
        with mock.patch.object(plugin, "_call", return_value={"ok": True, "filled": 1}) as call:
            plugin._fill(
                {
                    "handle": "vault_1",
                    "origin": "https://www.kaggle.com",
                    "cdp": "http://attacker.example:9223",  # injected attempt
                    "submit": True,
                }
            )
        sent = call.call_args.args[0]
        self.assertNotIn("cdp", sent)
        self.assertEqual(sent["op"], "fill")
        self.assertEqual(sent["submit"], True)
        self.assertNotIn("attacker.example", json.dumps(sent))


if __name__ == "__main__":
    unittest.main()
