import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from broker.store import LockedError, Store, VaultError, normalize_origin  # noqa: E402

PASS = "correct horse battery staple"


class StoreTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "store.json")
        self.store = Store(self.path)
        self.store.create(PASS)

    def tearDown(self):
        self.tmp.cleanup()

    def test_create_leaves_no_plaintext_on_disk(self):
        raw = Path(self.path).read_bytes()
        self.assertNotIn(PASS.encode(), raw)
        self.assertNotIn(b"kaggle", raw)

    def test_round_trip(self):
        meta = self.store.add("kaggle", "https://www.kaggle.com", "email", "me@example.com", "s3cret-value")
        items = self.store.list_items()
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].id, meta.id)
        found, password = self.store.resolve(meta.id, "https://www.kaggle.com/account/login")
        self.assertEqual(password, "s3cret-value")
        self.assertEqual(found.origin, "https://www.kaggle.com")

    def test_password_is_not_in_meta(self):
        meta = self.store.add("kaggle", "https://www.kaggle.com", "email", "me@example.com", "s3cret-value")
        self.assertNotIn("s3cret-value", repr(meta.to_dict()))

    def test_wrong_passphrase(self):
        other = Store(self.path)
        with self.assertRaises(VaultError):
            other.unlock("not the passphrase")

    def test_lock_clears_access(self):
        self.store.add("kaggle", "https://www.kaggle.com", "email", "me@example.com", "pw")
        self.store.lock()
        self.assertFalse(self.store.unlocked)
        with self.assertRaises(LockedError):
            self.store.list_items()

    def test_origin_mismatch_refuses(self):
        meta = self.store.add("kaggle", "https://www.kaggle.com", "email", "me@example.com", "pw")
        with self.assertRaises(VaultError) as caught:
            self.store.resolve(meta.id, "https://www.google.com")
        self.assertIn("refused", str(caught.exception))

    def test_default_port_is_normalized(self):
        meta = self.store.add("x", "https://Example.COM:443", "email", "me@example.com", "pw")
        self.store.resolve(meta.id, "https://example.com")

    def test_remove(self):
        meta = self.store.add("kaggle", "https://www.kaggle.com", "email", "me@example.com", "pw")
        self.assertTrue(self.store.remove(meta.id))
        self.assertFalse(self.store.remove(meta.id))
        self.assertEqual(self.store.list_items(), [])

    def test_reopen_after_unlock(self):
        meta = self.store.add("kaggle", "https://www.kaggle.com", "email", "me@example.com", "pw")
        fresh = Store(self.path)
        fresh.unlock(PASS)
        self.assertEqual(fresh.list_items()[0].id, meta.id)

    def test_empty_passphrase_rejected(self):
        with self.assertRaises(VaultError):
            Store(os.path.join(self.tmp.name, "x.json")).create("short")

    def test_dek_is_mlocked_and_wiped_on_lock(self):
        key = self.store._dek
        assert key is not None
        self.assertTrue(key.locked)
        buf = self.store._require_unlocked()
        self.assertIsInstance(buf, bytearray)
        self.assertIs(buf, key.buffer)  # no unlocked bytes copy on every op
        self.store.lock()
        self.assertFalse(key.locked)
        self.assertIsNone(self.store._dek)

    def test_unlock_mlocks_the_key_too(self):
        fresh = Store(self.path)
        fresh.unlock(PASS)
        key = fresh._dek
        assert key is not None
        self.assertTrue(key.locked)
        fresh.lock()

    def test_mlock_failure_is_fatal_not_a_silent_downgrade(self):
        from broker import store as store_module

        with mock.patch.object(store_module, "_MLOCK", return_value=-1):
            with self.assertRaises(VaultError) as caught:
                Store(os.path.join(self.tmp.name, "blocked.json")).create(PASS)
        self.assertIn("lock the data key", str(caught.exception))

    def test_aesgcm_accepts_a_bytearray_key(self):
        """The pinned dependency range must keep this behaviour: we pass the
        mlock'd bytearray straight to AESGCM instead of copying it to bytes."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        key = bytearray(b"0" * 32)
        nonce = b"0" * 12
        blob = AESGCM(key).encrypt(nonce, b"payload", b"aad")
        self.assertEqual(AESGCM(key).decrypt(nonce, blob, b"aad"), b"payload")

    def test_tampered_kdf_parameters_are_refused(self):
        doc = json.loads(Path(self.path).read_text(encoding="utf-8"))
        doc["kdf"]["n"] = 2 ** 30
        Path(self.path).write_text(json.dumps(doc), encoding="utf-8")
        with self.assertRaises(VaultError) as caught:
            Store(self.path).unlock(PASS)
        self.assertIn("KDF parameters", str(caught.exception))


class OriginTest(unittest.TestCase):
    def test_forms(self):
        self.assertEqual(normalize_origin("https://www.kaggle.com/login?a=1"), "https://www.kaggle.com")
        self.assertEqual(normalize_origin("https://example.com:443"), "https://example.com")
        self.assertEqual(normalize_origin("http://example.com:8080/x"), "http://example.com:8080")

    def test_rejects_garbage(self):
        for value in ("", "kaggle.com", "https://", "ftp://example.com", "https://user:pw@example.com"):
            with self.assertRaises(VaultError):
                normalize_origin(value)


if __name__ == "__main__":
    unittest.main()
