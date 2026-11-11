"""Encrypted credential store for the vault broker.

Two layers of AES-256-GCM:

    KEK   = scrypt(passphrase, salt)     derived at unlock time, never stored
    DEK   = 32 random bytes              wrapped with the KEK, stored wrapped
    body  = items JSON                   encrypted with the DEK

The file on disk holds the salt, both nonces, the wrapped DEK and the
ciphertext. Without the passphrase it decrypts to nothing, which is the whole
point: a copy of the file is not a copy of the credentials.
"""

from __future__ import annotations

import base64
import ctypes
import hashlib
import json
import os
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

MAGIC = "HVLT1"
KDF_N = 2 ** 15
KDF_R = 8
KDF_P = 1
KEY_LEN = 32
DEFAULT_PORTS = {"http": 80, "https": 443}
# The store file is writable by the service user, so its KDF parameters are
# untrusted input. Cap the scrypt cost to keep a tampered file from OOMing the
# daemon or silently downgrading the KDF.
MAX_KDF_N = 2 ** 16
MAX_KDF_R = 8
MAX_KDF_P = 4

# mlock is a libc call, not a Python API. Resolve it once; a platform without it
# is a hard failure rather than a silently unfulfilled security claim.
try:
    _LIBC = ctypes.CDLL(None, use_errno=True)
    _MLOCK = _LIBC.mlock
    _MLOCK.argtypes = (ctypes.c_void_p, ctypes.c_size_t)
    _MLOCK.restype = ctypes.c_int
    _MUNLOCK = _LIBC.munlock
    _MUNLOCK.argtypes = (ctypes.c_void_p, ctypes.c_size_t)
    _MUNLOCK.restype = ctypes.c_int
except (AttributeError, OSError):  # pragma: no cover - non-Linux
    _MLOCK = None
    _MUNLOCK = None


class _LockedKey:
    """The DEK, held in an mlock'd bytearray that is zeroed before release.

    ``mlock`` failure is fatal: continuing unlocked would keep the key eligible
    for swap and make the mlock claim a lie. ``LimitMEMLOCK=infinity`` in the
    systemd unit gives the service the headroom it needs.
    """

    def __init__(self, raw: bytes | bytearray):
        self._buf: bytearray | None = bytearray(raw)
        self._len = len(self._buf)
        self._addr = ctypes.addressof(ctypes.c_char.from_buffer(self._buf))
        self._locked = False
        if _MLOCK is None:
            raise VaultError("mlock is unavailable on this platform")
        if _MLOCK(ctypes.c_void_p(self._addr), ctypes.c_size_t(self._len)) != 0:
            errno = ctypes.get_errno()
            raise VaultError("could not lock the data key in memory (mlock errno %d)" % errno)
        self._locked = True
        self.locked = True

    @property
    def buffer(self) -> bytearray:
        assert self._buf is not None
        return self._buf

    def wipe(self) -> None:
        if self._buf is None:
            return
        ctypes.memset(ctypes.c_void_p(self._addr), 0, self._len)
        if self._locked and _MUNLOCK is not None:
            _MUNLOCK(ctypes.c_void_p(self._addr), ctypes.c_size_t(self._len))
        self._locked = False
        self.locked = False
        self._buf = None

    def __del__(self):  # pragma: no cover - interpreter shutdown
        try:
            self.wipe()
        except Exception:
            pass


def _wipe(buf: bytearray) -> None:
    """Zero a temporary key buffer that is not the long-lived DEK."""
    if buf:
        ctypes.memset(
            ctypes.c_void_p(ctypes.addressof(ctypes.c_char.from_buffer(buf))),
            0,
            len(buf),
        )


class VaultError(Exception):
    """Failure safe to surface: it never embeds a secret value."""


class LockedError(VaultError):
    """The store is locked; unlock it with the passphrase first."""


def normalize_origin(value: str) -> str:
    """``scheme://host[:port]`` with default ports stripped. Raises VaultError otherwise."""
    raw = (value or "").strip()
    if "://" not in raw:
        raise VaultError("origin must include a scheme, e.g. https://www.example.com")
    parts = urlsplit(raw)
    scheme = (parts.scheme or "").lower()
    host = (parts.hostname or "").lower()
    if not scheme or not host:
        raise VaultError("could not parse an origin from %r" % value)
    if scheme not in DEFAULT_PORTS:
        raise VaultError("origin must use http or https")
    if parts.username or parts.password:
        raise VaultError("origin must not contain credentials")
    try:
        port = parts.port
    except ValueError as exc:
        raise VaultError("invalid port in origin %r" % value) from exc
    if port is None or port == DEFAULT_PORTS.get(scheme):
        return "%s://%s" % (scheme, host)
    return "%s://%s:%d" % (scheme, host, port)


@dataclass(frozen=True)
class ItemMeta:
    """Metadata only. The password never appears in this object."""

    id: str
    label: str
    origin: str
    identifier_type: str
    identifier: str
    created_at: str

    def to_dict(self) -> dict:
        return {
            "handle": self.id,
            "label": self.label,
            "origin": self.origin,
            "identifier_type": self.identifier_type,
            "identifier": self.identifier,
            "created_at": self.created_at,
        }


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


class Store:
    """Passphrase-locked credential store.

    Every method is safe to call from multiple threads: the daemon serves one
    request per connection but connections overlap.
    """

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._lock = threading.RLock()
        self._dek: _LockedKey | None = None

    # -- state ------------------------------------------------------------
    @property
    def initialized(self) -> bool:
        return self.path.exists()

    @property
    def unlocked(self) -> bool:
        return self._dek is not None

    def _require_unlocked(self) -> bytearray:
        """Return the mlock'd key buffer itself — never a ``bytes`` copy."""
        if self._dek is None:
            raise LockedError("vault is locked; unlock it with the passphrase first")
        return self._dek.buffer

    def lock(self) -> None:
        with self._lock:
            if self._dek is not None:
                self._dek.wipe()
            self._dek = None

    # -- crypto -----------------------------------------------------------
    @staticmethod
    def _kek(passphrase: str, salt: bytes, n: int = KDF_N, r: int = KDF_R, p: int = KDF_P) -> bytearray:
        # OpenSSL's default scrypt memory ceiling is 32 MiB, which is exactly
        # what n=2**15 / r=8 needs; ask for headroom explicitly. The caller wipes
        # this buffer as soon as the DEK has been wrapped/unwrapped.
        if not (1 <= n <= MAX_KDF_N and 1 <= r <= MAX_KDF_R and 1 <= p <= MAX_KDF_P):
            raise VaultError("KDF parameters out of range")
        return bytearray(hashlib.scrypt(
            passphrase.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=KEY_LEN,
            maxmem=128 * r * n + 16 * 1024 * 1024,
        ))

    def _read_file(self) -> dict:
        if not self.path.exists():
            raise VaultError("store is not initialized")
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise VaultError("store file is unreadable") from exc

    def _write_file(self, doc: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(doc), encoding="utf-8")
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.path)

    def create(self, passphrase: str) -> None:
        """Initialise an empty store. Refuses to overwrite an existing one."""
        if not passphrase or len(passphrase) < 8:
            raise VaultError("passphrase must be at least 8 characters")
        with self._lock:
            if self.path.exists():
                raise VaultError("store already exists")
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM

            dek = bytearray(os.urandom(KEY_LEN))
            salt = os.urandom(16)
            kek = self._kek(passphrase, salt)
            try:
                wrap_nonce = os.urandom(12)
                wrapped = AESGCM(kek).encrypt(wrap_nonce, dek, b"hermes-vault-dek-v1")
                body_nonce = os.urandom(12)
                body = AESGCM(dek).encrypt(body_nonce, b'{"items": []}', b"hermes-vault-body-v1")
                self._write_file(
                    {
                        "magic": MAGIC,
                        "kdf": {"n": KDF_N, "r": KDF_R, "p": KDF_P},
                        "salt": _b64(salt),
                        "wrap_nonce": _b64(wrap_nonce),
                        "wrapped_dek": _b64(wrapped),
                        "body_nonce": _b64(body_nonce),
                        "body": _b64(body),
                    }
                )
                self._dek = _LockedKey(dek)
            finally:
                _wipe(kek)
                _wipe(dek)

    def unlock(self, passphrase: str) -> None:
        from cryptography.exceptions import InvalidTag
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        with self._lock:
            doc = self._read_file()
            if doc.get("magic") != MAGIC:
                raise VaultError("not a vault broker store")
            try:
                params = doc.get("kdf") or {}
                kek = self._kek(
                    passphrase,
                    _unb64(doc["salt"]),
                    n=int(params.get("n", KDF_N)),
                    r=int(params.get("r", KDF_R)),
                    p=int(params.get("p", KDF_P)),
                )
                try:
                    dek_plain = AESGCM(kek).decrypt(
                        _unb64(doc["wrap_nonce"]), _unb64(doc["wrapped_dek"]), b"hermes-vault-dek-v1"
                    )
                finally:
                    _wipe(kek)
            except (InvalidTag, KeyError, ValueError) as exc:
                raise VaultError("wrong passphrase") from exc
            # A failed mlock is a hard error of its own, not a wrong passphrase.
            self._dek = _LockedKey(dek_plain)

    # -- items ------------------------------------------------------------
    def _load_items(self) -> list[dict]:
        from cryptography.exceptions import InvalidTag
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        dek = self._require_unlocked()
        doc = self._read_file()
        try:
            plain = AESGCM(dek).decrypt(
                _unb64(doc["body_nonce"]), _unb64(doc["body"]), b"hermes-vault-body-v1"
            )
        except (InvalidTag, KeyError, ValueError) as exc:
            raise VaultError("store body could not be decrypted") from exc
        return json.loads(plain.decode("utf-8")).get("items", [])

    def _save_items(self, items: list[dict]) -> None:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        dek = self._require_unlocked()
        doc = self._read_file()
        body_nonce = os.urandom(12)
        body = AESGCM(dek).encrypt(
            body_nonce, json.dumps({"items": items}).encode("utf-8"), b"hermes-vault-body-v1"
        )
        doc["body_nonce"] = _b64(body_nonce)
        doc["body"] = _b64(body)
        self._write_file(doc)

    def list_items(self) -> list[ItemMeta]:
        with self._lock:
            return [self._meta(it) for it in self._load_items()]

    @staticmethod
    def _meta(item: dict) -> ItemMeta:
        return ItemMeta(
            id=item["id"],
            label=item.get("label", ""),
            origin=item.get("origin", ""),
            identifier_type=item.get("identifier_type", ""),
            identifier=item.get("identifier", ""),
            created_at=item.get("created_at", ""),
        )

    def add(
        self,
        label: str,
        origin: str,
        identifier_type: str,
        identifier: str,
        password: str,
    ) -> ItemMeta:
        if not password:
            raise VaultError("password is required")
        if identifier_type not in ("email", "username", "phone"):
            raise VaultError("identifier_type must be email, username or phone")
        norm = normalize_origin(origin)
        with self._lock:
            items = self._load_items()
            item = {
                "id": "vault_%s" % uuid.uuid4().hex[:12],
                "label": (label or "").strip(),
                "origin": norm,
                "identifier_type": identifier_type,
                "identifier": identifier.strip(),
                "created_at": datetime.now(timezone.utc).isoformat(),
                "secret": {"password": password},
            }
            items.append(item)
            self._save_items(items)
            return self._meta(item)

    def remove(self, handle: str) -> bool:
        with self._lock:
            items = self._load_items()
            keep = [it for it in items if it["id"] != handle]
            if len(keep) == len(items):
                return False
            self._save_items(keep)
            return True

    def resolve(self, handle: str, origin: str) -> tuple[ItemMeta, str]:
        """Return the item and its password, but only for the exact origin it was saved for."""
        want = normalize_origin(origin)
        with self._lock:
            for item in self._load_items():
                if item["id"] != handle:
                    continue
                if item.get("origin") != want:
                    raise VaultError(
                        "refused: %s was saved for %s" % (handle, item.get("origin"))
                    )
                return self._meta(item), item["secret"]["password"]
        raise VaultError("no vault item with handle %r" % handle)
