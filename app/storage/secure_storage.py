"""Encrypted-at-rest private key storage.

Design
======
Private keys are **never** written in plaintext. Each identity has a JSON
keystore file (stored under ``data/keys/``, outside any web-served folder)
containing non-secret metadata plus an AES-256-GCM ciphertext blob of the
private keys.

    passphrase --Argon2id(salt)--> 32-byte storage key --AES-256-GCM--> blob

* the passphrase itself is never stored anywhere;
* the salt and Argon2 parameters are stored (they are not secret) and are
  read back from the file on unlock, so changing the defaults in ``config.py``
  never locks anyone out of an existing keystore (values are bounds-checked);
* format 2 authenticates the whole metadata block (email, public keys, KDF
  parameters, ...) as AES-GCM associated data, so editing the file in any way
  makes unlock fail;
* files are written atomically (temp file + ``os.replace``) so a crash can
  never leave a half-written keystore;
* an optional OS keyring backend holds a random "vault" key that wraps a
  *second* copy of the private keys. The passphrase-wrapped copy is always
  kept, so enrolling never removes the ability to unlock with the passphrase.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from typing import Any

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app import config as cfg
from app.log import event

KEYRING_SERVICE = "PQMail"
FORMAT_VERSION = 3   # 1 (legacy): no AAD on the blob; 2: metadata bound as AAD; 3: + X25519 key


class KeyStoreError(Exception):
    """Generic keystore failure (bad file, wrong passphrase, IO problem)."""


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _unb64(data: str) -> bytes:
    try:
        return base64.b64decode(data, validate=True)
    except Exception as exc:  # noqa: BLE001
        raise KeyStoreError("Keystore contains invalid base64 data.") from exc


def _canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _atomic_write(path: Path, text: str) -> None:
    """Write ``text`` to ``path`` so readers see either the old or new file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    try:
        tmp.chmod(0o600)
    except OSError:  # pragma: no cover - Windows handles ACLs differently
        pass
    os.replace(tmp, path)


def derive_storage_key(passphrase: str, salt: bytes, params: dict[str, Any] | None = None) -> bytes:
    """Derive the 32-byte keystore encryption key (Argon2id, RFC 9106).

    ``params`` come from the keystore metadata; the live defaults in
    ``config.py`` are used only when creating a new keystore.
    """
    if not passphrase:
        raise KeyStoreError("Empty passphrase.")
    params = params or {}
    try:
        time_cost = int(params.get("time_cost", cfg.ARGON2_TIME_COST))
        memory_cost = int(params.get("memory_cost", cfg.ARGON2_MEMORY_COST))
        parallelism = int(params.get("parallelism", cfg.ARGON2_PARALLELISM))
        hash_len = int(params.get("hash_len", cfg.ARGON2_HASH_LEN))
    except (TypeError, ValueError) as exc:
        raise KeyStoreError("Keystore has invalid Argon2 parameters.") from exc
    if not (1 <= time_cost <= cfg.ARGON2_MAX_TIME_COST
            and 8 <= memory_cost <= cfg.ARGON2_MAX_MEMORY_COST
            and 1 <= parallelism <= cfg.ARGON2_MAX_PARALLELISM
            and hash_len == 32):
        raise KeyStoreError("Keystore has out-of-range Argon2 parameters.")
    return hash_secret_raw(
        secret=passphrase.encode("utf-8"),
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=hash_len,
        type=Type.ID,
    )


def keyring_available() -> bool:
    """True when an OS keyring backend is usable on this machine."""
    try:
        import keyring  # noqa: PLC0415

        backend = keyring.get_keyring()
        name = getattr(backend, "priority", 1)
        return name is not None and "fail" not in type(backend).__name__.lower()
    except Exception:  # noqa: BLE001
        return False


def _keyring_set(filename: str, key: bytes) -> bool:
    try:
        import keyring  # noqa: PLC0415

        keyring.set_password(KEYRING_SERVICE, filename, _b64(key))
        return True
    except Exception:  # noqa: BLE001
        return False


def _keyring_get(filename: str) -> bytes | None:
    try:
        import keyring  # noqa: PLC0415

        secret = keyring.get_password(KEYRING_SERVICE, filename)
        return _unb64(secret) if secret else None
    except Exception:  # noqa: BLE001
        return None


def _keyring_delete(filename: str) -> None:
    try:
        import keyring  # noqa: PLC0415

        keyring.delete_password(KEYRING_SERVICE, filename)
    except Exception:  # noqa: BLE001
        pass


def _opt_b64(raw: bytes | None) -> str:
    return _b64(raw) if raw else ""


def _opt_unb64(text: str | None) -> bytes | None:
    return _unb64(text) if text else None


def _encode_bundle(bundle: dict[str, Any]) -> bytes:
    """Serialise the private bundle (bytes -> base64) to JSON bytes."""
    out: dict[str, Any] = {
        "kem_private_der": _b64(bundle["kem_private_der"]),
        "dsa_private_der": _b64(bundle["dsa_private_der"]),
    }
    if bundle.get("x25519_private"):
        out["x25519_private"] = _b64(bundle["x25519_private"])
    previous = []
    for old in bundle.get("previous", []):
        entry = {
            "kem_private_der": _b64(old["kem_private_der"]),
            "dsa_private_der": _b64(old["dsa_private_der"]),
            "kem_public_key_b64": old.get("kem_public_key_b64", ""),
            "signature_public_key_b64": old.get("signature_public_key_b64", ""),
            "retired_at": old.get("retired_at", ""),
        }
        if old.get("x25519_private"):
            entry["x25519_private"] = _b64(old["x25519_private"])
            entry["x25519_public_key_b64"] = old.get("x25519_public_key_b64", "")
        previous.append(entry)
    if previous:
        out["previous"] = previous
    totp = bundle.get("totp")
    if totp:
        out["totp"] = {"secret": _b64(totp["secret"]),
                       "recovery_hashes": list(totp.get("recovery_hashes", []))}
    return json.dumps(out).encode("utf-8")


def _decode_bundle(plain: bytes) -> dict[str, Any]:
    try:
        raw = json.loads(plain)
        bundle: dict[str, Any] = {
            "kem_private_der": _unb64(raw["kem_private_der"]),
            "dsa_private_der": _unb64(raw["dsa_private_der"]),
            "x25519_private": _opt_unb64(raw.get("x25519_private")),
            "previous": [],
            "totp": None,
        }
        for old in raw.get("previous", []):
            bundle["previous"].append({
                "kem_private_der": _unb64(old["kem_private_der"]),
                "dsa_private_der": _unb64(old["dsa_private_der"]),
                "x25519_private": _opt_unb64(old.get("x25519_private")),
                "x25519_public_key_b64": old.get("x25519_public_key_b64", ""),
                "kem_public_key_b64": old.get("kem_public_key_b64", ""),
                "signature_public_key_b64": old.get("signature_public_key_b64", ""),
                "retired_at": old.get("retired_at", ""),
            })
        if isinstance(raw.get("totp"), dict):
            bundle["totp"] = {
                "secret": _unb64(raw["totp"]["secret"]),
                "recovery_hashes": [str(h) for h in raw["totp"].get("recovery_hashes", [])],
            }
        return bundle
    except KeyStoreError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise KeyStoreError("Keystore payload is corrupt.") from exc


class KeyStore:
    """One encrypted keystore file for one identity."""

    @staticmethod
    def validate_passphrase(passphrase: str) -> None:
        """Enforce the minimum passphrase policy (no composition rules)."""
        if not isinstance(passphrase, str) or len(passphrase) < cfg.MIN_PASSPHRASE_LEN:
            raise KeyStoreError(
                f"Passphrase must be at least {cfg.MIN_PASSPHRASE_LEN} characters long."
            )
        if len(passphrase) > cfg.MAX_PASSPHRASE_LEN:
            raise KeyStoreError("Passphrase is too long.")

    def __init__(self, path: Path, metadata: dict[str, Any], blob: bytes, nonce: bytes,
                 keyring_wrap: dict[str, bytes] | None = None):
        self.path = path
        self.metadata = metadata
        self._blob = blob
        self._nonce = nonce
        self._keyring_wrap = keyring_wrap

    # -- paths -------------------------------------------------------------
    @staticmethod
    def filename_for(email: str) -> str:
        # The address becomes part of a filename: reject anything that is not a
        # plain address (path separators, "..", control characters, ...).
        if not cfg.is_valid_email(email) or email != cfg.normalize_email(email):
            raise KeyStoreError("Invalid email address for a keystore.")
        return f"{email.replace('@', '_at_')}.keystore.json"

    @staticmethod
    def store_path_for(directory: Path, email: str, active: bool = True) -> Path:
        directory = Path(directory)
        path = directory / KeyStore.filename_for(email)
        if path.resolve().parent != directory.resolve():
            raise KeyStoreError("Keystore path escapes the key directory.")
        return path

    # -- helpers -------------------------------------------------------------
    @property
    def format_version(self) -> int:
        return int(self.metadata.get("format", 1))

    @property
    def keyring_enrolled(self) -> bool:
        return self._keyring_wrap is not None

    def _aad(self) -> bytes | None:
        return _canonical(self.metadata) if self.format_version >= 2 else None

    def _kdf_params(self) -> dict[str, Any]:
        return self.metadata.get("kdf", {})

    def _salt(self) -> bytes:
        try:
            return _unb64(self.metadata["kdf"]["salt_b64"])
        except KeyError as exc:
            raise KeyStoreError("Keystore metadata is incomplete.") from exc

    def _save(self) -> None:
        payload: dict[str, Any] = {
            "metadata": self.metadata,
            "nonce_b64": _b64(self._nonce),
            "blob_b64": _b64(self._blob),
        }
        if self._keyring_wrap is not None:
            payload["keyring"] = {
                "nonce_b64": _b64(self._keyring_wrap["nonce"]),
                "blob_b64": _b64(self._keyring_wrap["blob"]),
            }
        _atomic_write(self.path, json.dumps(payload, indent=2))

    # -- creation / loading --------------------------------------------------
    @classmethod
    def create(cls, *, directory: Path, email: str, salt: bytes,
               kem_private_der: bytes, kem_public_der: bytes,
               dsa_private_der: bytes, dsa_public_der: bytes,
               created_at: str, passphrase: str,
               previous: list[dict[str, Any]] | None = None,
               path: Path | None = None,
               x25519_private_raw: bytes | None = None,
               x25519_public_raw: bytes | None = None,
               totp: dict[str, Any] | None = None) -> "KeyStore":
        """Build and write a new keystore.

        ``path`` overrides the destination (used by key rotation to stage the
        new keystore next to the active one before swapping it in).
        """
        cls.validate_passphrase(passphrase)
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        target = path or cls.store_path_for(directory, email)
        metadata = {
            "format": FORMAT_VERSION,
            "version": cfg.KEYSTORE_BUNDLE_VERSION,
            "email": email,
            "created_at": created_at,
            "kdf": {
                "algorithm": cfg.STORAGE_KDF_ALGORITHM,
                "time_cost": cfg.ARGON2_TIME_COST,
                "memory_cost": cfg.ARGON2_MEMORY_COST,
                "parallelism": cfg.ARGON2_PARALLELISM,
                "hash_len": cfg.ARGON2_HASH_LEN,
                "salt_b64": _b64(salt),
            },
            "aead": cfg.AEAD_ALGORITHM,
            "algorithms": {"kem": cfg.KEM_ALGORITHM, "signature": cfg.SIG_ALGORITHM},
            "kem_public_key_b64": _b64(kem_public_der),
            "signature_public_key_b64": _b64(dsa_public_der),
        }
        if x25519_public_raw:
            metadata["x25519_public_key_b64"] = _b64(x25519_public_raw)
        keystore = cls(target, metadata, b"", b"")
        keystore._seal_and_save(
            {"kem_private_der": kem_private_der, "dsa_private_der": dsa_private_der,
             "x25519_private": x25519_private_raw, "previous": previous or [],
             "totp": totp},
            passphrase,
        )
        return keystore

    @classmethod
    def load(cls, directory: Path, email: str) -> "KeyStore":
        path = cls.store_path_for(directory, email)
        if not path.exists():
            raise KeyStoreError(f"No keystore found for {email}. Create one first.")
        return cls.load_path(path)

    @classmethod
    def load_path(cls, path: Path) -> "KeyStore":
        try:
            raw = json.loads(Path(path).read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            raise KeyStoreError("Keystore file is corrupt.") from exc
        if not isinstance(raw, dict) or not isinstance(raw.get("metadata", {}), dict):
            raise KeyStoreError("Keystore file is corrupt.")
        meta = raw.get("metadata", {})
        blob = _unb64(raw.get("blob_b64", ""))
        nonce = _unb64(raw.get("nonce_b64", ""))
        wrap = None
        if isinstance(raw.get("keyring"), dict):
            wrap = {"nonce": _unb64(raw["keyring"].get("nonce_b64", "")),
                    "blob": _unb64(raw["keyring"].get("blob_b64", ""))}
        return cls(Path(path), meta, blob, nonce, wrap)

    # -- crypto operations ---------------------------------------------------
    def _seal_and_save(self, private_bundle: dict[str, Any], passphrase: str) -> None:
        key = derive_storage_key(passphrase, self._salt(), self._kdf_params())
        self._nonce = os.urandom(cfg.AES_NONCE_BYTES)
        self._blob = AESGCM(key).encrypt(self._nonce, _encode_bundle(private_bundle), self._aad())
        # A keyring-wrapped copy is bound to the metadata and holds the same
        # private bundle, so it must be re-wrapped whenever either changes.
        if self._keyring_wrap is not None:
            vault_key = _keyring_get(self.path.name)
            if vault_key:
                nonce = os.urandom(cfg.AES_NONCE_BYTES)
                self._keyring_wrap = {
                    "nonce": nonce,
                    "blob": AESGCM(vault_key).encrypt(nonce, _encode_bundle(private_bundle), self._aad()),
                }
            else:
                self._keyring_wrap = None   # vault key is gone; passphrase unlock still works
        self._save()

    def reseal(self, private_bundle: dict[str, Any], passphrase: str) -> None:
        """Write ``private_bundle`` back (e.g. after enabling two-factor auth)."""
        self._seal_and_save(private_bundle, passphrase)

    def unlock(self, passphrase: str) -> dict[str, Any]:
        """Decrypt and return the private bundle.

        Result keys: ``kem_private_der``, ``dsa_private_der`` and ``previous``
        (a possibly empty list of retired key pairs kept so old mail stays
        readable after a rotation).

        Raises :class:`KeyStoreError` when the passphrase is wrong or the
        file was modified (AES-GCM authentication failure covers both).
        """
        key = derive_storage_key(passphrase, self._salt(), self._kdf_params())
        try:
            plain = AESGCM(key).decrypt(self._nonce, self._blob, self._aad())
        except Exception as exc:  # noqa: BLE001
            raise KeyStoreError(
                "Unlock failed: wrong passphrase or the keystore was modified."
            ) from exc
        return _decode_bundle(plain)

    def upgrade(self, passphrase: str, bundle: dict[str, Any] | None = None) -> dict[str, Any]:
        """Bring an older keystore to the current format and return its bundle.

        * format 1 -> 2: metadata becomes AES-GCM associated data;
        * format 2 -> 3: an X25519 key pair is generated for hybrid encryption.
        """
        bundle = bundle if bundle is not None else self.unlock(passphrase)
        if self.format_version >= FORMAT_VERSION:
            return bundle
        from app.crypto import pqc  # local import: keep this module crypto-light

        metadata = dict(self.metadata)
        metadata.pop("keyring_enrolled", None)           # legacy flag, replaced by "keyring" section
        if not bundle.get("x25519_private") or not metadata.get("x25519_public_key_b64"):
            pair = pqc.generate_x25519_keypair()
            bundle["x25519_private"] = pair.private_bytes()
            metadata["x25519_public_key_b64"] = _b64(pair.public_bytes())
        metadata["format"] = FORMAT_VERSION
        self.metadata = metadata
        if self.format_version < 2:
            self._keyring_wrap = None
        self._seal_and_save(bundle, passphrase)
        event("Keystore upgraded", user=self.metadata.get("email", "?"), fmt=FORMAT_VERSION)
        return bundle

    # -- OS keyring ----------------------------------------------------------
    def unlock_with_keyring(self) -> dict[str, Any] | None:
        """Unlock via the OS keyring vault key (when enrolled), else None."""
        if self._keyring_wrap is None:
            return None
        vault_key = _keyring_get(self.path.name)
        if not vault_key:
            return None
        try:
            plain = AESGCM(vault_key).decrypt(
                self._keyring_wrap["nonce"], self._keyring_wrap["blob"], self._aad())
            return _decode_bundle(plain)
        except Exception:  # noqa: BLE001
            return None

    def enroll_keyring(self, passphrase: str) -> bool:
        """Store a random vault key in the OS keyring and keep a second,
        vault-wrapped copy of the private keys in the keystore file.

        The passphrase-wrapped copy is untouched, so passphrase unlock keeps
        working whatever happens to the OS credential store.
        """
        if not keyring_available():
            return False
        bundle = self.upgrade(passphrase)  # raises KeyStoreError on a wrong passphrase
        vault_key = os.urandom(32)
        nonce = os.urandom(cfg.AES_NONCE_BYTES)
        blob = AESGCM(vault_key).encrypt(nonce, _encode_bundle(bundle), self._aad())
        if not _keyring_set(self.path.name, vault_key):
            return False
        self._keyring_wrap = {"nonce": nonce, "blob": blob}
        self._save()
        event("Keystore enrolled in OS keyring", user=self.metadata.get("email", "?"))
        return True

    def remove_keyring(self) -> None:
        """Forget the keyring enrollment (passphrase unlock is unaffected)."""
        _keyring_delete(self.path.name)
        if self._keyring_wrap is not None:
            self._keyring_wrap = None
            self._save()
            event("Keystore removed from OS keyring", user=self.metadata.get("email", "?"))

    # -- public key accessors ------------------------------------------------
    def kem_public_der(self) -> bytes:
        return _unb64(self.metadata["kem_public_key_b64"])

    def dsa_public_der(self) -> bytes:
        return _unb64(self.metadata["signature_public_key_b64"])

    def x25519_public_raw(self) -> bytes | None:
        text = self.metadata.get("x25519_public_key_b64")
        return _unb64(text) if text else None

    def delete(self) -> None:
        self.path.unlink(missing_ok=True)
        event("Keystore deleted", user=self.metadata.get("email", "?"))
