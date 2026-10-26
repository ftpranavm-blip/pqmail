"""Identity key management.

An *identity* (one mailbox user) owns:

* an ML-KEM-768 key pair  — encryption / key establishment
* an ML-DSA-65 key pair   — signing

Private key material is generated locally, encrypted with AES-256-GCM
under a key derived from the user's passphrase (Argon2id) and stored via
:class:`app.storage.secure_storage.KeyStore`. Only public keys are ever
exported.
"""
from __future__ import annotations

import base64
import secrets
import os
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from app import config as cfg
from app.crypto import fingerprints, pqc
from app.crypto.pqc import DsaKeyPair, KemKeyPair, X25519KeyPair
from app.log import event
from app.storage.secure_storage import KeyStore, KeyStoreError


# Retired key pairs carried inside the new keystore after a rotation, so mail
# encrypted to an older key stays readable. Oldest entries drop off first.
MAX_PREVIOUS_KEYS = 20


class WrongPassphraseError(Exception):
    """The provided passphrase cannot unlock the keystore."""


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def generate_identity_keys() -> tuple[KemKeyPair, DsaKeyPair, X25519KeyPair]:
    """Generate a fresh (ML-KEM-768, ML-DSA-65, X25519) key pair set."""
    return pqc.generate_kem_keypair(), pqc.generate_dsa_keypair(), pqc.generate_x25519_keypair()


def fingerprint_summary(kem_pub_der: bytes, dsa_pub_der: bytes) -> dict[str, str]:
    """Convenience wrapper returning both fingerprints."""
    return {
        "kem_fingerprint": fingerprints.public_key_fingerprint(kem_pub_der),
        "sig_fingerprint": fingerprints.public_key_fingerprint(dsa_pub_der),
    }


def generate_salt() -> bytes:
    """Random salt for a new keystore (never reused between identities)."""
    return secrets.token_bytes(cfg.ARGON2_SALT_LEN)


@dataclass
class IdentityKeys:
    """Unlocked identity keys held in RAM for the duration of a session."""

    email: str
    kem: KemKeyPair
    dsa: DsaKeyPair
    created_at: str
    # Retired ML-KEM key pairs (newest first), tried after the current key when
    # opening mail that was sent before the last rotation.
    previous_kems: list[KemKeyPair] = field(default_factory=list)
    # X25519 half of the hybrid exchange (None for identities that predate it).
    x25519: X25519KeyPair | None = None
    # Retired X25519 keys, aligned index-for-index with ``previous_kems``.
    previous_x25519: list[X25519KeyPair | None] = field(default_factory=list)
    # Two-factor authentication data kept inside the encrypted keystore.
    totp_secret: bytes | None = None
    recovery_hashes: list[str] = field(default_factory=list)

    @property
    def kem_public_bytes(self) -> bytes:
        return self.kem.public_bytes()

    @property
    def dsa_public_bytes(self) -> bytes:
        return self.dsa.public_bytes()

    @property
    def x25519_public_bytes(self) -> bytes | None:
        return self.x25519.public_bytes() if self.x25519 else None

    @property
    def totp_enabled(self) -> bool:
        return self.totp_secret is not None

    def export_public_bundle_b64(self) -> str:
        """Base64 JSON of both public keys — this is what users may share."""
        payload = {
            "version": cfg.KEYSTORE_BUNDLE_VERSION,
            "email": self.email,
            "algorithms": {"kem": cfg.KEM_ALGORITHM, "signature": cfg.SIG_ALGORITHM},
            "created_at": self.created_at,
            "kem_public_key_b64": base64.b64encode(self.kem_public_bytes).decode(),
            "signature_public_key_b64": base64.b64encode(self.dsa_public_bytes).decode(),
        }
        if self.x25519:
            payload["x25519_public_key_b64"] = base64.b64encode(self.x25519_public_bytes).decode()
        import json

        return base64.b64encode(json.dumps(payload, indent=2).encode()).decode()


def create_keystore(keystore_dir, email: str, passphrase: str,
                    previous: list[dict] | None = None, path: Path | None = None,
                    totp: dict | None = None) -> dict:
    """Generate fresh identity keys and encrypt them into a new keystore."""
    KeyStore.validate_passphrase(passphrase)
    (kem, dsa, xkey) = generate_identity_keys()
    created_at = utc_now_iso()
    salt = generate_salt()
    KeyStore.create(
        directory=keystore_dir,
        email=email,
        salt=salt,
        kem_private_der=kem.private_bytes(),
        kem_public_der=kem.public_bytes(),
        dsa_private_der=dsa.private_bytes(),
        dsa_public_der=dsa.public_bytes(),
        created_at=created_at,
        passphrase=passphrase,
        previous=previous,
        path=path,
        x25519_private_raw=xkey.private_bytes(),
        x25519_public_raw=xkey.public_bytes(),
        totp=totp,
    )
    event("Keystore created", user=email, algorithms=f"{cfg.KEM_ALGORITHM}+{cfg.SIG_ALGORITHM}")
    return {
        "email": email,
        "created_at": created_at,
        "kem_fingerprint": fingerprints.public_key_fingerprint(kem.public_bytes()),
        "sig_fingerprint": fingerprints.public_key_fingerprint(dsa.public_bytes()),
        "kem_public_b64": base64.b64encode(kem.public_bytes()).decode(),
        "sig_public_b64": base64.b64encode(dsa.public_bytes()).decode(),
        "x25519_public_b64": base64.b64encode(xkey.public_bytes()).decode(),
    }


def _identity_from_bundle(keystore: KeyStore, email: str, bundle: dict) -> IdentityKeys:
    kem = pqc.load_kem_private_key(bundle["kem_private_der"])
    dsa = pqc.load_dsa_private_key(bundle["dsa_private_der"])
    # Public keys are stored unencrypted in the keystore metadata and must
    # match the private keys; verify all of them before handing out the identity.
    kem_pub = pqc.load_kem_public_key(keystore.kem_public_der())
    dsa_pub = pqc.load_dsa_public_key(keystore.dsa_public_der())
    test_ss, test_ct = pqc.encapsulate(kem_pub)
    if pqc.decapsulate(kem, test_ct) != test_ss:
        raise WrongPassphraseError("Keystore key material is inconsistent.")
    probe = b"pqmail keystore self-check"
    if not pqc.verify(dsa_pub, pqc.sign(dsa, probe), probe):
        raise WrongPassphraseError("Keystore signing key is inconsistent.")

    x_pair = None
    if bundle.get("x25519_private"):
        x_priv = pqc.load_x25519_private_key(bundle["x25519_private"])
        stored_pub = keystore.x25519_public_raw()
        x_pair = pqc.X25519KeyPair(x_priv, x_priv.public_key())
        if stored_pub is not None and stored_pub != x_pair.public_bytes():
            raise WrongPassphraseError("Keystore X25519 key is inconsistent.")

    previous_kems, previous_x = [], []
    for old in bundle.get("previous", []):
        old_priv = pqc.load_kem_private_key(old["kem_private_der"])
        previous_kems.append(pqc.KemKeyPair(old_priv, old_priv.public_key()))
        if old.get("x25519_private"):
            old_x = pqc.load_x25519_private_key(old["x25519_private"])
            previous_x.append(pqc.X25519KeyPair(old_x, old_x.public_key()))
        else:
            previous_x.append(None)
    totp = bundle.get("totp") or None
    return IdentityKeys(
        email=email,
        kem=pqc.KemKeyPair(kem, kem_pub),
        dsa=pqc.DsaKeyPair(dsa, dsa_pub),
        created_at=keystore.metadata.get("created_at", "unknown"),
        previous_kems=previous_kems,
        x25519=x_pair,
        previous_x25519=previous_x,
        totp_secret=totp["secret"] if totp else None,
        recovery_hashes=list(totp["recovery_hashes"]) if totp else [],
    )


def load_identity(keystore_dir, email: str, passphrase: str | None = None,
                  use_keyring: bool = False) -> IdentityKeys:
    """Unlock an identity's keys (keys stay in RAM).

    Unlocks with ``passphrase``, or - when ``use_keyring`` is true and the
    keystore was enrolled - with the vault key held by the OS keyring. Older
    keystores are upgraded in place the first time they are unlocked with the
    passphrase (adding the X25519 key for hybrid encryption).
    """
    try:
        keystore = KeyStore.load(keystore_dir, email)
    except KeyStoreError as exc:
        raise WrongPassphraseError(str(exc)) from exc
    try:
        if use_keyring:
            bundle = keystore.unlock_with_keyring()
            if bundle is None:
                raise WrongPassphraseError("OS keyring unlock is not available for this identity.")
        else:
            bundle = keystore.unlock(passphrase or "")
            if keystore.format_version < 3:
                try:
                    bundle = keystore.upgrade(passphrase or "", bundle)
                except KeyStoreError:  # pragma: no cover - upgrade is best effort
                    event("Keystore upgrade skipped", user=email)
    except KeyStoreError as exc:
        raise WrongPassphraseError("Incorrect passphrase.") from exc
    return _identity_from_bundle(keystore, email, bundle)


def rotate_keys(keystore_dir, email: str, old_passphrase: str, new_passphrase: str) -> dict:
    """Rotate identity keys without ever leaving the user without a keystore.

    Order of operations (the active keystore is only replaced as the very last
    step, atomically, so any earlier failure changes nothing):

    1. validate the *new* passphrase and unlock the current keystore;
    2. stage a new keystore (new keys) next to the active one - it also carries
       the retired private keys, re-encrypted under the new passphrase, so mail
       sent to the old keys can still be opened (two-factor settings carry over);
    3. copy the current keystore into the archive;
    4. atomically swap the staged file into place.
    """
    KeyStore.validate_passphrase(new_passphrase)
    current = KeyStore.store_path_for(keystore_dir, email, active=True)
    keystore = KeyStore.load(keystore_dir, email)
    load_identity(keystore_dir, email, old_passphrase)   # wrong passphrase -> raises (also upgrades)
    keystore = KeyStore.load(keystore_dir, email)
    bundle = keystore.unlock(old_passphrase)

    retired = {
        "kem_private_der": bundle["kem_private_der"],
        "dsa_private_der": bundle["dsa_private_der"],
        "x25519_private": bundle.get("x25519_private"),
        "x25519_public_key_b64": keystore.metadata.get("x25519_public_key_b64", ""),
        "kem_public_key_b64": keystore.metadata.get("kem_public_key_b64", ""),
        "signature_public_key_b64": keystore.metadata.get("signature_public_key_b64", ""),
        "retired_at": utc_now_iso(),
    }
    previous = ([retired] + list(bundle.get("previous", [])))[:MAX_PREVIOUS_KEYS]

    staged = current.with_name(current.name + ".new")
    try:
        info = create_keystore(keystore_dir, email, new_passphrase, previous=previous,
                               path=staged, totp=bundle.get("totp"))
        archive_dir = cfg.KEY_ARCHIVE_DIR
        archive_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        backup_name = f"{email.replace('@', '_at_')}.{stamp}.keystore.json"
        shutil.copy2(current, archive_dir / backup_name)
        os.replace(staged, current)
    except Exception:
        staged.unlink(missing_ok=True)
        raise
    # The new keystore has no keyring wrapping; drop the stale vault key.
    from app.storage.secure_storage import _keyring_delete  # noqa: PLC0415
    _keyring_delete(current.name)
    event("Key rotation completed", user=email)
    return info
