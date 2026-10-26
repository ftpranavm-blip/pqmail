"""Public-key directory: importing other people's public key bundles safely.

Why this module exists
======================
The directory is the trust anchor for encryption (whose key do we encrypt to?)
and for signature verification (whose key signed this?). A bundle import is
therefore security-critical:

* a bundle can **never** create or replace the keys of an identity that lives
  on this machine (``users.source == 'local'``) - otherwise any signed-in user
  could publish their own key under ``bob@...`` and read/forge Bob's mail;
* for an already-imported contact, a *different* key is only accepted after an
  explicit confirmation that shows both fingerprints (trust-on-first-use with
  loud key-change warnings, like SSH/Signal);
* the bundle must be well-formed, size-limited and use the expected algorithms.

Bundles carry no proof of ownership, so the fingerprint must still be compared
with the owner over another channel - the UI says so.
"""
from __future__ import annotations

import base64
import json
from dataclasses import dataclass

from app import config as cfg
from app import db as database
from app.crypto import fingerprints, pqc
from app.log import event


class DirectoryError(Exception):
    """Import refused (message is safe to show to the user)."""


class KeyChangeNeedsConfirmation(DirectoryError):
    """An imported contact is already pinned to a different key."""

    def __init__(self, email: str, old_fingerprint: str, new_fingerprint: str):
        super().__init__(
            f"{email} is already pinned to a different key. "
            f"Pinned: {old_fingerprint}  ·  Offered: {new_fingerprint}. "
            "Only replace it if the owner confirmed the new fingerprint over another channel."
        )
        self.email = email
        self.old_fingerprint = old_fingerprint
        self.new_fingerprint = new_fingerprint


def sync_own_keys(db: database.Database, keys) -> str:
    """Compare a signed-in identity's real keys with what the directory publishes.

    Returns ``"ok"``, ``"attached"`` (the hybrid X25519 key was added to an older
    entry), ``"missing"`` (not published), or ``"mismatch"`` (the directory lists
    a different key set for this address than the keystore holds - possibly a
    key substitution; the UI warns loudly).
    """
    email = keys.email
    sig_b64 = base64.b64encode(keys.dsa_public_bytes).decode()
    kem_b64 = base64.b64encode(keys.kem_public_bytes).decode()
    x_b64 = base64.b64encode(keys.x25519_public_bytes).decode() if keys.x25519 else None
    fp = fingerprints.public_key_fingerprint(keys.dsa_public_bytes)
    active = db.get_active_public_key(email)
    if active is None or db.get_public_key_by_fingerprint(email, fp) is None:
        return "missing" if active is None else "mismatch"
    if active["fingerprint"] != fp:
        return "mismatch"
    if active["kem_public_b64"] != kem_b64 or active["sig_public_b64"] != sig_b64:
        return "mismatch"
    if active["x25519_public_b64"] != x_b64:
        if x_b64 and not active["x25519_public_b64"]:
            db.publish_public_keys(email=email, kem_algo=cfg.KEM_ALGORITHM, sig_algo=cfg.SIG_ALGORITHM,
                                   kem_public_b64=kem_b64, sig_public_b64=sig_b64,
                                   fingerprint=fp, x25519_public_b64=x_b64)
            return "attached"
        return "mismatch"
    return "ok"


@dataclass
class ImportResult:
    email: str
    fingerprint: str
    created: bool
    replaced: bool
    unchanged: bool


def parse_bundle(blob: str) -> dict:
    """Decode and validate a public key bundle; returns the verified fields."""
    blob = (blob or "").strip()
    if not blob or len(blob) > cfg.MAX_PUBLIC_BUNDLE_BYTES:
        raise DirectoryError("Import failed: the bundle is empty or too large.")
    try:
        decoded = json.loads(base64.b64decode(blob, validate=True))
        if not isinstance(decoded, dict):
            raise ValueError("bundle is not an object")
        algorithms = decoded["algorithms"]
        if algorithms["kem"] != cfg.KEM_ALGORITHM or algorithms["signature"] != cfg.SIG_ALGORITHM:
            raise ValueError("unexpected algorithms")
        kem_pub = base64.b64decode(decoded["kem_public_key_b64"], validate=True)
        sig_pub = base64.b64decode(decoded["signature_public_key_b64"], validate=True)
        pqc.load_kem_public_key(kem_pub)   # validates the encoding and key type
        pqc.load_dsa_public_key(sig_pub)
        x_pub_b64 = decoded.get("x25519_public_key_b64")
        if x_pub_b64:
            pqc.load_x25519_public_key(base64.b64decode(x_pub_b64, validate=True))
        else:
            x_pub_b64 = None
    except Exception as exc:  # noqa: BLE001 - any parse failure -> same message
        raise DirectoryError(
            "Import failed: the bundle is invalid or uses different algorithms."
        ) from exc
    email = cfg.normalize_email(decoded.get("email"))
    if not cfg.is_valid_email(email):
        raise DirectoryError("Import failed: bundle has no valid email address.")
    return {
        "email": email,
        "kem_public_b64": decoded["kem_public_key_b64"],
        "sig_public_b64": decoded["signature_public_key_b64"],
        "x25519_public_b64": x_pub_b64,
        "fingerprint": fingerprints.public_key_fingerprint(sig_pub),
    }


def import_bundle(blob: str, db: database.Database | None = None,
                  confirm_replace: bool = False) -> ImportResult:
    """Import another user's public keys under the rules in the module docstring."""
    db = db or database.get_db()
    bundle = parse_bundle(blob)
    email = bundle["email"]

    user = db.get_user(email)
    if user is not None and user["source"] == "local":
        raise DirectoryError(
            f"{email} is an identity on this machine; its keys can only be published "
            "by that identity itself and cannot be replaced by an import."
        )

    created = user is None
    replaced = False
    if not created:
        active = db.get_active_public_key(email)
        if active is not None:
            if active["fingerprint"] == bundle["fingerprint"]:
                if bundle["x25519_public_b64"] and not active["x25519_public_b64"] \
                        and active["kem_public_b64"] == bundle["kem_public_b64"]:
                    # same identity, now offering the hybrid X25519 key: attach it
                    db.publish_public_keys(
                        email=email, kem_algo=cfg.KEM_ALGORITHM, sig_algo=cfg.SIG_ALGORITHM,
                        kem_public_b64=bundle["kem_public_b64"], sig_public_b64=bundle["sig_public_b64"],
                        fingerprint=bundle["fingerprint"], x25519_public_b64=bundle["x25519_public_b64"])
                return ImportResult(email, bundle["fingerprint"], created=False,
                                    replaced=False, unchanged=True)
            if not confirm_replace:
                raise KeyChangeNeedsConfirmation(email, active["fingerprint"],
                                                 bundle["fingerprint"])
            replaced = True

    if created:
        db.upsert_user(email, email, is_demo=False, source="imported")
    db.publish_public_keys(
        email=email, kem_algo=cfg.KEM_ALGORITHM, sig_algo=cfg.SIG_ALGORITHM,
        kem_public_b64=bundle["kem_public_b64"], sig_public_b64=bundle["sig_public_b64"],
        fingerprint=bundle["fingerprint"], x25519_public_b64=bundle["x25519_public_b64"],
        action="replace" if replaced else "import",
    )
    event("Public key bundle imported", user=email, replaced=replaced)
    return ImportResult(email, bundle["fingerprint"], created=created,
                        replaced=replaced, unchanged=False)
