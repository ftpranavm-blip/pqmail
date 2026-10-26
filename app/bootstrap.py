"""First-run bootstrap: demo users, keystores, public-key directory.

Creates Alice and Bob with ML-KEM-768 + ML-DSA-65 identities protected by
the demo passphrase (``PQMAIL_DEMO_PASSPHRASE``, default ``demo1234``) and
publishes their public keys into the local key directory, so the
Alice→Bob demo flow works out of the box. Existing keystores are never
overwritten. Disable the whole thing with ``PQMAIL_DEMO_MODE=0``.
"""
from __future__ import annotations

import base64

from app import config as cfg
from app import db as database
from app.crypto import fingerprints
from app.crypto.key_manager import create_keystore
from app.log import event
from app.storage.secure_storage import KeyStore, KeyStoreError

_MAX_DISPLAY_NAME = 80


def _publish_from_keystore(db: database.Database, email: str) -> None:
    """Publish the public keys stored (non-secret) in the keystore metadata."""
    keystore = KeyStore.load(cfg.KEYS_DIR, email)
    kem_pub_b64 = base64.b64encode(keystore.kem_public_der()).decode()
    sig_pub_b64 = base64.b64encode(keystore.dsa_public_der()).decode()
    fingerprint = fingerprints.public_key_fingerprint(keystore.dsa_public_der())
    x_pub = keystore.x25519_public_raw()
    db.publish_public_keys(
        email=email,
        kem_algo=cfg.KEM_ALGORITHM,
        sig_algo=cfg.SIG_ALGORITHM,
        kem_public_b64=kem_pub_b64,
        sig_public_b64=sig_pub_b64,
        fingerprint=fingerprint,
        x25519_public_b64=base64.b64encode(x_pub).decode() if x_pub else None,
    )


def ensure_demo_users(db: database.Database | None = None) -> None:
    """Idempotently create demo users, keystores and published public keys."""
    db = db or database.get_db()
    if not cfg.DEMO_ENABLED:
        return
    for email, display_name in cfg.DEMO_USERS:
        user = db.get_user(email)
        if user is None:
            db.upsert_user(email, display_name, is_demo=True, source="local")
            event("Demo user created", user=email)
        else:
            db.upsert_user(email, display_name, is_demo=True, source="local")

        try:
            KeyStore.load(cfg.KEYS_DIR, email)
            keystore_exists = True
        except KeyStoreError:
            keystore_exists = False

        if not keystore_exists:
            create_keystore(cfg.KEYS_DIR, email, cfg.DEMO_PASSPHRASE)
            event("Demo identity keys generated", user=email,
                  algorithms=f"{cfg.KEM_ALGORITHM}+{cfg.SIG_ALGORITHM}")
        if db.get_active_public_key(email) is None:
            _publish_from_keystore(db, email)

    # Pre-populate each other as contacts for a friendly demo
    emails = [email for email, _name in cfg.DEMO_USERS]
    for owner in emails:
        for contact in emails:
            if owner != contact:
                db.add_contact(owner, contact)


def clean_display_name(value: str) -> str:
    """Collapse whitespace and drop control characters from a display name."""
    return " ".join("".join(ch for ch in (value or "") if ch.isprintable()).split())


def create_identity(email: str, display_name: str, passphrase: str,
                    db: database.Database | None = None) -> dict:
    """Create a brand-new identity (registration): keys + keystore + directory.

    Raises ``ValueError`` with a user-safe message for every validation problem.
    """
    email = cfg.normalize_email(email)
    if not cfg.is_valid_email(email):
        raise ValueError("Please provide a valid email address (letters, digits, . _ % + - only).")
    display_name = clean_display_name(display_name)
    if not display_name or len(display_name) > _MAX_DISPLAY_NAME:
        raise ValueError(f"Please provide a display name (max {_MAX_DISPLAY_NAME} characters).")
    try:
        KeyStore.validate_passphrase(passphrase)
    except KeyStoreError as exc:
        raise ValueError(str(exc)) from exc
    db = db or database.get_db()
    if KeyStore.store_path_for(cfg.KEYS_DIR, email).exists() or db.get_user(email) is not None:
        raise ValueError("An identity with this address already exists.")
    info = create_keystore(cfg.KEYS_DIR, email, passphrase)
    try:
        db.upsert_user(email, display_name, is_demo=False, source="local")
        db.publish_public_keys(
            email=email, kem_algo=cfg.KEM_ALGORITHM, sig_algo=cfg.SIG_ALGORITHM,
            kem_public_b64=info["kem_public_b64"], sig_public_b64=info["sig_public_b64"],
            fingerprint=info["sig_fingerprint"], x25519_public_b64=info["x25519_public_b64"],
        )
    except Exception:
        # Do not leave an orphan keystore behind if the directory write failed.
        KeyStore.store_path_for(cfg.KEYS_DIR, email).unlink(missing_ok=True)
        raise
    event("New identity registered", user=email)
    return info
