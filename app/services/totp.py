"""TOTP two-factor authentication (RFC 6238) with single-use recovery codes.

Design
======
* The TOTP secret and the SHA-256 hashes of the recovery codes live **inside the
  encrypted keystore bundle**, next to the private keys. They are never stored in
  the database or in clear on disk; they only exist in RAM once the passphrase
  has unlocked the keystore.
* Sign-in is therefore two steps: passphrase (unlocks the keystore) and then a
  6-digit code. Until the code is accepted the session is "pending" and cannot
  reach any page.
* Replay protection: the newest accepted 30-second step is recorded per account,
  so a code that was just used (or an older one) is refused.
* Recovery codes are one-time: their hashes sit in the keystore, the "used" state
  in the database.

2FA protects the *web sign-in* (phished or shoulder-surfed passphrase). It does
not protect against someone who steals the keystore *file* and brute-forces the
passphrase offline - that is what Argon2id is for.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

from app import config as cfg
from app import db as database
from app.crypto.key_manager import IdentityKeys
from app.log import event
from app.storage.secure_storage import KeyStore, KeyStoreError

_RECOVERY_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"   # no look-alike characters


class TotpError(Exception):
    """User-facing two-factor error (message is safe to display)."""


# ---------------------------------------------------------------------------
# RFC 6238 / RFC 4226 primitives
# ---------------------------------------------------------------------------
def generate_secret() -> bytes:
    return secrets.token_bytes(20)          # 160 bits, the RFC 4226 recommendation


def secret_b32(secret: bytes) -> str:
    return base64.b32encode(secret).decode().rstrip("=")


def hotp(secret: bytes, counter: int, digits: int = cfg.TOTP_DIGITS) -> str:
    mac = hmac.new(secret, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    value = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % (10 ** digits)).zfill(digits)


def time_step(now: float | None = None, period: int = cfg.TOTP_PERIOD) -> int:
    return int((time.time() if now is None else now) // period)


def totp_at(secret: bytes, step: int) -> str:
    return hotp(secret, step)


def match_step(secret: bytes, code: str, now: float | None = None,
               window: int = cfg.TOTP_WINDOW) -> int | None:
    """Return the time-step ``code`` is valid for (within ``window`` steps), else None."""
    code = "".join(ch for ch in (code or "") if ch.isdigit())
    if len(code) != cfg.TOTP_DIGITS:
        return None
    current = time_step(now)
    found = None
    for step in range(current - window, current + window + 1):
        # compare every candidate in constant time; keep the latest match
        if hmac.compare_digest(totp_at(secret, step), code):
            found = step
    return found


def provisioning_uri(secret: bytes, account: str, issuer: str = cfg.TOTP_ISSUER) -> str:
    label = quote(f"{issuer}:{account}")
    return (f"otpauth://totp/{label}?secret={secret_b32(secret)}&issuer={quote(issuer)}"
            f"&algorithm=SHA1&digits={cfg.TOTP_DIGITS}&period={cfg.TOTP_PERIOD}")


def qr_data_uri(uri: str) -> str | None:
    """SVG data-URI QR code for ``uri`` (None if the optional ``segno`` package is missing)."""
    try:
        import segno  # noqa: PLC0415
    except ImportError:  # pragma: no cover - optional dependency
        return None
    return segno.make(uri, error="m").svg_data_uri(scale=5, border=2, dark="#000000", light="#ffffff")


# ---------------------------------------------------------------------------
# Recovery codes
# ---------------------------------------------------------------------------
def _normalise_code(code: str) -> str:
    return "".join(ch for ch in (code or "").lower() if ch.isalnum())


def hash_recovery_code(code: str) -> str:
    return hashlib.sha256(_normalise_code(code).encode()).hexdigest()


def generate_recovery_codes(count: int = cfg.RECOVERY_CODE_COUNT) -> list[str]:
    """Human-friendly one-time codes like ``k7m2-9xqd-4h3t`` (~60 bits each)."""
    codes = []
    for _ in range(count):
        raw = "".join(secrets.choice(_RECOVERY_ALPHABET) for _ in range(12))
        codes.append("-".join(raw[i:i + 4] for i in range(0, 12, 4)))
    return codes


# ---------------------------------------------------------------------------
# Checking a code at sign-in
# ---------------------------------------------------------------------------
def check_code(db: database.Database, keys: IdentityKeys, code: str,
               now: float | None = None) -> str | None:
    """Validate a second-factor ``code``.

    Returns ``"totp"`` or ``"recovery"`` on success, ``None`` otherwise. A TOTP
    time-step can only be used once; each recovery code works once.
    """
    if not keys.totp_secret:
        return None
    step = match_step(keys.totp_secret, code, now)
    if step is not None:
        if db.totp_record_step(keys.email, step):
            return "totp"
        event("TOTP code reuse refused", user=keys.email)
        return None
    normalised = _normalise_code(code)
    if len(normalised) == 12:
        digest = hash_recovery_code(normalised)
        if digest in keys.recovery_hashes and db.recovery_use(keys.email, digest):
            event("Recovery code used", user=keys.email)
            return "recovery"
    return None


def recovery_codes_left(db: database.Database, keys: IdentityKeys) -> int:
    used = db.recovery_used_count(keys.email)
    return max(0, len(keys.recovery_hashes) - used)


# ---------------------------------------------------------------------------
# Enabling / disabling (rewrites the encrypted keystore)
# ---------------------------------------------------------------------------
def _unlock(email: str, passphrase: str) -> tuple[KeyStore, dict]:
    try:
        keystore = KeyStore.load(cfg.KEYS_DIR, email)
        return keystore, keystore.unlock(passphrase)
    except KeyStoreError as exc:
        raise TotpError("The passphrase is wrong.") from exc


def enable(db: database.Database, keys: IdentityKeys, passphrase: str, secret: bytes,
           code: str, now: float | None = None) -> list[str]:
    """Turn two-factor on after the user proved their app produces valid codes.

    Returns the plaintext recovery codes - shown once and never stored.
    """
    if keys.totp_enabled:
        raise TotpError("Two-factor authentication is already enabled.")
    step = match_step(secret, code, now)
    if step is None:
        raise TotpError("That code is not valid. Check your authenticator's clock and try again.")
    keystore, bundle = _unlock(keys.email, passphrase)
    codes = generate_recovery_codes()
    hashes = [hash_recovery_code(c) for c in codes]
    bundle["totp"] = {"secret": secret, "recovery_hashes": hashes}
    keystore.reseal(bundle, passphrase)
    db.totp_reset(keys.email)
    db.totp_record_step(keys.email, step)          # the enrolment code cannot be replayed
    keys.totp_secret, keys.recovery_hashes = secret, hashes
    event("Two-factor authentication enabled", user=keys.email)
    return codes


def disable(db: database.Database, keys: IdentityKeys, passphrase: str, code: str,
            now: float | None = None) -> None:
    if not keys.totp_enabled:
        raise TotpError("Two-factor authentication is not enabled.")
    keystore, bundle = _unlock(keys.email, passphrase)
    if check_code(db, keys, code, now) is None:
        raise TotpError("That authenticator or recovery code is not valid.")
    bundle["totp"] = None
    keystore.reseal(bundle, passphrase)
    db.totp_reset(keys.email)
    keys.totp_secret, keys.recovery_hashes = None, []
    event("Two-factor authentication disabled", user=keys.email)


def regenerate_recovery_codes(db: database.Database, keys: IdentityKeys, passphrase: str) -> list[str]:
    if not keys.totp_enabled:
        raise TotpError("Two-factor authentication is not enabled.")
    keystore, bundle = _unlock(keys.email, passphrase)
    codes = generate_recovery_codes()
    hashes = [hash_recovery_code(c) for c in codes]
    bundle["totp"] = {"secret": keys.totp_secret, "recovery_hashes": hashes}
    keystore.reseal(bundle, passphrase)
    with db._connect() as conn:                     # old codes are void, new ones start unused
        conn.execute("DELETE FROM recovery_used WHERE email = ?", (keys.email,))
    keys.recovery_hashes = hashes
    event("Recovery codes regenerated", user=keys.email)
    return codes
