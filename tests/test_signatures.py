"""Tests 5 & 6 — ML-DSA-65 digital signatures (FIPS 204)."""
from __future__ import annotations

import pytest

from app import db as database
from app.crypto import pqc
from app.crypto.pqc import PQCryptoError
from app.email import message_format
from app.services import mail_service


def test_dsa_keypair_generation():
    pair = pqc.generate_dsa_keypair()
    # FIPS 204 / ML-DSA-65 raw verification key: 1952 bytes; DER adds a header.
    assert 1952 <= len(pair.public_bytes()) <= 1952 + 32
    # pyca serialises ML-DSA private keys in SEED form (32-byte seed, FIPS 204
    # appendix D) — the tiny PKCS#8 DER expands to the full 4032-byte secret key.
    assert 40 <= len(pair.private_bytes()) <= 128


def test_sign_and_verify_succeeds():
    """Test 5: a genuine signature over unchanged data verifies."""
    pair = pqc.generate_dsa_keypair()
    data = b"canonical envelope bytes 2026-09-09"
    sig = pqc.sign(pair.private_key, data)
    assert pqc.verify(pair.public_key, sig, data) is True


def test_modified_data_fails_verification():
    """Test 6: modifying the signed data must invalidate the signature."""
    pair = pqc.generate_dsa_keypair()
    data = b"sender=alice@pqmail.local&amount=1"
    sig = pqc.sign(pair.private_key, data)
    tampered_variants = [
        b"sender=alice@pqmail.local&amount=2",      # same length
        data + b"x",                                  # appended
        data[:-1],                                    # truncated
        b"Sender=alice@pqmail.local&amount=1",        # case flip
    ]
    for bad in tampered_variants:
        assert pqc.verify(pair.public_key, sig, bad) is False


def test_signature_over_tampered_ciphertext_envelope_fails():
    """The signed canonical envelope binds the ciphertext: flipping a
    ciphertext bit invalidates the ML-DSA signature."""
    from app.bootstrap import ensure_demo_users

    ensure_demo_users()
    from app import config as cfg
    from app.crypto.key_manager import load_identity

    akm = load_identity(cfg.KEYS_DIR, "alice@pqmail.local", cfg.DEMO_PASSPHRASE)
    env = mail_service.encrypt_and_sign(
        sender_email="alice@pqmail.local",
        recipient_email="bob@pqmail.local",
        subject="sig test",
        body="body",
        sender_keys=akm,
        recipient_public_b64=_bob_kem_pub_b64(),
    )
    original = message_format.canonical_envelope_bytes(env)
    assert pqc.verify(
        pqc.load_dsa_public_key(_alice_sig_pub()),
        base64_decode(env["signature"]),
        original,
    )
    tampered = message_format.tamper_ciphertext(env)
    assert message_format.canonical_envelope_bytes(tampered) != original
    assert not pqc.verify(
        pqc.load_dsa_public_key(_alice_sig_pub()),
        base64_decode(env["signature"]),
        message_format.canonical_envelope_bytes(tampered),
    )


def _bob_kem_pub_b64() -> str:
    from app import config as cfg

    row = database.get_db().get_active_public_key("bob@pqmail.local")
    assert row is not None
    return row["kem_public_b64"]


def _alice_sig_pub() -> bytes:
    import base64

    row = database.get_db().get_active_public_key("alice@pqmail.local")
    return base64.b64decode(row["sig_public_b64"])


def base64_decode(s: str) -> bytes:
    import base64

    return base64.b64decode(s)


def test_signature_bytes_change_every_message():
    """ML-DSA signing is randomised: identical data yields different sigs."""
    pair = pqc.generate_dsa_keypair()
    data = b"same data"
    s1 = pqc.sign(pair.private_key, data)
    s2 = pqc.sign(pair.private_key, data)
    assert s1 != s2
    assert pqc.verify(pair.public_key, s1, data)
    assert pqc.verify(pair.public_key, s2, data)


def test_wrong_public_key_fails_verification():
    pair_a = pqc.generate_dsa_keypair()
    pair_b = pqc.generate_dsa_keypair()
    sig = pqc.sign(pair_a.private_key, b"data")
    assert pqc.verify(pair_b.public_key, sig, b"data") is False


def test_malformed_signature_and_key_rejected():
    pair = pqc.generate_dsa_keypair()
    data = b"data"
    sig = pqc.sign(pair.private_key, data)
    assert pqc.verify(pair.public_key, b"", data) is False
    assert pqc.verify(pair.public_key, sig[:-1] + b"\x00", data) is False
    with pytest.raises(PQCryptoError):
        pqc.load_dsa_public_key(b"not a key")


def test_dsa_serialization_roundtrip():
    pair = pqc.generate_dsa_keypair()
    priv = pqc.load_dsa_private_key(pair.private_bytes())
    pub = pqc.load_dsa_public_key(pair.public_bytes())
    sig = pqc.sign(priv, b"roundtrip")
    assert pqc.verify(pub, sig, b"roundtrip")
