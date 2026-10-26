"""Envelope format tests: structure, canonicalisation, AAD, validation."""
from __future__ import annotations

import base64
import json

import pytest

from app import config as cfg
from app.bootstrap import ensure_demo_users
from app.crypto.key_manager import load_identity
from app.email import message_format
from app.services import mail_service


@pytest.fixture()
def envelope():
    """One genuine Alice->Bob envelope built with the real crypto stack."""
    ensure_demo_users()
    akm = load_identity(cfg.KEYS_DIR, "alice@pqmail.local", cfg.DEMO_PASSPHRASE)
    bob_row = _active_key("bob@pqmail.local")
    return mail_service.encrypt_and_sign(
        sender_email="alice@pqmail.local",
        recipient_email="bob@pqmail.local",
        subject="Envelope format",
        body="structure test body",
        sender_keys=akm,
        recipient_public_b64=bob_row["kem_public_b64"],
    )


def _active_key(email):
    from app import db as database

    row = database.get_db().get_active_public_key(email)
    assert row is not None
    return row


def test_envelope_has_all_required_fields(envelope):
    expected = {
        "version", "algorithm", "sender", "recipient", "timestamp",
        "message_id", "kem_ciphertext", "salt", "nonce", "ciphertext",
        "sender_key_fingerprint", "signature",
    }
    assert expected <= set(envelope)
    assert envelope["algorithm"] == {
        "kem": "ML-KEM-768",
        "signature": "ML-DSA-65",
        "symmetric": "AES-256-GCM",
        "kdf": "HKDF-SHA-256",
    }


def test_no_plaintext_in_envelope(envelope):
    """The subject/body must not appear anywhere in the JSON package."""
    raw = json.dumps(envelope)
    assert "Envelope format" not in raw
    assert "structure test body" not in raw
    assert "alice@pqmail.local" in raw   # metadata IS public
    assert envelope["version"] == "1.0"


def test_binary_fields_are_base64(envelope):
    decoded = {
        field: base64.b64decode(envelope[field], validate=True)
        for field in ("kem_ciphertext", "salt", "nonce", "ciphertext", "signature")
    }
    assert len(decoded["kem_ciphertext"]) == 1088  # ML-KEM-768 ciphertext size
    assert len(decoded["nonce"]) == 12             # 96-bit GCM nonce
    assert len(decoded["salt"]) == 16
    assert len(decoded["ciphertext"]) > len("structure test body")  # + GCM tag


def test_canonicalisation_is_deterministic(envelope):
    b1 = message_format.canonical_envelope_bytes(envelope)
    b2 = message_format.canonical_envelope_bytes(json.loads(json.dumps(envelope)))
    assert b1 == b2
    # Sorted keys, no whitespace: byte-identical on both peers.
    assert b1 == json.dumps(
        {k: envelope[k] for k in message_format.signed_fields(envelope["version"])},
        sort_keys=True, separators=(",", ":"),
    ).encode()


def test_aad_covers_metadata_but_not_ciphertext(envelope):
    aad = json.loads(message_format.aad_bytes(envelope))
    assert "ciphertext" not in aad
    assert "signature" not in aad
    for field in ("sender", "recipient", "kem_ciphertext", "nonce", "salt"):
        assert aad[field] == envelope[field]


def test_validate_envelope_accepts_valid(envelope):
    message_format.validate_envelope(envelope)  # must not raise


@pytest.mark.parametrize("mutation,field", [
    (lambda e: e.update(version="9.9"), "version"),
    (lambda e: e["algorithm"].update(kem="Kyber768"), "algorithm"),
    (lambda e: e.update(sender="not-an-email"), "sender"),
    (lambda e: e.update(nonce="!!!not-base64!!!"), "nonce"),
    (lambda e: e.update(ciphertext=""), "ciphertext"),
    (lambda e: e.update(timestamp="not-a-date"), "timestamp"),
    (lambda e: e.pop("sender_key_fingerprint"), "sender_key_fingerprint"),
    (lambda e: e.update(kem_ciphertext=base64.b64encode(b"short").decode()), "kem_ciphertext"),
])
def test_validate_envelope_rejects_mutations(envelope, mutation, field):
    bad = json.loads(json.dumps(envelope))
    mutation(bad)
    with pytest.raises(message_format.EnvelopeFormatError):
        message_format.validate_envelope(bad)


def test_future_timestamp_beyond_1_day_rejected(envelope):
    from datetime import datetime, timedelta, timezone

    bad = json.loads(json.dumps(envelope))
    bad["timestamp"] = (datetime.now(timezone.utc) + timedelta(days=3)).isoformat()
    with pytest.raises(message_format.EnvelopeFormatError):
        message_format.validate_envelope(bad)


def test_tamper_ciphertext_flips_exactly_one_bit(envelope):
    original = base64.b64decode(envelope["ciphertext"])
    tampered = message_format.tamper_ciphertext(envelope)
    new = base64.b64decode(tampered["ciphertext"])
    assert len(new) == len(original)
    diff_bits = sum(bin(a ^ b).count("1") for a, b in zip(original, new))
    assert diff_bits == 1
    # Original envelope object is not mutated.
    assert envelope["ciphertext"] != tampered["ciphertext"]


def test_message_id_is_unique_per_message():
    ensure_demo_users()
    akm = load_identity(cfg.KEYS_DIR, "alice@pqmail.local", cfg.DEMO_PASSPHRASE)
    bob_row = _active_key("bob@pqmail.local")
    ids = set()
    for i in range(3):
        env = mail_service.encrypt_and_sign(
            sender_email="alice@pqmail.local", recipient_email="bob@pqmail.local",
            subject=f"m{i}", body="x", sender_keys=akm,
            recipient_public_b64=bob_row["kem_public_b64"],
        )
        ids.add(env["message_id"])
    assert len(ids) == 3
