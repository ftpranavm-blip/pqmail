"""End-to-end mail service tests: the full Alice -> Bob demo flow."""
from __future__ import annotations

import base64
import json

import pytest

from app import config as cfg
from app import db as database
from app.crypto.key_manager import load_identity
from app.services import mail_service
from app.services.mail_service import MailServiceError


@pytest.fixture()
def mail_world(demo_world, alice_keys, bob_keys):
    return {
        **demo_world,          # "alice"/"bob" are the email ADDRESSES here
        "alice_keys": alice_keys,
        "bob_keys": bob_keys,
    }


def _send(alice, bob_addr, subject="Project Meeting",
          body="Hello Bob, this message is protected using post-quantum cryptography."):
    return mail_service.send_email(
        sender_email="alice@pqmail.local", recipient_email=bob_addr,
        subject=subject, body=body, sender_keys=alice,
    )


def _open(result, owner_email, owner_keys):
    return mail_service.open_email(
        message_id=result.message_id, owner_email=owner_email, owner_keys=owner_keys,
    )


def test_full_alice_to_bob_flow(mail_world):
    """Test: Alice sends; Bob receives, decrypts and verifies the signature."""
    result = _send(mail_world["alice_keys"], mail_world["bob"])
    assert result.delivered_via == "local-demo-mailbox"
    assert result.kem_ciphertext_len == 1088
    assert result.signature_len > 0

    opened = _open(result, "bob@pqmail.local", mail_world["bob_keys"])
    assert opened.signature_valid is True
    assert opened.integrity_valid is True
    assert opened.subject == "Project Meeting"
    assert "post-quantum cryptography" in opened.body
    assert opened.algorithms["kem"] == "X25519+ML-KEM-768"   # hybrid by default
    assert opened.algorithms["signature"] == "ML-DSA-65"
    assert opened.algorithms["symmetric"] == "AES-256-GCM"
    assert opened.sender == "alice@pqmail.local"
    assert opened.sender_fingerprint  # fingerprint shown in UI


def test_database_stores_only_ciphertext(mail_world):
    """No plaintext subject/body may exist in the database file.

    The stored ``subject_hint`` is a constant non-sensitive label, so even
    the mailbox listing leaks nothing about message content (PS §20)."""
    _send(mail_world["alice_keys"], mail_world["bob"])
    db_path = database.get_db().db_path
    raw = db_path.read_bytes()
    assert b"post-quantum cryptography" not in raw
    assert b"Project Meeting" not in raw
    # The envelope JSON (ciphertext) is present.
    assert b"kem_ciphertext" in raw


def test_sent_copy_stored_for_sender(mail_world):
    _send(mail_world["alice_keys"], mail_world["bob"])
    sent = database.get_db().list_envelopes("alice@pqmail.local", "sent")
    assert len(sent) == 1


def test_missing_recipient_public_key_fails(mail_world):
    with pytest.raises(MailServiceError, match="No registered public key"):
        _send(mail_world["alice_keys"], "nobody@pqmail.local")


def test_invalid_recipient_address_rejected(mail_world):
    with pytest.raises(MailServiceError):
        _send(mail_world["alice_keys"], "not-an-email")


def test_tampered_ciphertext_withheld(mail_world):
    """Test (section 14): simulate tampering -> open -> content withheld."""
    result = _send(mail_world["alice_keys"], mail_world["bob"])
    mail_service.simulate_tampering(result.message_id, "bob@pqmail.local")
    opened = _open(result, "bob@pqmail.local", mail_world["bob_keys"])
    assert opened.signature_valid is False
    assert opened.integrity_valid is False
    assert opened.body == ""
    assert "withheld" in opened.subject.lower()


def test_swapped_metadata_breaks_verification(mail_world):
    """Re-addressing an envelope (Alice->Mallory spoof) must fail verification.

    The envelope is still *structurally* valid, so the defence is the
    ML-DSA signature (and AAD binding), which cover the recipient field."""
    from app.crypto import pqc
    from app.email import message_format

    result = _send(mail_world["alice_keys"], mail_world["bob"])
    with database.get_db()._connect() as conn:
        row = conn.execute(
            "SELECT envelope_json FROM envelopes WHERE message_id = ?",
            (result.message_id,),
        ).fetchone()
    env = json.loads(row["envelope_json"])
    spoofed = dict(env, recipient="mallory@pqmail.local")
    # Structure still parses (metadata fields all present)...
    message_format.validate_envelope(spoofed)  # must NOT raise
    # ...but the signature no longer verifies against the signed bytes.
    sender_pub = pqc.load_dsa_public_key(
        base64.b64decode(_active_key("alice@pqmail.local")["sig_public_b64"])
    )
    assert not pqc.verify(
        sender_pub,
        base64.b64decode(env["signature"]),
        message_format.canonical_envelope_bytes(spoofed),
    )


def _active_key(email):
    row = database.get_db().get_active_public_key(email)
    assert row is not None
    return row


def test_open_unknown_message_fails(mail_world):
    with pytest.raises(MailServiceError, match="not found"):
        mail_service.open_email(
            message_id="pqmail-does-not-exist", owner_email="bob@pqmail.local",
            owner_keys=mail_world["bob_keys"],
        )


def test_sender_cannot_open_recipients_inbox_copy(mail_world):
    """Alice (sender) must not reach Bob's inbox row: it is Bob's mailbox."""
    result = _send(mail_world["alice_keys"], mail_world["bob"])
    with pytest.raises(MailServiceError, match="not found"):
        mail_service.open_email(
            message_id=result.message_id, owner_email="alice@pqmail.local",
            owner_keys=mail_world["alice_keys"],
        )
