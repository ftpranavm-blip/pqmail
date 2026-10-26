"""Mail service: encrypt, send, receive, decrypt, verify — the security core.

Threat-model driven flow
========================
Sending:
  1. look up the recipient's public keys in the key directory
  2. establish a shared secret: hybrid X25519 + ML-KEM-768 when the recipient
     has an X25519 key (envelope v2), ML-KEM-768 alone for legacy keys (v1)
  3. derive an AES-256 key with HKDF-SHA-256 (fresh random salt per message)
  4. AES-256-GCM encrypt subject + body + attachments (metadata bound as AAD)
  5. ML-DSA-65 sign the canonical envelope
  6. store/send only the encrypted envelope
  7. keep a *second* envelope for the sender's "Sent" folder, encrypted to the
     sender's own keys, so the sender can read what they sent

Opening:
  1. parse the envelope and validate every metadata field
  2. verify the ML-DSA-65 signature FIRST (fail closed) against the sender key
     whose fingerprint the envelope names (so mail sent before the sender
     rotated keys still verifies)
  3. only then decapsulate / derive / AES-GCM-open (current keys first, then
     retired keys kept from earlier rotations)

Receiving from a real mailbox additionally enforces replay protection: a
message id that a mailbox has ever received (even if deleted) is not imported
again, and very old envelopes are refused.

Nothing in this module ever stores or logs plaintext.
"""
from __future__ import annotations

import base64
import json
import secrets
import uuid
from dataclasses import dataclass, field

from app import config as cfg
from app import db as database
from app.crypto import encryption, fingerprints, hybrid, pqc
from app.crypto.key_manager import IdentityKeys
from app.email import message_format
from app.email.message_format import Attachment
from app.log import event

SUBJECT_HINT = "🔐 Encrypted message"


class MailServiceError(Exception):
    """User-facing mail flow error (message is safe to display)."""


@dataclass
class SendResult:
    message_id: str
    recipient: str
    delivered_via: str          # "local-demo-mailbox" | "smtp"
    kem_ciphertext_len: int
    signature_len: int
    hybrid: bool = True         # False: recipient only has legacy (ML-KEM-only) keys
    attachment_count: int = 0


@dataclass
class AttachmentInfo:
    index: int
    name: str
    content_type: str
    size: int


@dataclass
class OpenResult:
    subject: str
    body: str
    sender: str
    recipient: str
    timestamp: str
    sender_fingerprint: str
    signature_valid: bool
    integrity_valid: bool
    tampered_demo: bool
    algorithms: dict
    sender_key_current: bool = True   # False: sender has rotated keys since sending
    sender_key_known: bool = True     # False: no directory key matches the envelope
    attachments: list[AttachmentInfo] = field(default_factory=list)
    envelope_version: str = cfg.ENVELOPE_VERSION_V1

    @property
    def trusted(self) -> bool:
        return self.signature_valid and self.integrity_valid


@dataclass
class Preview:
    """What a list view may show about a message (verified, in RAM only)."""
    subject: str
    attachment_count: int = 0


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def _new_message_id() -> str:
    return f"pqmail-{uuid.uuid4().hex}"


def encrypt_and_sign(*, sender_email: str, recipient_email: str, subject: str,
                     body: str, sender_keys: IdentityKeys,
                     recipient_public_b64: str, recipient_x25519_b64: str | None = None,
                     attachments: list[Attachment] | None = None,
                     message_id: str | None = None) -> dict:
    """Build the fully encrypted + signed envelope (no plaintext inside).

    With ``recipient_x25519_b64`` the key exchange is hybrid (envelope v2);
    without it, ML-KEM-768 only (envelope v1, for legacy keys).
    """
    try:
        recipient_kem_pub = pqc.load_kem_public_key(base64.b64decode(recipient_public_b64))
        recipient_x_pub = (pqc.load_x25519_public_key(base64.b64decode(recipient_x25519_b64))
                           if recipient_x25519_b64 else None)
    except Exception as exc:  # noqa: BLE001
        raise MailServiceError("Recipient's public key is invalid or corrupted.") from exc

    use_hybrid = recipient_x_pub is not None
    version = cfg.ENVELOPE_VERSION_V2 if use_hybrid else cfg.ENVELOPE_VERSION_V1
    salt = secrets.token_bytes(16)   # fresh randomness per message: HKDF salt + AES-GCM nonce

    meta = {
        "version": version,
        "algorithm": message_format.expected_algorithms(version),
        "sender": sender_email.lower().strip(),
        "recipient": recipient_email.lower().strip(),
        "timestamp": message_format.utc_now_iso(),
        "message_id": message_id or _new_message_id(),
        "sender_key_fingerprint": fingerprints.public_key_fingerprint(sender_keys.dsa_public_bytes),
    }

    # 1) key establishment -> 2) HKDF -> 3) AES-256-GCM (metadata as AAD).
    if use_hybrid:
        shared, kem_ct, eph_pub = hybrid.hybrid_encapsulate(recipient_kem_pub, recipient_x_pub)
        meta["x25519_ephemeral"] = _b64(eph_pub)
    else:
        shared, kem_ct = pqc.encapsulate(recipient_kem_pub)
    aes_key = encryption.hkdf_derive(shared, salt)
    try:
        payload_json = message_format.build_payload(subject, body, attachments).encode("utf-8")
    except message_format.EnvelopeFormatError as exc:
        raise MailServiceError(str(exc)) from exc

    # The nonce is drawn up-front so the AAD can cover the final metadata
    # values (everything except the ciphertext and the signature itself).
    nonce = secrets.token_bytes(cfg.AES_NONCE_BYTES)
    envelope = {**meta, "kem_ciphertext": _b64(kem_ct), "salt": _b64(salt), "nonce": _b64(nonce)}
    used_nonce, sealed = encryption.aead_encrypt(
        aes_key, payload_json, aad=message_format.aad_bytes({**envelope, "ciphertext": ""}),
        nonce=nonce)
    if used_nonce != nonce:  # defence in depth: never encrypt under a stale nonce
        raise RuntimeError("Nonce mismatch during encryption (internal error).")
    envelope["ciphertext"] = _b64(sealed)
    # 4) ML-DSA-65 signature over the canonical envelope bytes.
    envelope["signature"] = _b64(
        pqc.sign(sender_keys.dsa.private_key, message_format.canonical_envelope_bytes(envelope))
    )
    event("Email encryption successful", message_id=envelope["message_id"],
          recipient=envelope["recipient"], suite=envelope["algorithm"]["kem"])
    return envelope


def _resolve_recipient_key(db: database.Database, recipient_email: str) -> dict:
    row = db.get_active_public_key(recipient_email)
    if row is None:
        raise MailServiceError(
            f"No registered public key for {recipient_email}. "
            "Ask the recipient to publish their quantum-safe keys first "
            "(or import their public key bundle on the Contacts page)."
        )
    return {"kem_public_b64": row["kem_public_b64"],
            "sig_public_b64": row["sig_public_b64"],
            "x25519_public_b64": row["x25519_public_b64"],
            "fingerprint": row["fingerprint"]}


def send_email(*, sender_email: str, recipient_email: str, subject: str, body: str,
               sender_keys: IdentityKeys, db: database.Database | None = None,
               use_real_smtp: bool = False,
               attachments: list[Attachment] | None = None) -> SendResult:
    """Full send flow: encrypt -> sign -> deliver (demo mailbox or SMTP)."""
    db = db or database.get_db()
    subject = (subject or "").strip()
    body = body or ""
    attachments = list(attachments or [])
    recipient_email = cfg.normalize_email(recipient_email)
    if not cfg.is_valid_email(recipient_email):
        raise MailServiceError("Please provide a valid recipient address.")
    if len(subject) > cfg.MAX_SUBJECT_LEN:
        raise MailServiceError("Subject is too long.")
    if len(body) > cfg.MAX_BODY_LEN:
        raise MailServiceError("Message body is too long.")
    try:
        message_format.check_attachments(attachments)
    except message_format.EnvelopeFormatError as exc:
        raise MailServiceError(str(exc)) from exc

    recipient_key = _resolve_recipient_key(db, recipient_email)
    envelope = encrypt_and_sign(
        sender_email=sender_email,
        recipient_email=recipient_email,
        subject=subject,
        body=body,
        sender_keys=sender_keys,
        recipient_public_b64=recipient_key["kem_public_b64"],
        recipient_x25519_b64=recipient_key["x25519_public_b64"],
        attachments=attachments,
    )
    # The recipient's envelope is encrypted to the recipient only; the sender's
    # own copy is a separate envelope encrypted to the SENDER's keys.
    sent_copy = encrypt_and_sign(
        sender_email=sender_email,
        recipient_email=recipient_email,
        subject=subject,
        body=body,
        sender_keys=sender_keys,
        recipient_public_b64=_b64(sender_keys.kem_public_bytes),
        recipient_x25519_b64=_b64(sender_keys.x25519_public_bytes) if sender_keys.x25519 else None,
        attachments=attachments,
    )

    delivered_via = "local-demo-mailbox"
    if use_real_smtp:
        from app.email.smtp_client import send_envelope_via_smtp  # local import: optional path

        send_envelope_via_smtp(envelope)
        delivered_via = "smtp"
    else:
        # Demo mode: deliver a copy into the recipient's local mailbox. Content
        # is ciphertext only; the stored "hint" is deliberately NOT the subject,
        # so the mailbox database never contains message plaintext (PS §20).
        db.store_envelope(
            message_id=envelope["message_id"], sender=sender_email,
            recipient=recipient_email, subject_hint=SUBJECT_HINT,
            sender_fingerprint=envelope["sender_key_fingerprint"],
            envelope=envelope, folder="inbox",
        )

    db.store_envelope(
        message_id=sent_copy["message_id"], sender=sender_email,
        recipient=recipient_email, subject_hint=SUBJECT_HINT,
        sender_fingerprint=sent_copy["sender_key_fingerprint"],
        envelope=sent_copy, folder="sent",
    )
    event("Message sent", message_id=envelope["message_id"],
          recipient=recipient_email, transport=delivered_via)
    return SendResult(
        message_id=envelope["message_id"],
        recipient=recipient_email,
        delivered_via=delivered_via,
        kem_ciphertext_len=len(base64.b64decode(envelope["kem_ciphertext"])),
        signature_len=len(base64.b64decode(envelope["signature"])),
        hybrid=envelope["version"] == cfg.ENVELOPE_VERSION_V2,
        attachment_count=len(attachments),
    )


def _sender_key_for(db: database.Database, envelope: dict):
    """The sender's directory key named by the envelope fingerprint.

    Returns ``(public_key | None, is_current_key)``. The lookup is restricted to
    keys registered for the *claimed sender address*, so a forged fingerprint
    cannot select someone else's key.
    """
    sender = envelope["sender"]
    row = db.get_public_key_by_fingerprint(sender, envelope["sender_key_fingerprint"])
    if row is None:
        return None, False
    try:
        key = pqc.load_dsa_public_key(base64.b64decode(row["sig_public_b64"]))
    except Exception:  # noqa: BLE001 - corrupt directory entry
        return None, False
    active = db.get_active_public_key(sender)
    return key, bool(active and active["fingerprint"] == row["fingerprint"])


def _decrypt_payload(envelope: dict, owner_keys: IdentityKeys, message_id: str):
    """Try the current keys, then retired ones. Returns a Payload or None (integrity failure)."""
    is_v2 = envelope["version"] == cfg.ENVELOPE_VERSION_V2
    kem_ct = base64.b64decode(envelope["kem_ciphertext"])
    eph_pub = base64.b64decode(envelope["x25519_ephemeral"]) if is_v2 else b""
    salt = base64.b64decode(envelope["salt"])
    nonce = base64.b64decode(envelope["nonce"])
    sealed = base64.b64decode(envelope["ciphertext"])
    aad = message_format.aad_bytes(envelope)

    candidates = [(owner_keys.kem, owner_keys.x25519)]
    candidates += list(zip(owner_keys.previous_kems, owner_keys.previous_x25519
                           + [None] * (len(owner_keys.previous_kems) - len(owner_keys.previous_x25519))))
    for kem_pair, x_pair in candidates:
        try:
            if is_v2:
                if x_pair is None:
                    continue          # a key set that predates hybrid cannot open v2 mail
                shared = hybrid.hybrid_decapsulate(kem_pair.private_key, x_pair.private_key,
                                                   kem_ct, eph_pub)
            else:
                shared = pqc.decapsulate(kem_pair.private_key, kem_ct)
            aes_key = encryption.hkdf_derive(shared, salt)
            plaintext = encryption.aead_decrypt(aes_key, nonce, sealed, aad=aad)
            return message_format.parse_payload(plaintext)
        except encryption.TamperError:
            continue                  # wrong key (older rotation) or modified data
        except pqc.DecapsulationError as exc:
            event("Decapsulation failed (malformed key-establishment data)", message_id=message_id)
            raise MailServiceError("The message's key-establishment data is malformed.") from exc
        except message_format.EnvelopeFormatError:
            event("Decrypted payload malformed", message_id=message_id)
            return None
        except Exception:  # noqa: BLE001 - never leak internals
            event("Decryption failed", message_id=message_id)
            return None
    return None


def _open_row(row, owner_email: str, owner_keys: IdentityKeys,
              db: database.Database, mark_read: bool):
    """Verify + decrypt one stored row. Returns ``(OpenResult, Payload | None)``."""
    owner = owner_email.lower().strip()
    message_id = row["message_id"]
    if row["folder"] == "sent" and message_id.endswith(":sent"):
        raise MailServiceError(
            "This sent copy was created by an older PQMail version that encrypted it "
            "only to the recipient, so it cannot be opened here."
        )
    try:
        envelope = json.loads(row["envelope_json"])
        message_format.validate_envelope(envelope)
    except (message_format.EnvelopeFormatError, ValueError) as exc:
        event("Envelope validation failed", message_id=message_id)
        raise MailServiceError(f"Malformed message envelope: {exc}") from exc

    # The envelope must belong in this mailbox: inbox mail is addressed to the
    # owner, sent mail was sent by the owner.
    if row["folder"] == "inbox" and envelope["recipient"] != owner:
        raise MailServiceError("This message is not addressed to you.")
    if row["folder"] == "sent" and envelope["sender"] != owner:
        raise MailServiceError("This message was not sent by you.")

    # 1) Signature verification FIRST — never trust before verify.
    sender_pub, sender_key_current = _sender_key_for(db, envelope)
    sender_key_known = sender_pub is not None
    signature_valid = False
    if sender_pub is not None:
        signature_valid = pqc.verify(
            sender_pub,
            base64.b64decode(envelope["signature"]),
            message_format.canonical_envelope_bytes(envelope),
        )
    if not signature_valid:
        event("Signature verification failed", message_id=message_id)

    # 2) Integrity check. The plaintext is NEVER displayed unless BOTH the
    #    signature and the AES-GCM tag verify (fail-closed gating below);
    #    running the AEAD open here only gathers diagnostics for the UI.
    payload = _decrypt_payload(envelope, owner_keys, message_id)
    integrity_valid = payload is not None
    if not integrity_valid:
        event("Message integrity check failed", message_id=message_id)

    # 3) Fail-closed content gating: withhold everything unless both checks pass.
    trusted = signature_valid and integrity_valid
    if not trusted:
        payload = None

    if mark_read:
        db.mark_read(message_id, owner_email)
    attachments = [AttachmentInfo(i, a.name, a.content_type, a.size)
                   for i, a in enumerate(payload.attachments)] if payload else []
    result = OpenResult(
        subject=(payload.subject or "(no subject)") if payload else "(content withheld)",
        body=payload.body if payload else "",
        sender=envelope["sender"],
        recipient=envelope["recipient"],
        timestamp=envelope["timestamp"],
        sender_fingerprint=envelope["sender_key_fingerprint"],
        signature_valid=signature_valid,
        integrity_valid=integrity_valid,
        tampered_demo=bool(row["tampered_demo"]),
        algorithms=envelope["algorithm"],
        sender_key_current=sender_key_current,
        sender_key_known=sender_key_known,
        attachments=attachments,
        envelope_version=envelope["version"],
    )
    return result, payload


def open_email(*, message_id: str, owner_email: str,
               owner_keys: IdentityKeys, db: database.Database | None = None) -> OpenResult:
    """Parse, verify, decrypt and return one message (fail-closed order)."""
    db = db or database.get_db()
    row = db.get_envelope(message_id, owner_email)
    if row is None:
        raise MailServiceError("Message not found in this mailbox.")
    return _open_row(row, owner_email, owner_keys, db, mark_read=True)[0]


def get_attachment(*, message_id: str, owner_email: str, owner_keys: IdentityKeys,
                   index: int, db: database.Database | None = None) -> Attachment:
    """Return one decrypted attachment of a *trusted* message."""
    db = db or database.get_db()
    row = db.get_envelope(message_id, owner_email)
    if row is None:
        raise MailServiceError("Message not found in this mailbox.")
    result, payload = _open_row(row, owner_email, owner_keys, db, mark_read=False)
    if not result.trusted or payload is None:
        raise MailServiceError("This message failed verification; its attachments are withheld.")
    if not 0 <= index < len(payload.attachments):
        raise MailServiceError("Attachment not found.")
    return payload.attachments[index]


def preview_subject(row, owner_email: str, owner_keys: IdentityKeys,
                    db: database.Database | None = None) -> Preview | None:
    """Verified subject line (+ attachment count) for list views, or None when the
    message cannot be trusted/opened. Works in RAM only: nothing is stored and the
    message is not marked as read."""
    db = db or database.get_db()
    try:
        result, _payload = _open_row(row, owner_email, owner_keys, db, mark_read=False)
    except MailServiceError:
        return None
    return Preview(result.subject, len(result.attachments)) if result.trusted else None


# ---------------------------------------------------------------------------
# Reply / forward drafts
# ---------------------------------------------------------------------------
def _prefixed(subject: str, prefix: str) -> str:
    stripped = subject.strip()
    if stripped.lower().startswith(prefix.lower()):
        return stripped
    return f"{prefix} {stripped}".strip()[: cfg.MAX_SUBJECT_LEN]


def _quote(text: str) -> str:
    return "\n".join(("> " + line) if line else ">" for line in text.splitlines())


def build_draft(opened: OpenResult, owner_email: str, mode: str) -> dict[str, str]:
    """Compose-form defaults for replying to / forwarding a verified message."""
    if not opened.trusted:
        raise MailServiceError("Only verified messages can be replied to or forwarded.")
    owner = owner_email.lower().strip()
    if mode == "reply":
        to = opened.recipient if opened.sender == owner else opened.sender
        subject = _prefixed(opened.subject, "Re:")
        body = f"\n\nOn {opened.timestamp}, {opened.sender} wrote:\n{_quote(opened.body)}\n"
    elif mode == "forward":
        to = ""
        subject = _prefixed(opened.subject, "Fwd:")
        body = (f"\n\n---------- Forwarded message ----------\nFrom: {opened.sender}\n"
                f"To: {opened.recipient}\nDate: {opened.timestamp}\nSubject: {opened.subject}\n\n"
                f"{opened.body}\n")
        if opened.attachments:
            body += (f"\n[{len(opened.attachments)} attachment(s) were not forwarded: "
                     "re-attach them if needed.]\n")
    else:
        raise MailServiceError("Unknown draft type.")
    return {"to": to, "subject": subject, "body": body[: cfg.MAX_BODY_LEN]}


def simulate_tampering(message_id: str, owner_email: str,
                       db: database.Database | None = None) -> str:
    """Flip one bit inside the stored ciphertext for the tamper demo.

    The envelope stays structurally valid, but AES-GCM authentication and
    the ML-DSA signature will both fail when the message is opened.
    """
    db = db or database.get_db()
    row = db.get_envelope(message_id, owner_email)
    if row is None:
        raise MailServiceError("Message not found in this mailbox.")
    envelope = json.loads(row["envelope_json"])
    tampered = message_format.tamper_ciphertext(envelope)
    if not db.update_envelope(message_id, owner_email, tampered, tampered_demo=True):
        raise MailServiceError("Message not found in this mailbox.")
    event("Tamper simulation applied", message_id=message_id)
    return "Ciphertext modified for the demonstration."


# ---------------------------------------------------------------------------
# Receiving mail from a real IMAP mailbox (Real Email Mode)
# ---------------------------------------------------------------------------
def import_envelope(envelope: dict, owner_email: str,
                    db: database.Database | None = None) -> str:
    """Store a received envelope in ``owner_email``'s inbox.

    Returns ``"imported"``, ``"duplicate"``, or ``"skipped: <reason>"``. Nothing
    is trusted here - signature and integrity are verified when the message is
    opened, exactly like locally delivered mail. Replay defences: a message id the
    mailbox has ever received (even if since deleted) is refused, as are envelopes
    older than ``MAX_ENVELOPE_AGE_DAYS``.
    """
    db = db or database.get_db()
    owner = owner_email.lower().strip()
    try:
        message_format.validate_envelope(envelope)
    except message_format.EnvelopeFormatError as exc:
        return f"skipped: invalid envelope ({exc})"
    if envelope["recipient"] != owner:
        return "skipped: addressed to someone else"
    if db.get_user(envelope["sender"]) is None:
        return "skipped: unknown sender (import their public key first)"
    if db.has_envelope(envelope["message_id"]):
        return "duplicate"
    if db.ledger_has(owner, envelope["message_id"]):
        event("Replay refused", message_id=envelope["message_id"], recipient=owner)
        return "skipped: replay (this message was already received and deleted)"
    if message_format.envelope_age_days(envelope) > cfg.MAX_ENVELOPE_AGE_DAYS:
        return f"skipped: too old (more than {cfg.MAX_ENVELOPE_AGE_DAYS} days)"
    db.store_envelope(
        message_id=envelope["message_id"], sender=envelope["sender"], recipient=owner,
        subject_hint=SUBJECT_HINT, sender_fingerprint=envelope["sender_key_fingerprint"],
        envelope=envelope, folder="inbox",
    )
    event("Envelope imported from IMAP", message_id=envelope["message_id"], recipient=owner)
    return "imported"


def fetch_real_inbox(owner_email: str, db: database.Database | None = None) -> dict[str, int]:
    """Pull envelopes from the configured IMAP mailbox into ``owner_email``'s inbox."""
    from app.email.imap_client import fetch_envelopes  # local import: optional path

    db = db or database.get_db()
    counts = {"imported": 0, "duplicate": 0, "skipped": 0, "replay": 0}
    for envelope in fetch_envelopes():
        outcome = import_envelope(envelope, owner_email, db)
        if outcome.startswith("skipped: replay"):
            counts["replay"] += 1
        elif outcome.startswith("skipped"):
            counts["skipped"] += 1
        else:
            counts[outcome] += 1
    return counts
