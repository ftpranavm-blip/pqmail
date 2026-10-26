"""Encrypted envelope format, canonicalisation and validation.

Envelope layout (JSON), version 2.0 (hybrid X25519 + ML-KEM-768)::

    {
      "version": "2.0",
      "algorithm": {"kem": "X25519+ML-KEM-768", "signature": "ML-DSA-65",
                    "symmetric": "AES-256-GCM", "kdf": "HKDF-SHA-256"},
      "sender": "alice@pqmail.local",
      "recipient": "bob@pqmail.local",
      "timestamp": "2026-09-08T12:00:00+00:00",
      "message_id": "pqmail-<32 hex>",
      "kem_ciphertext": "<b64 ML-KEM ciphertext>",
      "x25519_ephemeral": "<b64 sender's ephemeral X25519 public key>",
      "salt": "<b64 HKDF salt>",
      "nonce": "<b64 AES-GCM nonce>",
      "ciphertext": "<b64 AES-GCM sealed subject + body + attachments>",
      "sender_key_fingerprint": "XXXX XXXX ...",
      "signature": "<b64 ML-DSA-65 signature over canonical bytes>"
    }

Version 1.0 (ML-KEM-768 only, no ``x25519_ephemeral``, ``kem`` = "ML-KEM-768")
is still accepted so older mail can be read and legacy contacts can be written to.

Binary values are base64. The signature covers the canonical JSON of every
field above **except** ``signature`` itself. The AES-GCM associated data
(AAD) binds the same metadata to the ciphertext, so swapping fields between
envelopes breaks both the signature and the AEAD. Unknown extra fields are
rejected: they would be neither signed nor authenticated.

The encrypted payload is JSON: ``{"subject", "body", "attachments": [...]}``.
"""
from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

from app import config as cfg

_V1_FIELDS = (
    "version", "algorithm", "sender", "recipient", "timestamp", "message_id",
    "kem_ciphertext", "salt", "nonce", "ciphertext", "sender_key_fingerprint",
)
_V2_FIELDS = _V1_FIELDS + ("x25519_ephemeral",)
_FIELDS_BY_VERSION = {cfg.ENVELOPE_VERSION_V1: _V1_FIELDS, cfg.ENVELOPE_VERSION_V2: _V2_FIELDS}

_MESSAGE_ID_RE = re.compile(r"^pqmail-[0-9a-f]{32}$")
_MAX_ENVELOPE_FIELD_LEN = 8 * 1024 * 1024  # generous cap on any single base64 field


class EnvelopeFormatError(Exception):
    """Envelope structure or metadata is invalid."""


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def signed_fields(version: object) -> tuple[str, ...]:
    try:
        return _FIELDS_BY_VERSION[version]  # type: ignore[index]
    except (KeyError, TypeError) as exc:
        raise EnvelopeFormatError(f"Unsupported envelope version: {version!r}") from exc


def expected_algorithms(version: str) -> dict[str, str]:
    return {
        "kem": cfg.HYBRID_KEM_ALGORITHM if version == cfg.ENVELOPE_VERSION_V2 else cfg.KEM_ALGORITHM,
        "signature": cfg.SIG_ALGORITHM,
        "symmetric": cfg.AEAD_ALGORITHM,
        "kdf": cfg.KDF_ALGORITHM,
    }


def canonical_envelope_bytes(envelope: dict) -> bytes:
    """Deterministic JSON encoding of all signed fields (sorted keys)."""
    canonical = {key: envelope[key] for key in signed_fields(envelope.get("version"))}
    return json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")


def aad_bytes(envelope: dict) -> bytes:
    """AES-GCM associated data: binds ciphertext to its metadata.

    Covers every envelope field that exists before encryption (all signed
    fields except the ciphertext itself), so changing the sender, recipient,
    KEM data, salt or any other metadata invalidates decryption.
    """
    aad = {key: envelope[key] for key in signed_fields(envelope.get("version"))
           if key != "ciphertext"}
    return json.dumps(aad, sort_keys=True, separators=(",", ":")).encode("utf-8")


def validate_envelope(envelope: dict) -> None:
    """Validate structure and all received cryptographic metadata.

    Raises :class:`EnvelopeFormatError` on any inconsistency. This must run
    before signature verification so malformed input never reaches crypto.
    """
    if not isinstance(envelope, dict):
        raise EnvelopeFormatError("Envelope is not a JSON object.")
    version = envelope.get("version")
    fields = signed_fields(version)

    algo = envelope.get("algorithm")
    expected = expected_algorithms(version)
    if not isinstance(algo, dict) or algo != expected:
        raise EnvelopeFormatError("Unsupported algorithm suite (must be "
                                  f"{expected}).")

    unknown = set(envelope) - set(fields) - {"signature"}
    if unknown:
        raise EnvelopeFormatError(f"Unexpected envelope fields: {sorted(unknown)}")

    string_fields = tuple(f for f in fields if f != "algorithm")
    for name in (*string_fields, "signature"):
        value = envelope.get(name)
        if not isinstance(value, str) or not value:
            raise EnvelopeFormatError(f"Missing or invalid field: {name}")

    if not cfg.is_valid_email(envelope["sender"]) or not cfg.is_valid_email(envelope["recipient"]):
        raise EnvelopeFormatError("Sender/recipient must be valid email addresses.")
    if not _MESSAGE_ID_RE.match(envelope["message_id"]):
        raise EnvelopeFormatError("Invalid message id.")
    if any(len(envelope[f]) > _MAX_ENVELOPE_FIELD_LEN for f in string_fields):
        raise EnvelopeFormatError("Envelope field is too large.")

    # base64 fields must actually decode (and have the exact size where fixed)
    sizes = {
        "kem_ciphertext": 1088,   # ML-KEM-768 ciphertext (FIPS 203)
        "salt": 16,               # HKDF salt (see mail_service.encrypt_and_sign)
        "nonce": cfg.AES_NONCE_BYTES,
        "x25519_ephemeral": 32,   # raw X25519 public key (RFC 7748)
    }
    binary_fields = ["kem_ciphertext", "salt", "nonce", "ciphertext", "signature"]
    if version == cfg.ENVELOPE_VERSION_V2:
        binary_fields.append("x25519_ephemeral")
    for name in binary_fields:
        try:
            decoded = base64.b64decode(envelope[name], validate=True)
        except (binascii.Error, ValueError) as exc:
            raise EnvelopeFormatError(f"Field {name} is not valid base64.") from exc
        if not decoded:
            raise EnvelopeFormatError(f"Field {name} is empty.")
        if name in sizes and len(decoded) != sizes[name]:
            raise EnvelopeFormatError(
                f"Field {name} has wrong length ({len(decoded)} != {sizes[name]})."
            )

    # timestamp sanity: must carry a timezone (an offset-naive value cannot be
    # compared with the clock) and may not be > 1 day in the future.
    try:
        ts = datetime.fromisoformat(envelope["timestamp"])
    except ValueError as exc:
        raise EnvelopeFormatError("Invalid timestamp.") from exc
    if ts.tzinfo is None or ts.utcoffset() is None:
        raise EnvelopeFormatError("Timestamp must include a timezone.")
    if (ts - datetime.now(timezone.utc)).total_seconds() > 86400:
        raise EnvelopeFormatError("Timestamp is too far in the future.")


def envelope_age_days(envelope: dict) -> float:
    """Age of a validated envelope in days (negative for slightly-future stamps)."""
    ts = datetime.fromisoformat(envelope["timestamp"])
    return (datetime.now(timezone.utc) - ts).total_seconds() / 86400


# ---------------------------------------------------------------------------
# Encrypted payload (subject + body + attachments)
# ---------------------------------------------------------------------------
@dataclass
class Attachment:
    name: str
    content_type: str
    data: bytes

    @property
    def size(self) -> int:
        return len(self.data)


@dataclass
class Payload:
    subject: str
    body: str
    attachments: list[Attachment] = field(default_factory=list)


_FILENAME_BAD = re.compile(r'[\x00-\x1f\x7f<>:"/\\|?*]+')


def safe_filename(name: str | None) -> str:
    """Reduce an uploaded file name to a harmless display/download name."""
    name = (name or "").replace("\\", "/").rsplit("/", 1)[-1]
    name = _FILENAME_BAD.sub("_", name).strip(" .")
    limit = cfg.MAX_FILENAME_LEN
    if len(name) > limit:
        stem, dot, ext = name.rpartition(".")
        if dot and len(ext) < 20:
            name = stem[: max(1, limit - len(ext) - 1)] + "." + ext
        else:
            name = name[:limit]
    return name or "attachment"


def check_attachments(attachments: list[Attachment]) -> None:
    """Enforce count and size limits (raises :class:`EnvelopeFormatError`)."""
    if len(attachments) > cfg.MAX_ATTACHMENTS:
        raise EnvelopeFormatError(f"At most {cfg.MAX_ATTACHMENTS} attachments are allowed.")
    total = sum(a.size for a in attachments)
    if total > cfg.MAX_ATTACHMENT_TOTAL_BYTES:
        raise EnvelopeFormatError(
            f"Attachments are too large ({total // 1024} KiB; limit "
            f"{cfg.MAX_ATTACHMENT_TOTAL_BYTES // 1024} KiB in total).")


def build_payload(subject: str, body: str, attachments: list[Attachment] | None = None) -> str:
    """JSON payload encrypted inside the envelope (subject + body + attachments)."""
    data: dict = {"subject": subject, "body": body}
    if attachments:
        check_attachments(attachments)
        data["attachments"] = [
            {"name": safe_filename(a.name), "type": a.content_type or "application/octet-stream",
             "data_b64": base64.b64encode(a.data).decode()}
            for a in attachments
        ]
    return json.dumps(data, ensure_ascii=False)


def parse_payload(plaintext: bytes) -> Payload:
    """Parse the decrypted payload (tolerant of payloads without attachments)."""
    try:
        data = json.loads(plaintext.decode("utf-8"))
        subject, body = data["subject"], data["body"]
        if not isinstance(subject, str) or not isinstance(body, str):
            raise ValueError("subject/body must be text")
        attachments = []
        for item in data.get("attachments", []):
            attachments.append(Attachment(
                name=safe_filename(item["name"]),
                content_type=str(item.get("type") or "application/octet-stream")[:100],
                data=base64.b64decode(item["data_b64"], validate=True)))
        check_attachments(attachments)
    except EnvelopeFormatError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise EnvelopeFormatError("Decrypted payload is malformed.") from exc
    return Payload(subject, body, attachments)


def tamper_ciphertext(envelope: dict) -> dict:
    """Return a copy of the envelope with one flipped ciphertext bit.

    Demo helper for section 14 of the PS (tamper detection). Flipping a
    single bit must break AES-GCM authentication and the ML-DSA signature.
    """
    raw = bytearray(base64.b64decode(envelope["ciphertext"]))
    if not raw:
        raise EnvelopeFormatError("Nothing to tamper with.")
    raw[0] ^= 0x01  # flip one bit
    tampered = dict(envelope)
    tampered["ciphertext"] = base64.b64encode(bytes(raw)).decode()
    return tampered
