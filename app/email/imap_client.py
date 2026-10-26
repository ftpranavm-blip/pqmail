"""IMAP transport for Real Email Mode (optional).

Fetches messages with a ``.pqmail.json`` attachment from the INBOX and
returns parsed envelopes ready for :func:`app.services.mail_service.import_envelope`.
Transport TLS (IMAPS) is separate from the end-to-end envelope encryption, and
the server certificate **is verified** (``ssl.create_default_context()``).
"""
from __future__ import annotations

import email as email_lib
import imaplib
import json
import ssl

from app import config as cfg
from app.log import event

MAX_ATTACHMENT_BYTES = 8 * 1024 * 1024


class ImapError(Exception):
    """IMAP fetch failed (message is safe to show; no credentials inside)."""


def extract_envelopes(raw_message: bytes) -> list[dict]:
    """Return every PQMail envelope attached to one RFC 822 message."""
    found: list[dict] = []
    parsed = email_lib.message_from_bytes(raw_message)
    for part in parsed.walk():
        filename = part.get_filename()
        if not filename or not filename.endswith(".pqmail.json"):
            continue
        payload = part.get_payload(decode=True)
        if not payload or len(payload) > MAX_ATTACHMENT_BYTES:
            continue
        try:
            envelope = json.loads(payload)
        except (json.JSONDecodeError, UnicodeDecodeError):
            event("Skipped malformed PQMail attachment")
            continue
        if isinstance(envelope, dict):
            found.append(envelope)
    return found


def fetch_envelopes(limit: int = 50) -> list[dict]:
    """Return up to ``limit`` PQMail envelopes found in the IMAP INBOX."""
    conf = cfg.imap_config()
    if conf is None:
        raise ImapError(
            "Real Email Mode is not configured. Set IMAP_HOST / IMAP_PORT / "
            "IMAP_USERNAME / IMAP_PASSWORD in your .env file."
        )
    context = ssl.create_default_context()   # verifies certificate chain + hostname
    results: list[dict] = []
    try:
        if conf["port"] == 993:
            client: imaplib.IMAP4 = imaplib.IMAP4_SSL(
                conf["host"], conf["port"], timeout=20, ssl_context=context)
        else:
            client = imaplib.IMAP4(conf["host"], conf["port"], timeout=20)
            client.starttls(ssl_context=context)
        with client:
            client.login(conf["username"], conf["password"])
            client.select("INBOX", readonly=True)
            status, data = client.search(None, "ALL")
            if status != "OK":
                raise ImapError("IMAP search failed.")
            ids = data[0].split()[-limit:]
            for mail_id in ids:
                status, msg_data = client.fetch(mail_id, "(RFC822)")
                if status != "OK" or not msg_data or msg_data[0] is None:
                    continue
                results.extend(extract_envelopes(msg_data[0][1]))
    except ImapError:
        raise
    except Exception as exc:  # noqa: BLE001 - normalise; never leak creds
        event("IMAP fetch failed")
        raise ImapError(
            f"IMAP fetch failed: {type(exc).__name__}. Check host/port/credentials."
        ) from exc
    event("IMAP fetch completed", count=len(results))
    return results
