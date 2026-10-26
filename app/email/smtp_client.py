"""SMTP transport for Real Email Mode (optional).

Security notes
==============
* Uses SMTP_SSL (implicit TLS on port 465) or STARTTLS; plain unauthenticated
  SMTP is never attempted.
* The server certificate **is verified** (``ssl.create_default_context()``).
  Python's ``smtplib`` does not verify certificates unless it is given such a
  context, which would let a man-in-the-middle capture the mail password.
* This transport encryption protects the hop to the mail server. The
  end-to-end confidentiality of the message itself comes from the
  ML-KEM + AES-GCM envelope, which the server only ever sees in
  encrypted form. The visible ``Subject`` header is a constant label - the real
  subject is inside the encrypted payload and never leaves this machine in clear.
* Credentials come exclusively from environment variables (never code).
"""
from __future__ import annotations

import json
import smtplib
import ssl
from email.message import EmailMessage

from app import config as cfg
from app.log import event

PUBLIC_SUBJECT = "[PQMail] Encrypted message"


class SmtpError(Exception):
    """SMTP send failed (message is safe to show; no credentials inside)."""


def build_message(envelope: dict, from_address: str) -> EmailMessage:
    """MIME message carrying the encrypted envelope (no plaintext anywhere)."""
    msg = EmailMessage()
    msg["From"] = from_address
    msg["To"] = envelope["recipient"]
    msg["Subject"] = PUBLIC_SUBJECT
    msg.set_content(
        "This is an end-to-end encrypted PQMail message.\n"
        "Open the attached .pqmail.json envelope with PQMail to read it.\n"
        f"Message id: {envelope['message_id']}\n"
    )
    msg.add_attachment(
        json.dumps(envelope, indent=2).encode(),
        maintype="application",
        subtype="json",
        filename=f"{envelope['message_id']}.pqmail.json",
    )
    return msg


def send_envelope_via_smtp(envelope: dict, subject_hint: str | None = None) -> None:
    """Send the base64 envelope as a MIME message via configured SMTP.

    ``subject_hint`` is accepted for backwards compatibility and deliberately
    ignored: the plaintext subject must never appear in a mail header.
    """
    conf = cfg.smtp_config()
    if conf is None:
        raise SmtpError(
            "Real Email Mode is not configured. Set SMTP_HOST / SMTP_PORT / "
            "SMTP_USERNAME / SMTP_PASSWORD in your .env file."
        )
    msg = build_message(envelope, conf["username"])
    context = ssl.create_default_context()   # verifies certificate chain + hostname
    try:
        if conf["port"] == 465:
            server: smtplib.SMTP = smtplib.SMTP_SSL(
                conf["host"], conf["port"], timeout=20, context=context)
        else:
            server = smtplib.SMTP(conf["host"], conf["port"], timeout=20)
            server.ehlo()
            server.starttls(context=context)
            server.ehlo()
        with server:
            server.login(conf["username"], conf["password"])
            server.send_message(msg)
    except SmtpError:
        raise
    except Exception as exc:  # noqa: BLE001 - normalise; never leak creds
        event("SMTP send failed")
        raise SmtpError(
            f"SMTP send failed: {type(exc).__name__}. Check host/port/credentials."
        ) from exc
    event("Envelope sent via SMTP", message_id=envelope["message_id"],
          recipient=envelope["recipient"])
