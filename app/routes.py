"""HTTP routes (Flask blueprint) for PQMail.

Session model
=============
* ``session["user"]``       — the logged-in email address
* ``session["key_token"]``  — pointer to unlocked keys in RAM (TTL-limited)
* ``session["mode"]``       — "demo" or "real"
* ``session["_csrf"]``      — CSRF token (see :mod:`app.security`)

Private keys live only in the in-process cache (``app.session_keys``) and
are never placed in cookies, templates, static files or logs. A request counts
as logged in only while the unlocked keys are still cached; when they expire
the session is ended and the user is sent back to the sign-in page.
"""
from __future__ import annotations

import base64
from urllib.parse import urlparse

from flask import (Blueprint, Response, flash, redirect, render_template,
                   request, session, url_for)

from app import config as cfg
from app import db as database
from app import security, session_keys
from app.bootstrap import create_identity
from app.crypto import fingerprints
from app.crypto.key_manager import (WrongPassphraseError, load_identity,
                                    rotate_keys)
from app.email.imap_client import ImapError
from app.email.smtp_client import SmtpError
from app.i18n import gettext as _
from app.log import event
from app.qkd import bb84
from app.qkd.bb84 import QKDParameterError
from app.services import directory, mail_service
from app.storage.secure_storage import KeyStore, KeyStoreError

bp = Blueprint("pqmail", __name__)

MAX_QKD_BITS = cfg.BB84_MAX_BITS
MAX_LIST_PREVIEWS = 100   # mailbox rows whose subject is decrypted for the list view


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def current_keys():
    return session_keys.get(session.get("key_token"))


def require_login():
    """Return the signed-in user's email, or None (and end a stale session).

    A session whose unlocked keys have expired from RAM (15-minute idle TTL, or
    a server restart) is treated as signed out everywhere, not just on the
    pages that happen to need the keys.
    """
    user = session.get("user")
    if not user:
        return None
    if session.get("twofa_pending"):
        return None          # passphrase accepted, second factor still outstanding
    if current_keys() is None:
        session_keys.pop(session.get("key_token"))
        session.clear()
        flash(_("Your session expired - please sign in again to unlock your keys."), "warning")
        return None
    return user


def _login_redirect():
    if session.get("twofa_pending") and session.get("user"):
        return redirect(url_for("pqmail.login_2fa"))
    return redirect(url_for("pqmail.login_page"))


def _start_session(email: str, keys) -> None:
    lang = session.get("lang")
    session.clear()          # new session: no fixation, no stale CSRF token
    if lang:
        session["lang"] = lang
    session.permanent = True
    session["user"] = email
    session["mode"] = "demo"
    if keys.totp_enabled:
        session["twofa_pending"] = True
    session["key_token"] = session_keys.new_token()
    session_keys.store(session["key_token"], keys)


def login_user(email: str, passphrase: str | None, use_keyring: bool = False) -> bool:
    """Unlock the keystore and start a session. Never raises on bad input."""
    if not cfg.is_valid_email(email):
        return False
    # With demo mode off, leftover demo accounts (public passphrase!) must not work
    # either, even if their keystores still exist from an earlier demo run.
    row = database.get_db().get_user(email)
    if row is not None and row["is_demo"] and not cfg.DEMO_ENABLED:
        event("Login refused: demo accounts are disabled", user=email)
        return False
    try:
        keys = load_identity(cfg.KEYS_DIR, email, passphrase, use_keyring=use_keyring)
    except WrongPassphraseError:
        return False
    except Exception:  # noqa: BLE001 - keystore missing/corrupt/unexpected
        event("Login failed with an unexpected keystore error", user=email)
        return False
    _start_session(email, keys)
    directory.sync_own_keys(database.get_db(), keys)   # e.g. attach a new hybrid key to the directory
    event("Session unlocked", user=email)
    return True


def logout_user() -> None:
    session_keys.pop(session.get("key_token"))
    session.clear()


def _safe_back(default_endpoint: str):
    """Redirect target taken from the Referer, but only if it is on this host."""
    ref = request.referrer
    if ref:
        parsed = urlparse(ref)
        if parsed.netloc == request.host and parsed.path.startswith("/") and not parsed.path.startswith("//"):
            return redirect(parsed.path)
    return redirect(url_for(default_endpoint))


def _fail_login(email: str):
    security.login_failed(email, request.remote_addr)
    event("Login failed", user=email)
    flash(_("Login failed: wrong passphrase or unknown identity."), "danger")
    return _login_redirect()


def _throttled_login(email: str, passphrase: str | None, use_keyring: bool):
    wait = security.login_lockout_seconds(email, request.remote_addr)
    if wait:
        event("Login blocked by throttle", user=email)
        flash(_("Too many failed attempts. Try again in %(s)s seconds.", s=wait), "danger")
        return _login_redirect()
    if login_user(email, passphrase, use_keyring=use_keyring):
        security.login_succeeded(email)
        if session.get("twofa_pending"):
            return redirect(url_for("pqmail.login_2fa"))
        flash(_("Welcome back, %(email)s!", email=email), "success")
        return redirect(url_for("pqmail.dashboard"))
    return _fail_login(email)


# ---------------------------------------------------------------------------
# Auth / registration
# ---------------------------------------------------------------------------
@bp.get("/")
def index():
    if require_login():
        return redirect(url_for("pqmail.dashboard"))
    return render_template("index.html", demo_users=cfg.DEMO_USERS)


@bp.get("/login")
def login_page():
    return render_template("login.html", demo_users=cfg.DEMO_USERS)


@bp.post("/login")
def login_submit():
    email = cfg.normalize_email(request.form.get("email"))
    passphrase = request.form.get("passphrase") or ""
    if not email or not passphrase:
        flash(_("Please enter your email and passphrase."), "warning")
        return _login_redirect()
    return _throttled_login(email, passphrase, use_keyring=False)


@bp.post("/login/keyring")
def login_keyring():
    """Sign in with the OS keyring instead of the passphrase (if enrolled)."""
    email = cfg.normalize_email(request.form.get("email"))
    if not email:
        flash(_("Please enter your email address."), "warning")
        return _login_redirect()
    return _throttled_login(email, None, use_keyring=True)


@bp.post("/logout")
def logout():
    logout_user()
    flash(_("You have been signed out. Unlocked keys were erased from memory."), "info")
    return redirect(url_for("pqmail.index"))


@bp.get("/register")
def register_page():
    return render_template("register.html")


@bp.post("/register")
def register_submit():
    email = cfg.normalize_email(request.form.get("email"))
    display_name = request.form.get("display_name") or ""
    passphrase = request.form.get("passphrase") or ""
    confirm = request.form.get("confirm") or ""
    if passphrase != confirm:
        flash(_("Passphrases do not match."), "danger")
        return redirect(url_for("pqmail.register_page"))
    try:
        create_identity(email, display_name, passphrase)
    except ValueError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("pqmail.register_page"))
    except Exception:  # noqa: BLE001 - storage failure
        event("Identity registration failed")
        flash(_("Could not create the identity (storage error)."), "danger")
        return redirect(url_for("pqmail.register_page"))
    flash(_("Identity created. Your quantum-safe keys are ready."), "success")
    return redirect(url_for("pqmail.login_page"))


@bp.post("/mode")
def set_mode():
    if not require_login():
        return _login_redirect()
    wants_real = request.form.get("mode", "demo") == "real"
    if wants_real and cfg.smtp_config() is None:
        flash(_("Real Email Mode needs SMTP_* settings (and IMAP_* to receive) in your .env file "
                "(see Settings). Staying in Demo Mode."), "warning")
        session["mode"] = "demo"
        return redirect(url_for("pqmail.settings_page"))
    session["mode"] = "real" if wants_real else "demo"
    flash(_("Switched to Real Email Mode.") if wants_real else _("Switched to Demo Mode."), "info")
    return _safe_back("pqmail.dashboard")


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------
@bp.get("/dashboard")
def dashboard():
    user = require_login()
    if not user:
        return _login_redirect()
    db = database.get_db()
    stats = db.stats(user)
    keys = current_keys()
    keystore_info = None
    if keys:
        keystore_info = {
            "created_at": keys.created_at,
            "kem_fingerprint": fingerprints.public_key_fingerprint(keys.kem_public_bytes),
            "sig_fingerprint": fingerprints.public_key_fingerprint(keys.dsa_public_bytes),
        }
    key_status = directory.sync_own_keys(db, keys) if keys else "ok"
    return render_template("dashboard.html", stats=stats, keystore_info=keystore_info,
                           mode=session.get("mode", "demo"), key_status=key_status)


# ---------------------------------------------------------------------------
# Mailbox
# ---------------------------------------------------------------------------
def _load_envelope(row):
    import json
    try:
        data = json.loads(row["envelope_json"])
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def _page_number() -> int:
    try:
        return max(1, int(request.args.get("page", "1")))
    except ValueError:
        return 1


def _mailbox_items(user: str, folder: str, *, trashed: bool = False, unread_only: bool = False,
                   page: int = 1):
    """One page of inbox/sent rows with verified, in-RAM-only subject lines.

    Returns ``(items, total_count, total_pages)``.
    """
    db = database.get_db()
    keys = current_keys()
    total = db.count_envelopes(user, folder, trashed=trashed, unread_only=unread_only)
    pages = max(1, -(-total // cfg.PAGE_SIZE))
    page = min(page, pages)
    rows = db.list_envelopes(user, folder, trashed=trashed, unread_only=unread_only,
                             limit=cfg.PAGE_SIZE, offset=(page - 1) * cfg.PAGE_SIZE)
    items = []
    for row in rows:
        envelope = _load_envelope(row)
        if envelope is None:
            continue
        preview = mail_service.preview_subject(row, user, keys, db) if keys is not None else None
        items.append({
            "message_id": row["message_id"],
            "folder": row["folder"],
            "subject": preview.subject if preview else None,
            "attachments": preview.attachment_count if preview else 0,
            "timestamp": envelope.get("timestamp", "?"),
            "tampered_demo": bool(row["tampered_demo"]),
            "sender": envelope.get("sender", "?"),
            "recipient": envelope.get("recipient", "?"),
            "read": bool(row["read"]),
            "hybrid": envelope.get("version") == cfg.ENVELOPE_VERSION_V2,
        })
    return items, total, pages, page


@bp.get("/inbox")
def inbox():
    user = require_login()
    if not user:
        return _login_redirect()
    unread_only = request.args.get("filter") == "unread"
    items, total, pages, page = _mailbox_items(user, "inbox", unread_only=unread_only,
                                               page=_page_number())
    return render_template("inbox.html", items=items, total=total, pages=pages, page=page,
                           unread_only=unread_only, mode=session.get("mode", "demo"))


@bp.post("/inbox/fetch")
def inbox_fetch():
    """Real Email Mode: pull encrypted envelopes from the IMAP mailbox."""
    user = require_login()
    if not user:
        return _login_redirect()
    if session.get("mode") != "real":
        flash(_("Switch to Real Email Mode (Settings) to fetch mail from IMAP."), "warning")
        return redirect(url_for("pqmail.inbox"))
    try:
        counts = mail_service.fetch_real_inbox(user)
    except ImapError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("pqmail.inbox"))
    except Exception:  # noqa: BLE001
        event("IMAP fetch failed unexpectedly")
        flash(_("Fetching mail failed (transport error)."), "danger")
        return redirect(url_for("pqmail.inbox"))
    flash(_("Fetched from IMAP: %(new)s new, %(dup)s already here, %(rep)s replayed copies refused, "
            "%(skip)s skipped (not for you / unknown sender / invalid / too old).",
            new=counts["imported"], dup=counts["duplicate"], rep=counts["replay"], skip=counts["skipped"]),
          "success" if counts["imported"] else "info")
    return redirect(url_for("pqmail.inbox"))


@bp.get("/sent")
def sent():
    user = require_login()
    if not user:
        return _login_redirect()
    items, total, pages, page = _mailbox_items(user, "sent", page=_page_number())
    return render_template("sent.html", items=items, total=total, pages=pages, page=page)


def _compose_context(**extra):
    user = session.get("user")
    ctx = {"contacts": database.get_db().list_contacts(user),
           "mode": session.get("mode", "demo"),
           "draft": {"to": "", "subject": "", "body": ""},
           "max_attachments": cfg.MAX_ATTACHMENTS,
           "max_attachment_mb": cfg.MAX_ATTACHMENT_TOTAL_BYTES // (1024 * 1024)}
    ctx.update(extra)
    return ctx


@bp.get("/compose")
def compose_page():
    user = require_login()
    if not user:
        return _login_redirect()
    draft = {"to": cfg.normalize_email(request.args.get("to")), "subject": "", "body": ""}
    kind, source = ("reply", request.args.get("reply_to")) if request.args.get("reply_to") \
        else ("forward", request.args.get("forward")) if request.args.get("forward") else (None, None)
    if kind:
        try:
            opened = mail_service.open_email(message_id=source, owner_email=user,
                                             owner_keys=current_keys())
            draft = mail_service.build_draft(opened, user, kind)
        except mail_service.MailServiceError as exc:
            flash(str(exc), "danger")
    return render_template("compose.html", **_compose_context(draft=draft, draft_kind=kind))


def _read_attachments() -> list[mail_service.Attachment]:
    """Uploaded files from the compose form (size-checked while reading)."""
    attachments = []
    budget = cfg.MAX_ATTACHMENT_TOTAL_BYTES
    for upload in request.files.getlist("attachments"):
        if not upload or not upload.filename:
            continue
        data = upload.read(budget + 1)
        budget -= len(data)
        if budget < 0:
            raise mail_service.MailServiceError(
                f"Attachments are too large (limit {cfg.MAX_ATTACHMENT_TOTAL_BYTES // 1024} KiB in total).")
        attachments.append(mail_service.Attachment(
            name=upload.filename, content_type=upload.mimetype or "application/octet-stream", data=data))
    return attachments


@bp.post("/compose")
def compose_submit():
    user = require_login()
    if not user:
        return _login_redirect()
    keys = current_keys()
    recipient = cfg.normalize_email(request.form.get("to"))
    subject = (request.form.get("subject") or "").strip()
    body = request.form.get("body") or ""
    use_real = session.get("mode") == "real"
    try:
        result = mail_service.send_email(
            sender_email=user, recipient_email=recipient, subject=subject,
            body=body, sender_keys=keys, use_real_smtp=use_real,
            attachments=_read_attachments(),
        )
    except (mail_service.MailServiceError, SmtpError) as exc:
        # Re-show the form with what the user typed instead of losing it.
        flash(str(exc), "danger")
        return render_template("compose.html", **_compose_context(
            draft={"to": recipient, "subject": subject, "body": body})), 400
    except Exception:  # noqa: BLE001 - transport failure etc.
        event("Send failed unexpectedly")
        flash(_("The message could not be sent (transport error)."), "danger")
        return render_template("compose.html", **_compose_context(
            draft={"to": recipient, "subject": subject, "body": body})), 500
    suite = _("hybrid X25519 + ML-KEM-768") if result.hybrid \
        else _("ML-KEM-768 only (recipient has a legacy key)")
    extra = _(", %(n)s attachment(s)", n=result.attachment_count) if result.attachment_count else ""
    flash(_("Encrypted & sent to %(to)s via %(via)s. (%(suite)s; KEM ciphertext %(kem)s B, signature %(sig)s B%(extra)s)",
            to=result.recipient, via=result.delivered_via, suite=suite, kem=result.kem_ciphertext_len,
            sig=result.signature_len, extra=extra),
          "success" if result.hybrid else "warning")
    return redirect(url_for("pqmail.sent"))


def _tamper_demo_allowed() -> bool:
    """The "Simulate Tampering" demo exists only in Demo Mode.

    It deliberately corrupts a stored message, so it is hidden *and* refused whenever the
    session is in Real Email Mode or demo mode is disabled in the configuration
    (``PQMAIL_DEMO_MODE=0``). Verification itself is never switched off: a message that
    really was altered is always withheld with a red warning.
    """
    return cfg.DEMO_ENABLED and session.get("mode", "demo") != "real"


@bp.get("/message/<message_id>")
def message_view(message_id: str):
    user = require_login()
    if not user:
        return _login_redirect()
    keys = current_keys()
    db = database.get_db()
    row = db.get_envelope(message_id, user)
    try:
        opened = mail_service.open_email(message_id=message_id, owner_email=user,
                                         owner_keys=keys)
    except mail_service.MailServiceError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("pqmail.inbox"))
    return render_template("message.html", msg=opened, message_id=message_id,
                           mode=session.get("mode", "demo"), demo_tools=_tamper_demo_allowed(),
                           folder=row["folder"] if row else "inbox",
                           in_trash=bool(row and row["deleted_at"]))


@bp.get("/message/<message_id>/attachment/<int:index>")
def attachment_download(message_id: str, index: int):
    """Download one decrypted attachment of a verified message."""
    user = require_login()
    if not user:
        return _login_redirect()
    try:
        item = mail_service.get_attachment(message_id=message_id, owner_email=user,
                                           owner_keys=current_keys(), index=index)
    except mail_service.MailServiceError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("pqmail.message_view", message_id=message_id))
    from urllib.parse import quote
    # Always served as an opaque download: never rendered by the browser, so a
    # hostile .html/.svg attachment cannot run script in this origin.
    return Response(
        item.data,
        mimetype="application/octet-stream",
        headers={
            "Content-Disposition": f"attachment; filename=\"{item.name.encode('ascii', 'replace').decode().replace(chr(34), '_')}\"; "
                                   f"filename*=UTF-8''{quote(item.name)}",
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'none'; sandbox",
        },
    )


@bp.post("/message/<message_id>/tamper")
def message_tamper(message_id: str):
    """Demo control: flip one ciphertext bit to show tamper detection."""
    user = require_login()
    if not user:
        return _login_redirect()
    if not _tamper_demo_allowed():
        flash(_("The tamper demo is only available when demo mode is enabled."), "warning")
        return redirect(url_for("pqmail.message_view", message_id=message_id))
    try:
        mail_service.simulate_tampering(message_id, user)
        flash(_("Ciphertext modified — open the message to see tamper detection."), "warning")
    except mail_service.MailServiceError as exc:
        flash(str(exc), "danger")
    return redirect(url_for("pqmail.message_view", message_id=message_id))


# ---------------------------------------------------------------------------
# Contacts / key directory
# ---------------------------------------------------------------------------
@bp.get("/contacts")
def contacts():
    user = require_login()
    if not user:
        return _login_redirect()
    db = database.get_db()
    my_contacts = db.list_contacts(user)
    directory_rows = []
    for u in db.list_users():
        pk = db.get_active_public_key(u["email"])
        directory_rows.append({
            "email": u["email"],
            "display_name": u["display_name"],
            "fingerprint": pk["fingerprint"] if pk else None,
            "kem_algo": pk["kem_algo"] if pk else None,
            "sig_algo": pk["sig_algo"] if pk else None,
            "hybrid": bool(pk and pk["x25519_public_b64"]),
            "imported": u["source"] != "local",
        })
    return render_template("contacts.html", contacts=my_contacts, directory=directory_rows)


@bp.post("/contacts/add")
def contacts_add():
    user = require_login()
    if not user:
        return _login_redirect()
    contact = cfg.normalize_email(request.form.get("contact_email"))
    label = " ".join((request.form.get("label") or "").split())[:60] or None
    if cfg.is_valid_email(contact):
        database.get_db().add_contact(user, contact, label)
        flash(_("Contact %(c)s added.", c=contact), "success")
    else:
        flash(_("Please provide a valid contact email."), "danger")
    return redirect(url_for("pqmail.contacts"))


@bp.post("/contacts/remove")
def contacts_remove():
    user = require_login()
    if not user:
        return _login_redirect()
    contact = cfg.normalize_email(request.form.get("contact_email"))
    if database.get_db().remove_contact(user, contact):
        flash(_("Contact %(c)s removed.", c=contact), "info")
    else:
        flash(_("Contact not found."), "danger")
    return redirect(url_for("pqmail.contacts"))


# ---------------------------------------------------------------------------
# Security / keys
# ---------------------------------------------------------------------------
@bp.get("/keys")
def keys_page():
    user = require_login()
    if not user:
        return _login_redirect()
    keys = current_keys()
    db = database.get_db()
    published = db.get_active_public_key(user)
    info = {
        "kem_fingerprint": fingerprints.public_key_fingerprint(keys.kem_public_bytes),
        "sig_fingerprint": fingerprints.public_key_fingerprint(keys.dsa_public_bytes),
        "x25519_fingerprint": (fingerprints.public_key_fingerprint(keys.x25519_public_bytes)
                               if keys.x25519 else None),
        "created_at": keys.created_at,
        "kem_public_b64": base64.b64encode(keys.kem_public_bytes).decode(),
        "sig_public_b64": base64.b64encode(keys.dsa_public_bytes).decode(),
        "published": published is not None,
        "retired_keys": len(keys.previous_kems),
    }
    key_count = len(db.list_public_keys(user))
    return render_template("keys.html", info=info, key_count=key_count,
                           algos=cfg.algorithm_display_info())


@bp.post("/keys/rotate")
def keys_rotate():
    user = require_login()
    if not user:
        return _login_redirect()
    old_pass = request.form.get("old_passphrase") or ""
    new_pass = request.form.get("new_passphrase") or ""
    confirm = request.form.get("confirm") or ""
    if new_pass != confirm:
        flash(_("New passphrases do not match."), "danger")
        return redirect(url_for("pqmail.keys_page"))
    try:
        info = rotate_keys(cfg.KEYS_DIR, user, old_pass, new_pass)
    except WrongPassphraseError:
        flash(_("Rotation failed: the current passphrase is wrong."), "danger")
        return redirect(url_for("pqmail.keys_page"))
    except KeyStoreError as exc:
        # e.g. new passphrase too short - nothing was changed.
        flash(_("Rotation failed: %(why)s Your existing keys were not changed.", why=str(exc)), "danger")
        return redirect(url_for("pqmail.keys_page"))
    except Exception:  # noqa: BLE001 - storage failure
        event("Key rotation failed")
        flash(_("Rotation failed (storage error). Old keys were kept."), "danger")
        return redirect(url_for("pqmail.keys_page"))
    # Re-publish new public keys under the same identity (old ones stay in the
    # directory so mail signed with them keeps verifying).
    db = database.get_db()
    db.publish_public_keys(
        email=user, kem_algo=cfg.KEM_ALGORITHM, sig_algo=cfg.SIG_ALGORITHM,
        kem_public_b64=info["kem_public_b64"], sig_public_b64=info["sig_public_b64"],
        fingerprint=info["sig_fingerprint"], x25519_public_b64=info["x25519_public_b64"],
    )
    # Refresh the unlocked keys for this session.
    session_keys.pop(session.get("key_token"))
    session["key_token"] = session_keys.new_token()
    session_keys.store(session["key_token"], load_identity(cfg.KEYS_DIR, user, new_pass))
    flash(
        _("Keys rotated. New ML-KEM-768, X25519 and ML-DSA-65 keys are active. The previous keys were "
          "kept inside your new encrypted keystore, so older messages stay readable; "
          "the old keystore file was also archived."),
        "success",
    )
    return redirect(url_for("pqmail.keys_page"))


@bp.get("/keys/export")
def keys_export():
    """Download this identity's PUBLIC key bundle (safe to share)."""
    user = require_login()
    if not user:
        return _login_redirect()
    keys = current_keys()
    bundle = keys.export_public_bundle_b64()
    return Response(
        bundle,
        mimetype="text/plain",
        headers={"Content-Disposition": f"attachment; filename={user.replace('@', '_at_')}_public_keys.pqpub"},
    )


@bp.post("/keys/import")
def keys_import():
    """Register another user's public key bundle into the directory (safely)."""
    user = require_login()
    if not user:
        return _login_redirect()
    blob = request.form.get("bundle") or ""
    confirm_replace = request.form.get("confirm_replace") == "on"
    try:
        result = directory.import_bundle(blob, confirm_replace=confirm_replace)
    except directory.KeyChangeNeedsConfirmation as exc:
        flash(str(exc) + " " + _("Tick 'Replace the pinned key' and import again to accept it."), "danger")
        return redirect(url_for("pqmail.contacts"))
    except directory.DirectoryError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("pqmail.contacts"))
    if result.unchanged:
        flash(_("%(e)s is already in the directory with this key.", e=result.email), "info")
    else:
        flash(_("Imported public keys for %(e)s (fingerprint %(fp)s). "
                "Compare this fingerprint with its owner over another channel.",
                e=result.email, fp=result.fingerprint), "success")
    return redirect(url_for("pqmail.contacts"))


@bp.post("/keys/publish")
def keys_publish():
    user = require_login()
    if not user:
        return _login_redirect()
    keys = current_keys()
    database.get_db().publish_public_keys(
        email=user, kem_algo=cfg.KEM_ALGORITHM, sig_algo=cfg.SIG_ALGORITHM,
        kem_public_b64=base64.b64encode(keys.kem_public_bytes).decode(),
        sig_public_b64=base64.b64encode(keys.dsa_public_bytes).decode(),
        fingerprint=fingerprints.public_key_fingerprint(keys.dsa_public_bytes),
        x25519_public_b64=(base64.b64encode(keys.x25519_public_bytes).decode()
                           if keys.x25519 else None),
    )
    flash(_("Public keys published to the demo key directory."), "success")
    return redirect(url_for("pqmail.keys_page"))


# ---------------------------------------------------------------------------
# QKD simulator
# ---------------------------------------------------------------------------
def _qkd_defaults(bits: int, noise_percent: float = 0.0, intercept_percent: float = 100.0,
                  eve: bool = False) -> dict:
    return {
        "bits": bits,
        "min": cfg.BB84_MIN_BITS,
        "max": cfg.BB84_MAX_BITS,
        "threshold_percent": int(cfg.BB84_DETECTION_THRESHOLD * 100),
        "max_noise_percent": int(cfg.BB84_MAX_NOISE * 100),
        "noise_percent": noise_percent,
        "intercept_percent": intercept_percent,
        "eve": eve,
    }


def _float_field(name: str, default: float) -> float:
    try:
        return float(request.form.get(name, default))
    except ValueError:
        return default


@bp.get("/qkd")
def qkd_page():
    if not require_login():
        return _login_redirect()
    return render_template("qkd.html", defaults=_qkd_defaults(cfg.BB84_DEFAULT_BITS))


@bp.post("/qkd/run")
def qkd_run():
    if not require_login():
        return _login_redirect()
    try:
        n_bits = int(request.form.get("bits", cfg.BB84_DEFAULT_BITS))
    except ValueError:
        n_bits = cfg.BB84_DEFAULT_BITS
    eve = request.form.get("eve") == "on"
    noise_pct = _float_field("noise", 0.0)
    intercept_pct = _float_field("intercept", 100.0)
    defaults = _qkd_defaults(n_bits, noise_pct, intercept_pct, eve)
    try:
        result = bb84.run_bb84(n_bits, eve, noise=noise_pct / 100.0,
                               intercept_fraction=intercept_pct / 100.0)
    except QKDParameterError as exc:
        return render_template("qkd.html", error=str(exc), defaults=defaults)
    event("QKD simulation run", qubits=n_bits, eve=eve, noise=noise_pct,
          intercept=intercept_pct, eve_detected=result.eve_detected)
    return render_template("qkd.html", result=result, preview=bb84.transcript_preview(result),
                           defaults=defaults)


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------
def _keyring_enrolled(user: str) -> bool:
    try:
        return KeyStore.load(cfg.KEYS_DIR, user).keyring_enrolled
    except KeyStoreError:
        return False


@bp.get("/settings")
def settings_page():
    user = require_login()
    if not user:
        return _login_redirect()
    return render_template(
        "settings.html",
        mode=session.get("mode", "demo"),
        smtp_configured=cfg.smtp_config() is not None,
        imap_configured=cfg.imap_config() is not None,
        keyring_available=_keyring_available(),
        keyring_enrolled=_keyring_enrolled(user),
        twofa_enabled=bool(current_keys() and current_keys().totp_enabled),
    )


@bp.post("/settings/keyring")
def settings_keyring():
    """Enroll the current session's keystore into the OS keyring vault."""
    user = require_login()
    if not user:
        return _login_redirect()
    passphrase = request.form.get("passphrase") or ""
    if not _keyring_available():
        flash(_("No OS keyring backend is available on this machine."), "warning")
        return redirect(url_for("pqmail.settings_page"))
    try:
        ok = KeyStore.load(cfg.KEYS_DIR, user).enroll_keyring(passphrase)
    except Exception:  # noqa: BLE001
        ok = False
    flash(_("OS keyring enrollment succeeded. Your passphrase still works as before.") if ok else
          _("Keyring enrollment failed (wrong passphrase?)."),
          "success" if ok else "danger")
    return redirect(url_for("pqmail.settings_page"))


@bp.post("/settings/keyring/remove")
def settings_keyring_remove():
    user = require_login()
    if not user:
        return _login_redirect()
    try:
        KeyStore.load(cfg.KEYS_DIR, user).remove_keyring()
        flash(_("OS keyring enrollment removed. Sign in with your passphrase."), "success")
    except Exception:  # noqa: BLE001
        flash(_("Could not remove the keyring enrollment."), "danger")
    return redirect(url_for("pqmail.settings_page"))


def _keyring_available() -> bool:
    from app.storage.secure_storage import keyring_available
    return keyring_available()


# ---------------------------------------------------------------------------
# Security dashboard & learn pages
# ---------------------------------------------------------------------------
@bp.get("/security")
def security_page():
    if not require_login():
        return _login_redirect()
    return render_template("security.html", algos=cfg.algorithm_display_info(),
                           mode=session.get("mode", "demo"))


@bp.get("/learn")
def learn_page():
    if not require_login():
        return _login_redirect()
    return render_template("learn.html", algos=cfg.algorithm_display_info())


# ---------------------------------------------------------------------------
# JSON API (used by the UI for live stats)
# ---------------------------------------------------------------------------
@bp.get("/api/stats")
def api_stats():
    user = require_login()
    if not user:
        return {"error": "not logged in"}, 401
    stats = database.get_db().stats(user)
    stats["keys_unlocked"] = current_keys() is not None
    stats["mode"] = session.get("mode", "demo")
    return stats


# Additional route groups register themselves on the same blueprint.
from app import routes_extra  # noqa: E402,F401
