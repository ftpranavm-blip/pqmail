"""Additional routes: trash / delete, key transparency log, two-factor auth, benchmarks, attack lab.

These register on the same blueprint as :mod:`app.routes` (imported at the
bottom of that module), so ``url_for("pqmail.<endpoint>")`` keeps working.
"""
from __future__ import annotations

import threading
import time

from flask import flash, redirect, render_template, request, session, url_for

from app import config as cfg
from app import db as database
from app import security
from app.i18n import gettext as _
from app.log import event
from app.routes import (_login_redirect, _mailbox_items, bp, current_keys,
                        require_login)
from app.services import attack_lab, benchmarks, totp


# ---------------------------------------------------------------------------
# Delete / trash
# ---------------------------------------------------------------------------
@bp.post("/message/<message_id>/delete")
def message_delete(message_id: str):
    """Move a message to the trash (soft delete, can be undone)."""
    user = require_login()
    if not user:
        return _login_redirect()
    db = database.get_db()
    row = db.get_envelope(message_id, user)
    if row is not None and db.trash_envelope(message_id, user):
        flash(_("Moved to trash. You can restore it from the Trash page."), "info")
    else:
        flash(_("Message not found in this mailbox."), "danger")
        return redirect(url_for("pqmail.inbox"))
    return redirect(url_for("pqmail.sent" if row["folder"] == "sent" else "pqmail.inbox"))


@bp.post("/message/<message_id>/restore")
def message_restore(message_id: str):
    user = require_login()
    if not user:
        return _login_redirect()
    if database.get_db().restore_envelope(message_id, user):
        flash(_("Message restored."), "success")
    else:
        flash(_("Message not found in the trash."), "danger")
    return redirect(url_for("pqmail.trash"))


@bp.post("/message/<message_id>/purge")
def message_purge(message_id: str):
    """Permanently delete a trashed message."""
    user = require_login()
    if not user:
        return _login_redirect()
    if database.get_db().purge_envelope(message_id, user):
        flash(_("Message permanently deleted."), "success")
    else:
        flash(_("Only messages in the trash can be permanently deleted."), "danger")
    return redirect(url_for("pqmail.trash"))


@bp.get("/trash")
def trash():
    user = require_login()
    if not user:
        return _login_redirect()
    inbox_items, inbox_total, _p, _n = _mailbox_items(user, "inbox", trashed=True)
    sent_items, sent_total, _p2, _n2 = _mailbox_items(user, "sent", trashed=True)
    items = sorted(inbox_items + sent_items, key=lambda i: i["timestamp"], reverse=True)
    return render_template("trash.html", items=items, total=inbox_total + sent_total)


@bp.post("/trash/empty")
def trash_empty():
    user = require_login()
    if not user:
        return _login_redirect()
    count = database.get_db().empty_trash(user)
    flash(_("%(n)s message(s) permanently deleted.", n=count), "success")
    return redirect(url_for("pqmail.trash"))


# ---------------------------------------------------------------------------
# Key transparency log
# ---------------------------------------------------------------------------
@bp.get("/transparency")
def transparency():
    """Public, append-only log of every key-directory change, verified on each view."""
    user = require_login()
    if not user:
        return _login_redirect()
    db = database.get_db()
    focus = cfg.normalize_email(request.args.get("email"))
    report = db.verify_key_log()
    entries = db.list_key_log(focus or None, limit=200)
    return render_template("transparency.html", report=report, entries=entries, focus=focus,
                           me=user)


# ---------------------------------------------------------------------------
# Two-factor authentication (TOTP)
# ---------------------------------------------------------------------------
@bp.get("/login/2fa")
def login_2fa():
    """Second sign-in step: authenticator code or recovery code."""
    if not (session.get("twofa_pending") and session.get("user")):
        return redirect(url_for("pqmail.login_page"))
    if current_keys() is None:                     # unlocked keys expired while waiting
        session.clear()
        flash(_("Your session expired - please sign in again to unlock your keys."), "warning")
        return redirect(url_for("pqmail.login_page"))
    return render_template("login_2fa.html", email=session["user"])


@bp.post("/login/2fa")
def login_2fa_submit():
    if not (session.get("twofa_pending") and session.get("user")):
        return redirect(url_for("pqmail.login_page"))
    email, keys = session["user"], current_keys()
    if keys is None:
        session.clear()
        return redirect(url_for("pqmail.login_page"))
    throttle_key = f"2fa:{email}"
    wait = security.login_lockout_seconds(throttle_key, request.remote_addr)
    if wait:
        flash(_("Too many failed attempts. Try again in %(s)s seconds.", s=wait), "danger")
        return redirect(url_for("pqmail.login_2fa"))
    method = totp.check_code(database.get_db(), keys, request.form.get("code") or "")
    if method is None:
        security.login_failed(throttle_key, request.remote_addr)
        event("Second factor failed", user=email)
        flash(_("That code is not valid."), "danger")
        return redirect(url_for("pqmail.login_2fa"))
    security.login_succeeded(throttle_key)
    session.pop("twofa_pending", None)
    if method == "recovery":
        left = totp.recovery_codes_left(database.get_db(), keys)
        flash(_("Signed in with a recovery code. %(n)s left - consider regenerating them in Settings.", n=left),
              "warning")
    else:
        flash(_("Welcome back, %(email)s!", email=email), "success")
    return redirect(url_for("pqmail.dashboard"))


@bp.get("/settings/2fa")
def twofa_setup():
    """Show the QR code / secret and the enrolment form (secret stays in the session)."""
    user = require_login()
    if not user:
        return _login_redirect()
    keys = current_keys()
    db = database.get_db()
    if keys.totp_enabled:
        return render_template("twofa.html", enabled=True,
                               codes_left=totp.recovery_codes_left(db, keys),
                               total_codes=len(keys.recovery_hashes))
    raw = session.get("totp_setup")
    secret = totp.generate_secret() if not raw else bytes.fromhex(raw)
    session["totp_setup"] = secret.hex()
    uri = totp.provisioning_uri(secret, user)
    return render_template("twofa.html", enabled=False, secret=totp.secret_b32(secret), uri=uri,
                           qr=totp.qr_data_uri(uri))


@bp.post("/settings/2fa/enable")
def twofa_enable():
    user = require_login()
    if not user:
        return _login_redirect()
    raw = session.get("totp_setup")
    if not raw:
        return redirect(url_for("pqmail.twofa_setup"))
    try:
        codes = totp.enable(database.get_db(), current_keys(), request.form.get("passphrase") or "",
                            bytes.fromhex(raw), request.form.get("code") or "")
    except totp.TotpError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("pqmail.twofa_setup"))
    session.pop("totp_setup", None)
    flash(_("Two-factor authentication is now on."), "success")
    return render_template("recovery_codes.html", codes=codes)


@bp.post("/settings/2fa/disable")
def twofa_disable():
    user = require_login()
    if not user:
        return _login_redirect()
    try:
        totp.disable(database.get_db(), current_keys(), request.form.get("passphrase") or "",
                     request.form.get("code") or "")
    except totp.TotpError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("pqmail.twofa_setup"))
    flash(_("Two-factor authentication is now off."), "info")
    return redirect(url_for("pqmail.settings_page"))


@bp.post("/settings/2fa/recovery")
def twofa_recovery():
    user = require_login()
    if not user:
        return _login_redirect()
    try:
        codes = totp.regenerate_recovery_codes(database.get_db(), current_keys(),
                                               request.form.get("passphrase") or "")
    except totp.TotpError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("pqmail.twofa_setup"))
    return render_template("recovery_codes.html", codes=codes)


# ---------------------------------------------------------------------------
# Benchmarks
# ---------------------------------------------------------------------------
_bench_lock = threading.Lock()
_bench_state: dict = {"report": None, "last_run": 0.0}
BENCH_COOLDOWN_SECONDS = 15


def _speed_bars(report: benchmarks.BenchmarkReport) -> dict[str, list[dict]]:
    """Normalised bar data (percent of the slowest in each chart) for the SVG charts."""
    charts: dict[str, list[dict]] = {}
    for title, op in (("Signing speed (higher is faster)", "sign"),
                      ("Verification speed (higher is faster)", "verify")):
        rows = [t for t in report.timings if t.operation == op]
        top = max((t.ops_per_sec for t in rows), default=1.0)
        charts[title] = [{"label": t.algorithm, "value": f"{t.ops_per_sec:,.0f} ops/s",
                          "pct": max(2, round(100 * t.ops_per_sec / top)), "classical": t.classical}
                         for t in sorted(rows, key=lambda t: -t.ops_per_sec)]
    sizes = [s for s in report.sizes if s.kind == "Signature"]
    top = max((s.public_key + s.ciphertext_or_signature for s in sizes), default=1)
    charts["Public key + signature size (smaller is lighter)"] = [
        {"label": s.algorithm, "value": f"{s.public_key + s.ciphertext_or_signature:,} B",
         "pct": max(2, round(100 * (s.public_key + s.ciphertext_or_signature) / top)),
         "classical": s.classical}
        for s in sorted(sizes, key=lambda s: s.public_key + s.ciphertext_or_signature)]
    return charts


@bp.get("/benchmarks")
def benchmarks_page():
    if not require_login():
        return _login_redirect()
    report = _bench_state["report"]
    return render_template("benchmarks.html", report=report,
                           charts=_speed_bars(report) if report else None,
                           cooldown=BENCH_COOLDOWN_SECONDS)


@bp.post("/benchmarks/run")
def benchmarks_run():
    if not require_login():
        return _login_redirect()
    with _bench_lock:                                   # one run at a time, with a cool-down
        if time.time() - _bench_state["last_run"] < BENCH_COOLDOWN_SECONDS and _bench_state["report"]:
            flash(_("A benchmark ran moments ago - showing those results. Try again in a few seconds."), "info")
        else:
            _bench_state["report"] = benchmarks.run_benchmarks()
            _bench_state["last_run"] = time.time()
            event("Benchmarks run", seconds=round(_bench_state["report"].seconds, 1))
    return redirect(url_for("pqmail.benchmarks_page"))


# ---------------------------------------------------------------------------
# Attack lab
# ---------------------------------------------------------------------------
@bp.get("/attack-lab")
def attack_lab_page():
    if not require_login():
        return _login_redirect()
    return render_template("attack_lab.html", results=None)


@bp.post("/attack-lab/run")
def attack_lab_run():
    if not require_login():
        return _login_redirect()
    results = attack_lab.run_all()
    event("Attack lab run", blocked=sum(r.blocked for r in results), total=len(results))
    return render_template("attack_lab.html", results=results)
