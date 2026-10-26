"""Web-level tests: attachments, reply/forward, trash, pagination, transparency page,
two-factor sign-in, benchmarks, attack lab, QKD page, theme/i18n plumbing."""
from __future__ import annotations

import io
import re

from app import config as cfg
from app import db as database
from app import session_keys
from app.services import benchmarks, mail_service, totp
from app.storage.secure_storage import KeyStore
from helpers import PASS, login, make_user, post, token


def send_to(client_user_keys, sender, recipient, **kw):
    kw.setdefault("subject", "Hello")
    kw.setdefault("body", "body text")
    return mail_service.send_email(sender_email=sender, recipient_email=recipient,
                                   sender_keys=client_user_keys, **kw)


# ---------------------------------------------------------------------------
# Attachments through the UI
# ---------------------------------------------------------------------------
def compose_with_files(client, to, files, subject="With files", body="see attached"):
    data = {"to": to, "subject": subject, "body": body, "csrf_token": token(client, "/compose"),
            "attachments": [(io.BytesIO(content), name) for name, content in files]}
    return client.post("/compose", data=data, content_type="multipart/form-data")


def test_upload_and_download_attachment(client, demo_world):
    login(client, demo_world["alice"], demo_world["passphrase"])
    payload = bytes(range(256)) * 20
    resp = compose_with_files(client, demo_world["bob"], [("data.bin", payload), ("note.txt", b"hello")])
    assert resp.status_code == 302 and resp.headers["Location"].endswith("/sent")
    post(client, "/logout", page="/dashboard")

    login(client, demo_world["bob"], demo_world["passphrase"])
    html = client.get("/inbox").get_data(as_text=True)
    mid = re.search(r"/message/(pqmail-[0-9a-f]{32})", html).group(1)
    assert "With files" in html and "&#128206; 2" in html            # paperclip + count in the list
    page = client.get(f"/message/{mid}").get_data(as_text=True)
    assert "data.bin" in page and "note.txt" in page
    dl = client.get(f"/message/{mid}/attachment/0")
    assert dl.status_code == 200 and dl.data == payload
    assert dl.mimetype == "application/octet-stream"
    assert "attachment" in dl.headers["Content-Disposition"] and "data.bin" in dl.headers["Content-Disposition"]
    assert dl.headers["X-Content-Type-Options"] == "nosniff"
    assert "sandbox" in dl.headers["Content-Security-Policy"]
    assert client.get(f"/message/{mid}/attachment/1").data == b"hello"
    assert client.get(f"/message/{mid}/attachment/9").status_code == 302    # missing -> back to message


def test_hostile_attachment_name_and_type_are_neutralised(client, demo_world):
    login(client, demo_world["alice"], demo_world["passphrase"])
    compose_with_files(client, demo_world["bob"],
                       [('../../x<script>alert(1)</script>.html', b"<script>alert(1)</script>")])
    post(client, "/logout", page="/dashboard")
    login(client, demo_world["bob"], demo_world["passphrase"])
    mid = re.search(r"/message/(pqmail-[0-9a-f]{32})",
                    client.get("/inbox").get_data(as_text=True)).group(1)
    page = client.get(f"/message/{mid}").get_data(as_text=True)
    assert "<script>alert(1)</script>" not in page
    dl = client.get(f"/message/{mid}/attachment/0")
    assert dl.mimetype == "application/octet-stream" and "<" not in dl.headers["Content-Disposition"]


def test_attachment_too_large_keeps_the_typed_message(client, demo_world):
    login(client, demo_world["alice"], demo_world["passphrase"])
    big = b"0" * (cfg.MAX_ATTACHMENT_TOTAL_BYTES + 10)
    resp = compose_with_files(client, demo_world["bob"], [("big.bin", big)], subject="Keep me",
                              body="my long text that must not be lost")
    html = resp.get_data(as_text=True)
    assert resp.status_code == 400
    assert "too large" in html and "my long text that must not be lost" in html and "Keep me" in html


def test_other_users_cannot_download_attachments(client, demo_world):
    alice = demo_world["alice"]
    login(client, alice, demo_world["passphrase"])
    compose_with_files(client, demo_world["bob"], [("a.txt", b"secret")])
    mid = database.get_db().list_envelopes(demo_world["bob"], "inbox")[0]["message_id"]
    # Alice (sender) cannot reach Bob's inbox copy
    resp = client.get(f"/message/{mid}/attachment/0", follow_redirects=False)
    assert resp.status_code == 302 and b"secret" not in resp.data
    post(client, "/logout", page="/dashboard")
    carol, _k = make_user("carol")
    login(client, carol)
    assert client.get(f"/message/{mid}/attachment/0").status_code == 302


def test_upload_beyond_request_limit_gets_a_clean_413(client, demo_world):
    login(client, demo_world["alice"], demo_world["passphrase"])
    huge = b"0" * (cfg.MAX_REQUEST_BYTES + 1024)
    resp = compose_with_files(client, demo_world["bob"], [("huge.bin", huge)])
    assert resp.status_code == 413 and "too large" in resp.get_data(as_text=True)


def test_compose_requires_csrf_with_multipart(client, demo_world):
    login(client, demo_world["alice"], demo_world["passphrase"])
    data = {"to": demo_world["bob"], "subject": "x", "attachments": (io.BytesIO(b"a"), "a.txt")}
    assert client.post("/compose", data=data, content_type="multipart/form-data").status_code == 400


# ---------------------------------------------------------------------------
# Reply / forward / delete / trash
# ---------------------------------------------------------------------------
def test_reply_and_forward_prefill(client, demo_world, alice_keys):
    send_to(alice_keys, demo_world["alice"], demo_world["bob"], subject="Plan", body="line1\nline2")
    mid = database.get_db().list_envelopes(demo_world["bob"], "inbox")[0]["message_id"]
    login(client, demo_world["bob"], demo_world["passphrase"])
    reply = client.get(f"/compose?reply_to={mid}").get_data(as_text=True)
    assert 'value="alice@pqmail.local"' in reply and 'value="Re: Plan"' in reply
    assert "&gt; line1" in reply and "Replying to a verified message" in reply
    fwd = client.get(f"/compose?forward={mid}").get_data(as_text=True)
    assert 'value="Fwd: Plan"' in fwd and "Forwarded message" in fwd


def test_reply_to_tampered_message_is_refused(client, demo_world, alice_keys):
    send_to(alice_keys, demo_world["alice"], demo_world["bob"])
    mid = database.get_db().list_envelopes(demo_world["bob"], "inbox")[0]["message_id"]
    mail_service.simulate_tampering(mid, demo_world["bob"])
    login(client, demo_world["bob"], demo_world["passphrase"])
    html = client.get(f"/compose?reply_to={mid}").get_data(as_text=True)
    assert "Only verified messages" in html and 'value="Re:' not in html


def test_delete_restore_purge_via_routes(client, demo_world, alice_keys):
    send_to(alice_keys, demo_world["alice"], demo_world["bob"], subject="Bye")
    db = database.get_db()
    mid = db.list_envelopes(demo_world["bob"], "inbox")[0]["message_id"]
    login(client, demo_world["bob"], demo_world["passphrase"])
    assert "Bye" in client.get("/inbox").get_data(as_text=True)
    assert client.post(f"/message/{mid}/delete").status_code == 400                    # CSRF
    post(client, f"/message/{mid}/delete", page=f"/message/{mid}")
    assert "Bye" not in client.get("/inbox").get_data(as_text=True)
    assert "Bye" in client.get("/trash").get_data(as_text=True)
    assert db.stats(demo_world["bob"])["trash_emails"] == 1
    post(client, f"/message/{mid}/restore", page="/trash")
    assert "Bye" in client.get("/inbox").get_data(as_text=True)
    post(client, f"/message/{mid}/purge", page="/trash")                               # not in trash -> refused
    assert db.has_envelope(mid)
    post(client, f"/message/{mid}/delete", page=f"/message/{mid}")
    post(client, f"/message/{mid}/purge", page="/trash")
    assert not db.has_envelope(mid) and db.ledger_has(demo_world["bob"], mid)


def test_cannot_delete_someone_elses_message(client, demo_world, alice_keys):
    send_to(alice_keys, demo_world["alice"], demo_world["bob"])
    db = database.get_db()
    mid = db.list_envelopes(demo_world["bob"], "inbox")[0]["message_id"]
    login(client, demo_world["alice"], demo_world["passphrase"])
    post(client, f"/message/{mid}/delete", page="/inbox")
    assert len(db.list_envelopes(demo_world["bob"], "inbox")) == 1


def test_empty_trash(client, demo_world, alice_keys):
    for i in range(3):
        send_to(alice_keys, demo_world["alice"], demo_world["bob"], subject=f"s{i}")
    db = database.get_db()
    login(client, demo_world["bob"], demo_world["passphrase"])
    for row in db.list_envelopes(demo_world["bob"], "inbox"):
        post(client, f"/message/{row['message_id']}/delete", page="/inbox")
    post(client, "/trash/empty", page="/trash")
    assert db.stats(demo_world["bob"])["trash_emails"] == 0
    assert "The trash is empty." in client.get("/trash").get_data(as_text=True)


def test_inbox_pagination_and_unread_filter(client, demo_world, alice_keys):
    total = cfg.PAGE_SIZE + 3
    for i in range(total):
        send_to(alice_keys, demo_world["alice"], demo_world["bob"], subject=f"msg-{i:03d}")
    login(client, demo_world["bob"], demo_world["passphrase"])
    p1 = client.get("/inbox").get_data(as_text=True)
    p2 = client.get("/inbox?page=2").get_data(as_text=True)
    assert p1.count('class="mail-item') == cfg.PAGE_SIZE and p2.count('class="mail-item') == 3
    assert "Page 1 of 2" in p1 and "Page 2 of 2" in p2
    assert client.get("/inbox?page=99").status_code == 200            # clamped, no crash
    assert client.get("/inbox?page=abc").status_code == 200
    mid = database.get_db().list_envelopes(demo_world["bob"], "inbox")[0]["message_id"]
    client.get(f"/message/{mid}")                                     # marks one as read
    unread = client.get("/inbox?filter=unread").get_data(as_text=True)
    assert f"({total - 1})" in unread


def test_unread_badge_in_navigation(client, demo_world, alice_keys):
    send_to(alice_keys, demo_world["alice"], demo_world["bob"])
    login(client, demo_world["bob"], demo_world["passphrase"])
    assert 'class="count-badge"' in client.get("/dashboard").get_data(as_text=True)


# ---------------------------------------------------------------------------
# Hybrid UI details, transparency page, dashboard warning
# ---------------------------------------------------------------------------
def test_message_page_shows_hybrid_suite(client, demo_world, alice_keys):
    send_to(alice_keys, demo_world["alice"], demo_world["bob"])
    mid = database.get_db().list_envelopes(demo_world["bob"], "inbox")[0]["message_id"]
    login(client, demo_world["bob"], demo_world["passphrase"])
    page = client.get(f"/message/{mid}").get_data(as_text=True)
    assert "X25519+ML-KEM-768" in page and "v2.0" in page


def test_transparency_page_verified_then_failing(client, demo_world):
    login(client, demo_world["alice"], demo_world["passphrase"])
    page = client.get("/transparency").get_data(as_text=True)
    assert "Log verified" in page and "alice@pqmail.local" in page
    db = database.get_db()
    with db._connect() as conn:
        conn.execute("UPDATE key_log SET email = 'evil@x.test' WHERE seq = 1")
    page = client.get("/transparency").get_data(as_text=True)
    assert "Log verification FAILED" in page
    assert "alice@pqmail.local" in client.get("/transparency?email=alice@pqmail.local").get_data(as_text=True)


def test_dashboard_warns_when_directory_key_does_not_match(client, demo_world):
    import base64

    from app.crypto.key_manager import create_keystore

    other = create_keystore(cfg.KEYS_DIR.parent / "tmp-keys", "zz@a.test", PASS)
    login(client, demo_world["alice"], demo_world["passphrase"])
    assert "does NOT match your keystore" not in client.get("/dashboard").get_data(as_text=True)
    with database.get_db()._connect() as conn:
        conn.execute("UPDATE public_keys SET kem_public_b64 = ? WHERE email = ?",
                     (other["kem_public_b64"], demo_world["alice"]))
    assert "does NOT match your keystore" in client.get("/dashboard").get_data(as_text=True)
    assert base64  # (module imported for clarity of intent)


# ---------------------------------------------------------------------------
# TOTP primitives (RFC test vectors)
# ---------------------------------------------------------------------------
def test_hotp_rfc4226_vectors():
    secret = b"12345678901234567890"
    expected = ["755224", "287082", "359152", "969429", "338314",
                "254676", "287922", "162583", "399871", "520489"]
    assert [totp.hotp(secret, i) for i in range(10)] == expected


def test_totp_rfc6238_vector():
    secret = b"12345678901234567890"
    assert totp.hotp(secret, 59 // 30, digits=8) == "94287082"
    assert totp.hotp(secret, 1111111109 // 30, digits=8) == "07081804"
    assert totp.totp_at(secret, 59 // 30) == "287082"


def test_totp_window_and_garbage():
    secret = totp.generate_secret()
    now = 1_700_000_000.0
    step = totp.time_step(now)
    assert totp.match_step(secret, totp.totp_at(secret, step), now) == step
    assert totp.match_step(secret, totp.totp_at(secret, step + 1), now) == step + 1
    assert totp.match_step(secret, totp.totp_at(secret, step - 1), now) == step - 1
    assert totp.match_step(secret, totp.totp_at(secret, step + 2), now) is None
    for junk in ("", "12345", "abcdef", "1234567", None):
        assert totp.match_step(secret, junk, now) is None
    assert totp.match_step(secret, " " + totp.totp_at(secret, step)[:3] + " " + totp.totp_at(secret, step)[3:], now) == step


def test_provisioning_uri_and_qr():
    secret = bytes(range(20))
    uri = totp.provisioning_uri(secret, "a@b.test")
    assert uri.startswith("otpauth://totp/PQMail%3Aa%40b.test?secret=") and "issuer=PQMail" in uri
    assert totp.secret_b32(secret) in uri
    qr = totp.qr_data_uri(uri)
    assert qr is None or qr.startswith("data:image/svg+xml")


def test_recovery_code_format_and_hash():
    codes = totp.generate_recovery_codes()
    assert len(codes) == cfg.RECOVERY_CODE_COUNT == len(set(codes))
    assert all(re.fullmatch(r"[a-z2-9]{4}-[a-z2-9]{4}-[a-z2-9]{4}", c) for c in codes)
    assert totp.hash_recovery_code(codes[0]) == totp.hash_recovery_code(codes[0].upper().replace("-", " "))


# ---------------------------------------------------------------------------
# Two-factor sign-in end to end
# ---------------------------------------------------------------------------
def current_code(secret):
    return totp.totp_at(secret, totp.time_step())


def enable_2fa(client, email):
    """Turn 2FA on through the UI; returns (secret_bytes, recovery_codes)."""
    page = client.get("/settings/2fa").get_data(as_text=True)
    secret_b32 = re.search(r'class="key-display">([A-Z2-7]+)<', page).group(1)
    import base64
    secret = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8))
    resp = post(client, "/settings/2fa/enable", {"code": current_code(secret), "passphrase": PASS},
                page="/settings/2fa")
    html = resp.get_data(as_text=True)
    codes = re.findall(r'<li class="mono">([a-z0-9-]{14})</li>', html)
    return secret, codes, html


def test_enable_2fa_then_two_step_login(client, demo_world):
    email, _ = make_user("tf")
    login(client, email)
    secret, codes, html = enable_2fa(client, email)
    assert len(codes) == cfg.RECOVERY_CODE_COUNT and "shown only once" in html
    # nothing sensitive in the keystore file in clear
    raw = KeyStore.store_path_for(cfg.KEYS_DIR, email).read_bytes()
    import base64
    for needle in (secret.hex().encode(), base64.b32encode(secret).rstrip(b"="), base64.b64encode(secret),
                   codes[0].encode()):
        assert needle not in raw
    post(client, "/logout", page="/dashboard")

    # step 1: passphrase only -> half-signed-in, nothing reachable
    resp = login(client, email)
    assert resp.headers["Location"].endswith("/login/2fa")
    for path in ("/dashboard", "/inbox", "/compose", "/keys", "/settings", "/api/stats"):
        r = client.get(path)
        assert r.status_code in (302, 401), path
        if r.status_code == 302:
            assert r.headers["Location"].endswith("/login/2fa"), path
    assert 'class="nav-links"' not in client.get("/login/2fa").get_data(as_text=True)

    # wrong code
    post(client, "/login/2fa", {"code": "000000"}, page="/login/2fa")
    assert client.get("/dashboard").status_code == 302
    # right code (the enrolment code's step is already spent, so use the next one)
    post(client, "/login/2fa", {"code": totp.totp_at(secret, totp.time_step() + 1)}, page="/login/2fa")
    assert client.get("/dashboard").status_code == 200


def test_totp_code_cannot_be_replayed(client, demo_world):
    email, _ = make_user("rp")
    login(client, email)
    secret, _codes, _ = enable_2fa(client, email)       # the enrolment code's step is already spent
    post(client, "/logout", page="/dashboard")
    login(client, email)
    post(client, "/login/2fa", {"code": current_code(secret)}, page="/login/2fa")
    assert client.get("/dashboard").status_code == 302                    # same step as enrolment: refused
    step = totp.time_step()
    post(client, "/login/2fa", {"code": totp.totp_at(secret, step + 1)}, page="/login/2fa")
    assert client.get("/dashboard").status_code == 200                    # next step is fine
    post(client, "/logout", page="/dashboard")
    login(client, email)
    post(client, "/login/2fa", {"code": totp.totp_at(secret, step + 1)}, page="/login/2fa")
    assert client.get("/dashboard").status_code == 302                    # ...once


def test_recovery_code_works_exactly_once(client, demo_world):
    email, _ = make_user("rc")
    login(client, email)
    _secret, codes, _ = enable_2fa(client, email)
    post(client, "/logout", page="/dashboard")
    login(client, email)
    post(client, "/login/2fa", {"code": codes[0].upper()}, page="/login/2fa")
    assert client.get("/dashboard").status_code == 200
    post(client, "/logout", page="/dashboard")
    login(client, email)
    post(client, "/login/2fa", {"code": codes[0]}, page="/login/2fa")
    assert client.get("/dashboard").status_code == 302
    post(client, "/login/2fa", {"code": codes[1]}, page="/login/2fa")     # another code still fine
    assert client.get("/dashboard").status_code == 200


def test_2fa_attempts_are_throttled(client, demo_world):
    email, _ = make_user("th")
    login(client, email)
    secret, _c, _ = enable_2fa(client, email)
    post(client, "/logout", page="/dashboard")
    login(client, email)
    for _ in range(cfg.LOGIN_MAX_FAILURES):
        post(client, "/login/2fa", {"code": "111111"}, page="/login/2fa")
    post(client, "/login/2fa", {"code": totp.totp_at(secret, totp.time_step() + 1)}, page="/login/2fa")
    assert client.get("/dashboard").status_code == 302                    # locked out even with a valid code


def test_enable_requires_valid_code_and_passphrase(client, demo_world):
    email, _ = make_user("bad")
    login(client, email)
    client.get("/settings/2fa")
    post(client, "/settings/2fa/enable", {"code": "000000", "passphrase": PASS}, page="/settings/2fa")
    assert "Two-factor authentication is ON" not in client.get("/settings/2fa").get_data(as_text=True)
    page = client.get("/settings/2fa").get_data(as_text=True)
    import base64
    b32 = re.search(r'class="key-display">([A-Z2-7]+)<', page).group(1)
    secret = base64.b32decode(b32 + "=" * (-len(b32) % 8))
    post(client, "/settings/2fa/enable", {"code": current_code(secret), "passphrase": "wrong-passphrase"},
         page="/settings/2fa")
    assert "Two-factor authentication is ON" not in client.get("/settings/2fa").get_data(as_text=True)
    assert not login_keys(email).totp_enabled


def login_keys(email):
    from app.crypto.key_manager import load_identity

    return load_identity(cfg.KEYS_DIR, email, PASS)


def test_disable_2fa(client, demo_world):
    email, _ = make_user("dis")
    login(client, email)
    secret, codes, _ = enable_2fa(client, email)
    post(client, "/settings/2fa/disable", {"passphrase": PASS, "code": "000000"}, page="/settings/2fa")
    assert login_keys(email).totp_enabled                                  # bad code: still on
    post(client, "/settings/2fa/disable", {"passphrase": PASS, "code": codes[2]}, page="/settings/2fa")
    assert not login_keys(email).totp_enabled
    post(client, "/logout", page="/dashboard")
    login(client, email)
    assert client.get("/dashboard").status_code == 200                     # plain passphrase login again


def test_regenerate_recovery_codes_invalidates_old_ones(client, demo_world):
    email, _ = make_user("reg")
    login(client, email)
    _s, old, _ = enable_2fa(client, email)
    resp = post(client, "/settings/2fa/recovery", {"passphrase": PASS}, page="/settings/2fa")
    new = re.findall(r'<li class="mono">([a-z0-9-]{14})</li>', resp.get_data(as_text=True))
    assert len(new) == cfg.RECOVERY_CODE_COUNT and not set(new) & set(old)
    post(client, "/logout", page="/dashboard")
    login(client, email)
    post(client, "/login/2fa", {"code": old[0]}, page="/login/2fa")
    assert client.get("/dashboard").status_code == 302
    post(client, "/login/2fa", {"code": new[0]}, page="/login/2fa")
    assert client.get("/dashboard").status_code == 200


def test_2fa_survives_key_rotation(client, demo_world):
    email, _ = make_user("rot2")
    login(client, email)
    secret, _c, _ = enable_2fa(client, email)
    post(client, "/keys/rotate", {"old_passphrase": PASS, "new_passphrase": PASS + "2",
                                  "confirm": PASS + "2"}, page="/keys")
    keys = login_keys_with(email, PASS + "2")
    assert keys.totp_enabled and keys.totp_secret == secret


def login_keys_with(email, passphrase):
    from app.crypto.key_manager import load_identity

    return load_identity(cfg.KEYS_DIR, email, passphrase)


def test_2fa_pending_session_expires_with_the_keys(client, demo_world):
    email, _ = make_user("exp")
    login(client, email)
    enable_2fa(client, email)
    post(client, "/logout", page="/dashboard")
    login(client, email)
    session_keys.clear()
    resp = client.get("/login/2fa")
    assert resp.status_code == 302 and resp.headers["Location"].endswith("/login")


def test_2fa_with_keyring_login_still_asks_for_a_code(client, demo_world, monkeypatch):
    from app.storage import secure_storage

    store = {}
    monkeypatch.setattr(secure_storage, "keyring_available", lambda: True)
    monkeypatch.setattr(secure_storage, "_keyring_set", lambda n, k: store.__setitem__(n, k) or True)
    monkeypatch.setattr(secure_storage, "_keyring_get", lambda n: store.get(n))
    monkeypatch.setattr(secure_storage, "_keyring_delete", lambda n: store.pop(n, None))
    email, _ = make_user("kr2")
    assert KeyStore.load(cfg.KEYS_DIR, email).enroll_keyring(PASS)
    login(client, email)
    secret, _c, _ = enable_2fa(client, email)         # re-seals both the passphrase and keyring copies
    post(client, "/logout", page="/dashboard")
    resp = post(client, "/login/keyring", {"email": email})
    assert resp.headers["Location"].endswith("/login/2fa")
    assert client.get("/dashboard").status_code == 302
    post(client, "/login/2fa", {"code": totp.totp_at(secret, totp.time_step() + 1)}, page="/login/2fa")
    assert client.get("/dashboard").status_code == 200


# ---------------------------------------------------------------------------
# Benchmarks
# ---------------------------------------------------------------------------
def test_benchmark_report_contents():
    report = benchmarks.run_benchmarks(scale=0.03)
    assert report.timings and all(t.mean_ms > 0 and t.runs >= 1 for t in report.timings)
    algos = {t.algorithm for t in report.timings}
    assert {"ML-KEM-768", "ML-DSA-65", "X25519", "RSA-3072", "ECDSA P-256", "Ed25519"} <= algos
    sizes = {s.algorithm: s for s in report.sizes}
    assert sizes["ML-KEM-768"].public_key == 1184 and sizes["ML-KEM-768"].ciphertext_or_signature == 1088
    assert sizes["ML-DSA-65"].public_key == 1952 and sizes["ML-DSA-65"].ciphertext_or_signature == 3309
    assert sizes["Ed25519"].ciphertext_or_signature == 64 and sizes["X25519"].public_key == 32
    assert sizes["X25519+ML-KEM-768 (hybrid)"].public_key == 1184 + 32
    assert not sizes["RSA-3072"].quantum_safe and sizes["ML-DSA-65"].quantum_safe
    assert sizes["ML-DSA-65"].ciphertext_or_signature > 40 * sizes["Ed25519"].ciphertext_or_signature // 1


def test_benchmark_page_and_cooldown(client, demo_world, monkeypatch):
    from app import routes_extra

    calls = []
    real = benchmarks.run_benchmarks
    monkeypatch.setattr(benchmarks, "run_benchmarks", lambda: calls.append(1) or real(scale=0.03))
    monkeypatch.setitem(routes_extra._bench_state, "report", None)
    monkeypatch.setitem(routes_extra._bench_state, "last_run", 0.0)
    login(client, demo_world["alice"], demo_world["passphrase"])
    assert "No results yet" in client.get("/benchmarks").get_data(as_text=True)
    assert client.post("/benchmarks/run").status_code == 400                 # CSRF
    post(client, "/benchmarks/run", page="/benchmarks")
    html = client.get("/benchmarks").get_data(as_text=True)
    assert "ML-KEM-768" in html and "bar-pq" in html and "bar-classical" in html and "Sizes (bytes)" in html
    post(client, "/benchmarks/run", page="/benchmarks")                       # inside the cool-down
    assert len(calls) == 1


# ---------------------------------------------------------------------------
# Attack lab
# ---------------------------------------------------------------------------
def test_every_attack_is_blocked():
    from app.services import attack_lab

    results = attack_lab.run_all()
    assert len(results) == len(attack_lab.SCENARIOS) >= 14
    failures = [(r.id, r.steps, r.outcome) for r in results if not r.blocked]
    assert not failures, failures
    assert all(r.steps and r.defence and r.attacker_goal for r in results)
    assert len({r.id for r in results}) == len(results)


def test_attack_lab_sandbox_never_touches_real_data(demo_world):
    from app.services import attack_lab

    db = database.get_db()
    before = (db.list_users(), db.verify_key_log()["entries"], len(db.list_key_log()))
    attack_lab.run_all()
    after = (db.list_users(), db.verify_key_log()["entries"], len(db.list_key_log()))
    assert [u["email"] for u in before[0]] == [u["email"] for u in after[0]] and before[1:] == after[1:]


def test_attack_lab_page(client, demo_world):
    login(client, demo_world["alice"], demo_world["passphrase"])
    assert "Run all attacks" in client.get("/attack-lab").get_data(as_text=True)
    assert client.post("/attack-lab/run").status_code == 400
    html = post(client, "/attack-lab/run", page="/attack-lab").get_data(as_text=True)
    assert re.search(r"(\d+) of \1 attacks blocked", html) and "NOT BLOCKED" not in html


# ---------------------------------------------------------------------------
# QKD page
# ---------------------------------------------------------------------------
def test_qkd_page_with_noise_and_partial_eve(client, demo_world):
    login(client, demo_world["alice"], demo_world["passphrase"])
    html = post(client, "/qkd/run", {"bits": "1024", "noise": "2"}, page="/qkd").get_data(as_text=True)
    assert "Step through the protocol" in html and "data-qkd-step" in html and "Toeplitz" in html
    assert "Key agreement succeeded" in html
    html = post(client, "/qkd/run", {"bits": "512", "noise": "3", "intercept": "20", "eve": "on"},
                page="/qkd").get_data(as_text=True)
    assert "Step through the protocol" in html and "Eve intercepted" in html
    html = post(client, "/qkd/run", {"bits": "512", "noise": "50"}, page="/qkd").get_data(as_text=True)
    assert "Channel noise must be between" in html
    html = post(client, "/qkd/run", {"bits": "512", "intercept": "oops", "noise": "x"}, page="/qkd").get_data(as_text=True)
    assert "Step through the protocol" in html                              # bad numbers fall back to defaults


# ---------------------------------------------------------------------------
# Theme / language plumbing
# ---------------------------------------------------------------------------
def test_theme_assets_and_toggle_present(client, demo_world):
    login(client, demo_world["alice"], demo_world["passphrase"])
    html = client.get("/dashboard").get_data(as_text=True)
    assert 'id="theme-toggle"' in html and "js/theme.js" in html and 'class="skip-link"' in html
    assert client.get("/static/js/theme.js").status_code == 200
    assert 'data-theme="light"' in client.get("/static/css/style.css").get_data(as_text=True)


def test_nav_groups_all_features(client, demo_world):
    login(client, demo_world["alice"], demo_world["passphrase"])
    html = client.get("/dashboard").get_data(as_text=True)
    for path in ("/trash", "/transparency", "/attack-lab", "/benchmarks", "/qkd", "/learn", "/keys"):
        assert f'href="{path}"' in html, path
    for path in ("/trash", "/transparency", "/attack-lab", "/benchmarks", "/qkd", "/learn", "/keys", "/security",
                 "/settings", "/settings/2fa", "/contacts"):
        assert client.get(path).status_code == 200, path


def test_language_switch_persists_across_login(client, demo_world):
    client.get("/login?lang=hi")
    assert 'lang="hi"' in client.get("/login").get_data(as_text=True)
    login(client, demo_world["alice"], demo_world["passphrase"])
    assert 'lang="hi"' in client.get("/dashboard").get_data(as_text=True)
    client.get("/dashboard?lang=en")
    assert 'lang="en"' in client.get("/dashboard").get_data(as_text=True)
    client.get("/login?lang=xx")                                           # unknown language ignored
    assert 'lang="en"' in client.get("/dashboard").get_data(as_text=True)


def test_gettext_percent_handling():
    from app.i18n import gettext

    assert gettext("100%% safe") == "100% safe"
    assert gettext("Hello %(n)s", n="x") == "Hello x"
    assert gettext("lone % sign") == "lone % sign"
    assert gettext("Missing %(n)s") == "Missing %(n)s"


# ---------------------------------------------------------------------------
# Real Email Mode / demo-mode switches (tamper demo, leftover demo accounts)
# ---------------------------------------------------------------------------
def _configure_smtp(monkeypatch):
    monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("SMTP_USERNAME", "me@example.com")
    monkeypatch.setenv("SMTP_PASSWORD", "app-password")


def test_tamper_button_disappears_in_real_mode_and_returns_in_demo_mode(client, demo_world, alice_keys, monkeypatch):
    _configure_smtp(monkeypatch)
    send_to(alice_keys, demo_world["alice"], demo_world["bob"], subject="Real?")
    db = database.get_db()
    mid = db.list_envelopes(demo_world["bob"], "inbox")[0]["message_id"]
    before = db.get_envelope(mid, demo_world["bob"])["envelope_json"]
    login(client, demo_world["bob"], demo_world["passphrase"])
    assert "Simulate Tampering" in client.get(f"/message/{mid}").get_data(as_text=True)      # Demo Mode
    post(client, "/mode", {"mode": "real"}, page="/settings")
    assert "Real Email Mode" in client.get("/settings").get_data(as_text=True)
    page = client.get(f"/message/{mid}").get_data(as_text=True)
    assert "Simulate Tampering" not in page and "Tamper detection demo" not in page          # Real mode
    post(client, f"/message/{mid}/tamper", page=f"/message/{mid}")                          # forged request: refused
    after = db.get_envelope(mid, demo_world["bob"])
    assert after["envelope_json"] == before and after["tampered_demo"] == 0
    post(client, "/mode", {"mode": "demo"}, page="/settings")
    assert "Simulate Tampering" in client.get(f"/message/{mid}").get_data(as_text=True)


def test_genuinely_tampered_message_is_flagged_in_real_mode(client, demo_world, alice_keys, monkeypatch):
    """Verification is never switched off: only the *demo button* disappears."""
    _configure_smtp(monkeypatch)
    send_to(alice_keys, demo_world["alice"], demo_world["bob"], subject="Top secret", body="private text")
    mid = database.get_db().list_envelopes(demo_world["bob"], "inbox")[0]["message_id"]
    mail_service.simulate_tampering(mid, demo_world["bob"])        # stands in for a real attacker editing the DB
    login(client, demo_world["bob"], demo_world["passphrase"])
    post(client, "/mode", {"mode": "real"}, page="/settings")
    page = client.get(f"/message/{mid}").get_data(as_text=True)
    assert "Do not trust this message" in page and "Content withheld" in page
    assert "private text" not in page and "Simulate Tampering" not in page


def test_disabled_demo_mode_blocks_leftover_demo_accounts(client, demo_world, monkeypatch):
    monkeypatch.setattr(cfg, "DEMO_ENABLED", False)
    login(client, demo_world["alice"], demo_world["passphrase"])            # correct (public) passphrase
    assert client.get("/dashboard").status_code == 302                       # ...but demo accounts are off
    email, _keys = make_user("realuser")                                       # a normally registered identity
    login(client, email)
    assert client.get("/dashboard").status_code == 200
    post(client, "/logout", page="/dashboard")
    monkeypatch.setattr(cfg, "DEMO_ENABLED", True)
    login(client, demo_world["alice"], demo_world["passphrase"])
    assert client.get("/dashboard").status_code == 200                       # demo mode back on: works again
