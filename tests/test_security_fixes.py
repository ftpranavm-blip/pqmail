"""Regression tests for the flaws found in the review (F1-F24).

Each test names the flaw it guards against. They all run against the sandbox
data directory from ``conftest.py``; nothing touches the real ``data/`` folder
and nothing talks to the network (SMTP/IMAP are faked).
"""
from __future__ import annotations

import base64
import json
import re
import ssl
import uuid

import pytest

from app import config as cfg
from app import db as database
from app import security, session_keys
from app.bootstrap import create_identity
from app.crypto import fingerprints
from app.crypto.key_manager import (WrongPassphraseError, create_keystore,
                                    load_identity, rotate_keys)
from app.email import message_format
from app.services import directory, mail_service
from app.storage import secure_storage
from app.storage.secure_storage import KeyStore, KeyStoreError

PASS = "longenough-passphrase"


# ---------------------------------------------------------------------------
# helpers / fixtures
# ---------------------------------------------------------------------------
def make_user(prefix="user"):
    """Register a fresh local identity; returns (email, unlocked keys)."""
    email = f"{prefix}-{uuid.uuid4().hex[:8]}@pqmail.test"
    create_identity(email, prefix.title(), PASS)
    return email, load_identity(cfg.KEYS_DIR, email, PASS)


def send(sender, sender_keys, recipient, subject="Subject line", body="the secret body"):
    return mail_service.send_email(sender_email=sender, recipient_email=recipient,
                                   subject=subject, body=body, sender_keys=sender_keys)


@pytest.fixture()
def client(demo_world):
    from app import create_app

    security.login_throttle.clear()
    session_keys.clear()
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


def token(client, path="/login"):
    html = client.get(path).get_data(as_text=True)
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)


def post(client, path, data=None, page="/login", **kw):
    data = dict(data or {})
    data["csrf_token"] = token(client, page)
    return client.post(path, data=data, **kw)


def login(client, email, passphrase=PASS):
    return post(client, "/login", {"email": email, "passphrase": passphrase})


# ---------------------------------------------------------------------------
# F1  key hijacking through /keys/import
# ---------------------------------------------------------------------------
def test_f1_import_cannot_replace_local_identity(demo_world):
    _mallory, mkeys = make_user("mallory")
    forged = json.loads(base64.b64decode(mkeys.export_public_bundle_b64()))
    forged["email"] = demo_world["bob"]
    blob = base64.b64encode(json.dumps(forged).encode()).decode()
    before = database.get_db().get_active_public_key(demo_world["bob"])["fingerprint"]
    with pytest.raises(directory.DirectoryError, match="identity on this machine"):
        directory.import_bundle(blob)
    assert database.get_db().get_active_public_key(demo_world["bob"])["fingerprint"] == before


def test_f1_import_route_blocks_hijack(client, demo_world):
    mallory, mkeys = make_user("mallory")
    forged = json.loads(base64.b64decode(mkeys.export_public_bundle_b64()))
    forged["email"] = demo_world["bob"]
    blob = base64.b64encode(json.dumps(forged).encode()).decode()
    before = database.get_db().get_active_public_key(demo_world["bob"])["fingerprint"]
    login(client, mallory)
    post(client, "/keys/import", {"bundle": blob}, page="/contacts")
    assert database.get_db().get_active_public_key(demo_world["bob"])["fingerprint"] == before


def test_f1_imported_contact_key_change_needs_confirmation(demo_world):
    first = create_keystore(cfg.KEYS_DIR.parent / "tmp-keys", f"x{uuid.uuid4().hex[:6]}@a.test", PASS)
    second = create_keystore(cfg.KEYS_DIR.parent / "tmp-keys", f"y{uuid.uuid4().hex[:6]}@a.test", PASS)
    email = f"ext-{uuid.uuid4().hex[:6]}@remote.test"

    def bundle(info):
        return base64.b64encode(json.dumps({
            "email": email,
            "algorithms": {"kem": cfg.KEM_ALGORITHM, "signature": cfg.SIG_ALGORITHM},
            "kem_public_key_b64": info["kem_public_b64"],
            "signature_public_key_b64": info["sig_public_b64"],
        }).encode()).decode()

    res = directory.import_bundle(bundle(first))
    assert res.created and not res.replaced
    assert directory.import_bundle(bundle(first)).unchanged
    with pytest.raises(directory.KeyChangeNeedsConfirmation):
        directory.import_bundle(bundle(second))
    res = directory.import_bundle(bundle(second), confirm_replace=True)
    assert res.replaced
    active = database.get_db().get_active_public_key(email)
    assert active["fingerprint"] == second["sig_fingerprint"]


def test_f1_bad_bundles_rejected(demo_world):
    for blob in ("", "not-base64!!", base64.b64encode(b"[]").decode(),
                 base64.b64encode(b'{"algorithms":{}}').decode(), "A" * (cfg.MAX_PUBLIC_BUNDLE_BYTES + 1)):
        with pytest.raises(directory.DirectoryError):
            directory.import_bundle(blob)


# ---------------------------------------------------------------------------
# F2  rotation must never destroy the keystore
# ---------------------------------------------------------------------------
def test_f2_failed_rotation_leaves_keystore_usable(demo_world):
    email, _ = make_user("rot")
    with pytest.raises(KeyStoreError):
        rotate_keys(cfg.KEYS_DIR, email, PASS, "x")          # new passphrase too short
    assert KeyStore.store_path_for(cfg.KEYS_DIR, email).exists()
    load_identity(cfg.KEYS_DIR, email, PASS)                 # still unlocks with the old one
    with pytest.raises(WrongPassphraseError):
        rotate_keys(cfg.KEYS_DIR, email, "wrong-passphrase", PASS)
    assert not list(cfg.KEYS_DIR.glob("*.new"))              # no staging leftovers


# ---------------------------------------------------------------------------
# F3  path traversal / unsafe addresses
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("bad", ["..\\..\\evil@x.test", "../evil@x.test", "a b@x.test",
                                 "a/b@x.test", "ev\nil@x.test", "@x.test", "a@", "a..b@x.test",
                                 "x" * 80 + "@x.test"])
def test_f3_unsafe_addresses_rejected(bad, demo_world):
    assert not cfg.is_valid_email(bad)
    with pytest.raises(ValueError):
        create_identity(bad, "Evil", PASS)
    with pytest.raises(KeyStoreError):
        KeyStore.filename_for(bad)


def test_f3_keystore_path_stays_inside_directory(tmp_path):
    path = KeyStore.store_path_for(tmp_path, "ok@x.test")
    assert path.parent == tmp_path


def test_f3_login_with_traversal_address_is_plain_failure(client):
    resp = login(client, "..\\..\\x@y.test", "whatever1")
    assert resp.status_code == 302 and resp.headers["Location"].endswith("/login")


# ---------------------------------------------------------------------------
# F4  CSRF
# ---------------------------------------------------------------------------
def test_f4_post_without_token_is_rejected(client, demo_world):
    login(client, demo_world["alice"], demo_world["passphrase"])
    assert client.post("/mode", data={"mode": "real"}).status_code == 400
    assert client.post("/keys/publish").status_code == 400
    assert client.post("/logout").status_code == 400
    assert client.get("/dashboard").status_code == 200     # still signed in


def test_f4_wrong_token_is_rejected(client, demo_world):
    login(client, demo_world["alice"], demo_world["passphrase"])
    assert client.post("/logout", data={"csrf_token": "forged"}).status_code == 400


def test_f4_logout_is_post_only(client, demo_world):
    login(client, demo_world["alice"], demo_world["passphrase"])
    assert client.get("/logout").status_code == 405
    assert client.get("/dashboard").status_code == 200
    assert post(client, "/logout", page="/dashboard").status_code == 302
    assert client.get("/dashboard").status_code == 302


def test_f4_login_form_needs_token(client, demo_world):
    resp = client.post("/login", data={"email": demo_world["alice"],
                                       "passphrase": demo_world["passphrase"]})
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# F5  OS keyring enrollment must not lock the passphrase out
# ---------------------------------------------------------------------------
@pytest.fixture()
def fake_keyring(monkeypatch):
    store: dict[str, bytes] = {}
    monkeypatch.setattr(secure_storage, "keyring_available", lambda: True)
    monkeypatch.setattr(secure_storage, "_keyring_set", lambda name, key: store.__setitem__(name, key) or True)
    monkeypatch.setattr(secure_storage, "_keyring_get", lambda name: store.get(name))
    monkeypatch.setattr(secure_storage, "_keyring_delete", lambda name: store.pop(name, None))
    import app.routes as routes
    monkeypatch.setattr(routes, "_keyring_available", lambda: True)
    return store


def test_f5_enroll_keeps_passphrase_working(fake_keyring, demo_world):
    email, _ = make_user("kr")
    store = KeyStore.load(cfg.KEYS_DIR, email)
    assert store.enroll_keyring(PASS) is True
    reloaded = KeyStore.load(cfg.KEYS_DIR, email)
    assert reloaded.keyring_enrolled
    load_identity(cfg.KEYS_DIR, email, PASS)                       # passphrase still works
    ident = load_identity(cfg.KEYS_DIR, email, use_keyring=True)   # and so does the keyring
    assert ident.email == email
    reloaded.remove_keyring()
    assert not KeyStore.load(cfg.KEYS_DIR, email).keyring_enrolled
    with pytest.raises(WrongPassphraseError):
        load_identity(cfg.KEYS_DIR, email, use_keyring=True)
    load_identity(cfg.KEYS_DIR, email, PASS)


def test_f5_keyring_login_route(fake_keyring, client, demo_world):
    email, _ = make_user("krr")
    KeyStore.load(cfg.KEYS_DIR, email).enroll_keyring(PASS)
    post(client, "/login/keyring", {"email": email})
    assert client.get("/dashboard").status_code == 200
    # an identity that never enrolled cannot use the keyring route
    post(client, "/logout", page="/dashboard")
    post(client, "/login/keyring", {"email": demo_world["alice"]})
    assert client.get("/dashboard").status_code == 302


# ---------------------------------------------------------------------------
# F6 / F7  Real Email Mode transport
# ---------------------------------------------------------------------------
def _envelope_for_transport(demo_world, alice_keys):
    send("alice@pqmail.local", alice_keys, "bob@pqmail.local", subject="TOP SECRET SUBJECT")
    row = database.get_db().list_envelopes("bob@pqmail.local", "inbox")[0]
    return json.loads(row["envelope_json"])


def test_f6_subject_never_in_smtp_headers(demo_world, alice_keys):
    from app.email import smtp_client

    env = _envelope_for_transport(demo_world, alice_keys)
    msg = smtp_client.build_message(env, "me@example.com")
    assert msg["Subject"] == smtp_client.PUBLIC_SUBJECT
    assert "TOP SECRET" not in msg.as_string()


class _FakeSMTP:
    instances: list = []

    def __init__(self, host, port, timeout=None, context=None):
        self.context = context
        self.sent = []
        _FakeSMTP.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def login(self, user, pw):
        pass

    def send_message(self, msg):
        self.sent.append(msg)

    def ehlo(self):
        pass

    def starttls(self, context=None):
        self.context = context


def test_f7_smtp_verifies_certificates(monkeypatch, demo_world, alice_keys):
    import smtplib

    from app.email import smtp_client

    monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("SMTP_USERNAME", "me@example.com")
    monkeypatch.setenv("SMTP_PASSWORD", "app-password")
    env = _envelope_for_transport(demo_world, alice_keys)
    for port, cls_name in (("465", "SMTP_SSL"), ("587", "SMTP")):
        monkeypatch.setenv("SMTP_PORT", port)
        monkeypatch.setattr(smtplib, cls_name, _FakeSMTP)
        _FakeSMTP.instances.clear()
        smtp_client.send_envelope_via_smtp(env)
        ctx = _FakeSMTP.instances[0].context
        assert ctx is not None and ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname


def test_f7_imap_verifies_certificates(monkeypatch):
    import imaplib

    from app.email import imap_client

    seen = {}

    class FakeIMAP:
        def __init__(self, host, port, timeout=None, ssl_context=None):
            seen["ctx"] = ssl_context

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def login(self, *a):
            pass

        def select(self, *a, **k):
            pass

        def search(self, *a):
            return "OK", [b""]

    monkeypatch.setenv("IMAP_HOST", "imap.example.com")
    monkeypatch.setenv("IMAP_USERNAME", "me@example.com")
    monkeypatch.setenv("IMAP_PASSWORD", "app-password")
    monkeypatch.setattr(imaplib, "IMAP4_SSL", FakeIMAP)
    assert imap_client.fetch_envelopes() == []
    assert seen["ctx"].verify_mode == ssl.CERT_REQUIRED and seen["ctx"].check_hostname


# ---------------------------------------------------------------------------
# F8  sender can read the Sent folder
# ---------------------------------------------------------------------------
def test_f8_sent_copy_is_readable_by_sender(demo_world, alice_keys, bob_keys):
    send("alice@pqmail.local", alice_keys, "bob@pqmail.local", subject="Hello", body="for Bob")
    row = database.get_db().list_envelopes("alice@pqmail.local", "sent")[0]
    opened = mail_service.open_email(message_id=row["message_id"],
                                     owner_email="alice@pqmail.local", owner_keys=alice_keys)
    assert opened.trusted and opened.subject == "Hello" and opened.body == "for Bob"
    assert opened.recipient == "bob@pqmail.local"
    # the recipient's copy is a different envelope encrypted to Bob only
    inbox_row = database.get_db().list_envelopes("bob@pqmail.local", "inbox")[0]
    assert inbox_row["message_id"] != row["message_id"]
    assert mail_service.open_email(message_id=inbox_row["message_id"], owner_email="bob@pqmail.local",
                                   owner_keys=bob_keys).body == "for Bob"


def test_f8_sent_copy_stays_ciphertext_only(demo_world, alice_keys):
    send("alice@pqmail.local", alice_keys, "bob@pqmail.local", subject="PLAINSUBJECT", body="PLAINBODY")
    raw = database.get_db().db_path.read_bytes()
    assert b"PLAINSUBJECT" not in raw and b"PLAINBODY" not in raw


# ---------------------------------------------------------------------------
# F9 / F10  rotation keeps old mail verifiable and readable
# ---------------------------------------------------------------------------
def _publish_rotation(email, info):
    database.get_db().publish_public_keys(
        email=email, kem_algo=cfg.KEM_ALGORITHM, sig_algo=cfg.SIG_ALGORITHM,
        kem_public_b64=info["kem_public_b64"], sig_public_b64=info["sig_public_b64"],
        fingerprint=info["sig_fingerprint"])


def test_f9_old_signature_still_verifies_after_sender_rotates(demo_world):
    alice, akeys = make_user("alice")
    bob, bkeys = make_user("bob")
    result = send(alice, akeys, bob)
    _publish_rotation(alice, rotate_keys(cfg.KEYS_DIR, alice, PASS, PASS))   # same second on purpose
    opened = mail_service.open_email(message_id=result.message_id, owner_email=bob, owner_keys=bkeys)
    assert opened.signature_valid and opened.trusted
    assert opened.sender_key_current is False
    # mail signed with the new key verifies too and is flagged current
    new_keys = load_identity(cfg.KEYS_DIR, alice, PASS)
    r2 = send(alice, new_keys, bob)
    o2 = mail_service.open_email(message_id=r2.message_id, owner_email=bob, owner_keys=bkeys)
    assert o2.trusted and o2.sender_key_current


def test_f9_active_key_is_deterministic_within_one_second(demo_world):
    email, _ = make_user("tie")
    info = rotate_keys(cfg.KEYS_DIR, email, PASS, PASS)
    _publish_rotation(email, info)
    assert database.get_db().get_active_public_key(email)["fingerprint"] == info["sig_fingerprint"]


def test_f10_old_mail_readable_after_recipient_rotates(demo_world):
    alice, akeys = make_user("alice")
    bob, bkeys = make_user("bob")
    old = send(alice, akeys, bob, body="written before rotation")
    _publish_rotation(bob, rotate_keys(cfg.KEYS_DIR, bob, PASS, PASS + "2"))
    new_bob = load_identity(cfg.KEYS_DIR, bob, PASS + "2")
    assert len(new_bob.previous_kems) == 1
    assert mail_service.open_email(message_id=old.message_id, owner_email=bob,
                                   owner_keys=new_bob).body == "written before rotation"
    new = send(alice, akeys, bob, body="written after rotation")
    assert mail_service.open_email(message_id=new.message_id, owner_email=bob,
                                   owner_keys=new_bob).body == "written after rotation"
    # a second rotation keeps both retired keys
    rotate_keys(cfg.KEYS_DIR, bob, PASS + "2", PASS + "3")
    assert len(load_identity(cfg.KEYS_DIR, bob, PASS + "3").previous_kems) == 2
    # archive copy of the old keystore still exists
    assert list(cfg.KEY_ARCHIVE_DIR.glob(bob.replace("@", "_at_") + ".*.keystore.json"))


# ---------------------------------------------------------------------------
# F11  .env loader
# ---------------------------------------------------------------------------
def test_f11_dotenv_loader(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text('# comment\nPQ_TEST_A=hello\nPQ_TEST_B="quoted value"\nPQ_TEST_C=from-file\n\nbad line\n',
                        encoding="utf-8")
    monkeypatch.setenv("PQ_TEST_C", "from-real-env")
    monkeypatch.delenv("PQ_TEST_A", raising=False)
    monkeypatch.delenv("PQ_TEST_B", raising=False)
    cfg._load_dotenv(env_file)
    import os
    assert os.environ["PQ_TEST_A"] == "hello"
    assert os.environ["PQ_TEST_B"] == "quoted value"
    assert os.environ["PQ_TEST_C"] == "from-real-env"      # real environment wins
    monkeypatch.delenv("PQ_TEST_A"); monkeypatch.delenv("PQ_TEST_B")


# ---------------------------------------------------------------------------
# F12  IMAP import
# ---------------------------------------------------------------------------
def test_f12_import_envelope_rules(demo_world, alice_keys):
    send("alice@pqmail.local", alice_keys, "bob@pqmail.local")
    db = database.get_db()
    row = db.list_envelopes("bob@pqmail.local", "inbox")[0]
    env = json.loads(row["envelope_json"])
    with db._connect() as conn:
        conn.execute("DELETE FROM envelopes")
        conn.execute("DELETE FROM message_ledger")      # as if this inbox had never seen it
    assert mail_service.import_envelope(env, "bob@pqmail.local") == "imported"
    assert mail_service.import_envelope(env, "bob@pqmail.local") == "duplicate"
    assert mail_service.import_envelope(env, "alice@pqmail.local").startswith("skipped: addressed")
    ghost = dict(env, message_id="pqmail-" + "0" * 32, sender="ghost@nowhere.test")
    assert "unknown sender" in mail_service.import_envelope(ghost, "bob@pqmail.local")
    assert mail_service.import_envelope({"junk": 1}, "bob@pqmail.local").startswith("skipped: invalid")


def test_f12_extract_envelopes_from_mime(demo_world, alice_keys):
    from app.email import imap_client, smtp_client

    env = _envelope_for_transport(demo_world, alice_keys)
    raw = smtp_client.build_message(env, "x@example.com").as_bytes()
    assert imap_client.extract_envelopes(raw) == [env]
    assert imap_client.extract_envelopes(b"Subject: hi\r\n\r\nno attachment") == []


def test_f12_fetch_real_inbox_end_to_end(monkeypatch, demo_world, alice_keys, bob_keys):
    from app.email import imap_client

    env = _envelope_for_transport(demo_world, alice_keys)
    with database.get_db()._connect() as conn:
        conn.execute("DELETE FROM envelopes")
        conn.execute("DELETE FROM message_ledger")
    monkeypatch.setattr(imap_client, "fetch_envelopes", lambda limit=50: [env, env])
    counts = mail_service.fetch_real_inbox("bob@pqmail.local")
    assert counts == {"imported": 1, "duplicate": 1, "skipped": 0, "replay": 0}
    opened = mail_service.open_email(message_id=env["message_id"], owner_email="bob@pqmail.local",
                                     owner_keys=bob_keys)
    assert opened.trusted


# ---------------------------------------------------------------------------
# F13  envelope validation robustness
# ---------------------------------------------------------------------------
def test_f13_naive_timestamp_is_a_format_error_not_a_crash(demo_world, alice_keys):
    env = _envelope_for_transport(demo_world, alice_keys)
    env["timestamp"] = "2026-01-01T00:00:00"
    with pytest.raises(message_format.EnvelopeFormatError, match="timezone"):
        message_format.validate_envelope(env)


@pytest.mark.parametrize("field,value", [("message_id", "../../x"), ("sender", "no-at-sign"),
                                         ("salt", base64.b64encode(b"short").decode())])
def test_f13_malformed_fields_rejected(field, value, demo_world, alice_keys):
    env = _envelope_for_transport(demo_world, alice_keys)
    env[field] = value
    with pytest.raises(message_format.EnvelopeFormatError):
        message_format.validate_envelope(env)


def test_f13_corrupt_envelope_json_is_a_user_error(demo_world, alice_keys, bob_keys):
    send("alice@pqmail.local", alice_keys, "bob@pqmail.local")
    db = database.get_db()
    row = db.list_envelopes("bob@pqmail.local", "inbox")[0]
    with db._connect() as conn:
        conn.execute("UPDATE envelopes SET envelope_json = '{broken' WHERE message_id = ?",
                     (row["message_id"],))
    with pytest.raises(mail_service.MailServiceError, match="Malformed"):
        mail_service.open_email(message_id=row["message_id"], owner_email="bob@pqmail.local",
                                owner_keys=bob_keys)


# ---------------------------------------------------------------------------
# F14  keystore hardening
# ---------------------------------------------------------------------------
def test_f14_unlock_uses_parameters_stored_in_the_file(tmp_path, monkeypatch):
    create_keystore(tmp_path, "p@x.test", PASS)
    monkeypatch.setattr(cfg, "ARGON2_MEMORY_COST", 16384)      # defaults changed later
    monkeypatch.setattr(cfg, "ARGON2_TIME_COST", 2)
    load_identity(tmp_path, "p@x.test", PASS)                  # still unlocks


def test_f14_metadata_is_authenticated(tmp_path):
    create_keystore(tmp_path, "q@x.test", PASS)
    path = KeyStore.store_path_for(tmp_path, "q@x.test")
    data = json.loads(path.read_text(encoding="utf-8"))
    data["metadata"]["created_at"] = "1999-01-01T00:00:00+00:00"   # any edit at all
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(WrongPassphraseError):
        load_identity(tmp_path, "q@x.test", PASS)


def test_f14_swapped_public_key_is_detected(tmp_path):
    a = create_keystore(tmp_path, "a@x.test", PASS)
    create_keystore(tmp_path, "b@x.test", PASS)
    pa = KeyStore.store_path_for(tmp_path, "a@x.test")
    data = json.loads(pa.read_text(encoding="utf-8"))
    other = json.loads(KeyStore.store_path_for(tmp_path, "b@x.test").read_text(encoding="utf-8"))
    data["metadata"]["signature_public_key_b64"] = other["metadata"]["signature_public_key_b64"]
    pa.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(WrongPassphraseError):
        load_identity(tmp_path, "a@x.test", PASS)
    assert a["sig_public_b64"] != other["metadata"]["signature_public_key_b64"]


def test_f14_out_of_range_kdf_parameters_rejected(tmp_path):
    create_keystore(tmp_path, "r@x.test", PASS)
    path = KeyStore.store_path_for(tmp_path, "r@x.test")
    data = json.loads(path.read_text(encoding="utf-8"))
    data["metadata"]["kdf"]["memory_cost"] = 10 ** 9
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(WrongPassphraseError):
        load_identity(tmp_path, "r@x.test", PASS)


def test_f14_atomic_write_leaves_no_temp_files(tmp_path):
    create_keystore(tmp_path, "s@x.test", PASS)
    names = [p.name for p in tmp_path.iterdir() if "keystore" in p.name or p.suffix == ".tmp"]
    assert names == ["s_at_x.test.keystore.json"]


def test_f14_legacy_format1_keystore_is_upgraded(tmp_path):
    """A keystore written by the old code (no AAD, no format field) still unlocks
    and is transparently re-sealed as format 2."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    create_keystore(tmp_path, "old@x.test", PASS)
    path = KeyStore.store_path_for(tmp_path, "old@x.test")
    ks = KeyStore.load(tmp_path, "old@x.test")
    bundle = ks.unlock(PASS)
    bundle["x25519_private"] = None                      # the old code had no X25519 key
    legacy_meta = {k: v for k, v in ks.metadata.items()
                   if k not in ("format", "x25519_public_key_b64")}
    key = secure_storage.derive_storage_key(PASS, base64.b64decode(legacy_meta["kdf"]["salt_b64"]),
                                            legacy_meta["kdf"])
    nonce = b"\x01" * cfg.AES_NONCE_BYTES
    blob = AESGCM(key).encrypt(nonce, secure_storage._encode_bundle(bundle), None)   # no AAD
    path.write_text(json.dumps({"metadata": legacy_meta,
                                "nonce_b64": base64.b64encode(nonce).decode(),
                                "blob_b64": base64.b64encode(blob).decode()}), encoding="utf-8")
    assert KeyStore.load(tmp_path, "old@x.test").format_version == 1
    identity = load_identity(tmp_path, "old@x.test", PASS)
    assert identity.x25519 is not None                   # hybrid key generated during the upgrade
    assert KeyStore.load(tmp_path, "old@x.test").format_version == secure_storage.FORMAT_VERSION
    again = load_identity(tmp_path, "old@x.test", PASS)
    assert again.x25519_public_bytes == identity.x25519_public_bytes


# ---------------------------------------------------------------------------
# F15  sessions
# ---------------------------------------------------------------------------
def test_f15_secret_key_is_persisted(monkeypatch, tmp_path):
    monkeypatch.delenv("PQMAIL_SECRET_KEY", raising=False)
    monkeypatch.setattr(cfg, "DATA_DIR", tmp_path)
    monkeypatch.setattr(cfg, "SECRET_KEY_FILE", tmp_path / "secret_key")
    first = cfg.get_secret_key()
    assert len(first) >= 32 and cfg.get_secret_key() == first
    monkeypatch.setenv("PQMAIL_SECRET_KEY", "from-env")
    assert cfg.get_secret_key() == "from-env"


def test_f15_expired_keys_end_the_session_everywhere(client, demo_world):
    login(client, demo_world["alice"], demo_world["passphrase"])
    assert client.get("/inbox").status_code == 200
    session_keys.clear()                                    # TTL expiry / server restart
    for path in ("/inbox", "/dashboard", "/qkd", "/learn", "/settings"):
        login(client, demo_world["alice"], demo_world["passphrase"])
        session_keys.clear()
        resp = client.get(path)
        assert resp.status_code == 302 and resp.headers["Location"].endswith("/login"), path


def test_f15_mode_redirect_is_not_open(client, demo_world):
    login(client, demo_world["alice"], demo_world["passphrase"])
    resp = post(client, "/mode", {"mode": "demo"}, page="/settings",
                headers={"Referer": "https://evil.example/phish"})
    assert resp.headers["Location"].endswith("/dashboard")
    resp = post(client, "/mode", {"mode": "demo"}, page="/settings",
                headers={"Referer": "http://localhost/settings"})
    assert resp.headers["Location"] == "/settings"


def test_f15_real_mode_requires_smtp_configuration(client, demo_world, monkeypatch):
    for var in ("SMTP_HOST", "SMTP_USERNAME", "SMTP_PASSWORD"):
        monkeypatch.delenv(var, raising=False)
    login(client, demo_world["alice"], demo_world["passphrase"])
    post(client, "/mode", {"mode": "real"}, page="/settings")
    assert "Demo Mode" in client.get("/settings").get_data(as_text=True)


# ---------------------------------------------------------------------------
# F16  demo accounts
# ---------------------------------------------------------------------------
def test_f16_demo_mode_can_be_disabled(monkeypatch, tmp_path):
    from app.bootstrap import ensure_demo_users

    monkeypatch.setattr(cfg, "DEMO_ENABLED", False)
    db = database.Database(tmp_path / "nodemo.db")
    ensure_demo_users(db)
    assert db.list_users() == []


def test_f16_login_page_hides_demo_accounts_when_disabled(client, monkeypatch):
    assert "Demo accounts" in client.get("/login").get_data(as_text=True)
    monkeypatch.setattr(cfg, "DEMO_ENABLED", False)
    html = client.get("/login").get_data(as_text=True)
    assert "Demo accounts" not in html and cfg.DEMO_PASSPHRASE not in html


def test_f16_refuses_public_binding_with_demo_accounts(monkeypatch):
    monkeypatch.setattr(cfg, "DEMO_ENABLED", True)
    assert cfg.check_safe_binding("0.0.0.0")
    assert cfg.check_safe_binding("127.0.0.1") is None
    monkeypatch.setattr(cfg, "DEMO_ENABLED", False)
    assert cfg.check_safe_binding("0.0.0.0") is None


def test_f16_tamper_demo_disabled_outside_demo_mode(client, demo_world, alice_keys, bob_keys, monkeypatch):
    send("alice@pqmail.local", alice_keys, "bob@pqmail.local")
    mid = database.get_db().list_envelopes("bob@pqmail.local", "inbox")[0]["message_id"]
    login(client, "bob@pqmail.local", demo_world["passphrase"])
    monkeypatch.setattr(cfg, "DEMO_ENABLED", False)
    post(client, f"/message/{mid}/tamper", page=f"/message/{mid}")
    assert database.get_db().get_envelope(mid, "bob@pqmail.local")["tampered_demo"] == 0


# ---------------------------------------------------------------------------
# F17  login throttling
# ---------------------------------------------------------------------------
def test_f17_lockout_after_repeated_failures(client, demo_world):
    for _ in range(cfg.LOGIN_MAX_FAILURES):
        login(client, demo_world["alice"], "wrong-passphrase")
    # even the CORRECT passphrase is refused while locked out...
    login(client, demo_world["alice"], demo_world["passphrase"])
    assert client.get("/dashboard").status_code == 302
    # ...another account is unaffected...
    login(client, demo_world["bob"], demo_world["passphrase"])
    assert client.get("/dashboard").status_code == 200


def test_f17_success_resets_the_counter(client, demo_world):
    for _ in range(cfg.LOGIN_MAX_FAILURES - 1):
        login(client, demo_world["alice"], "wrong-passphrase")
    login(client, demo_world["alice"], demo_world["passphrase"])
    assert client.get("/dashboard").status_code == 200
    post(client, "/logout", page="/dashboard")
    for _ in range(cfg.LOGIN_MAX_FAILURES - 1):
        login(client, demo_world["alice"], "wrong-passphrase")
    login(client, demo_world["alice"], demo_world["passphrase"])
    assert client.get("/dashboard").status_code == 200


# ---------------------------------------------------------------------------
# F18  per-user stats, subjects in lists
# ---------------------------------------------------------------------------
def test_f18_stats_are_per_user(demo_world, alice_keys):
    send("alice@pqmail.local", alice_keys, "bob@pqmail.local")
    db = database.get_db()
    a, b = db.stats("alice@pqmail.local"), db.stats("bob@pqmail.local")
    assert (a["sent_emails"], a["inbox_emails"]) == (1, 0)
    assert (b["sent_emails"], b["inbox_emails"], b["unread_emails"]) == (0, 1, 1)
    assert db.stats("nobody@pqmail.test")["total_emails"] == 0


def test_f18_inbox_shows_verified_subjects(client, demo_world, alice_keys):
    send("alice@pqmail.local", alice_keys, "bob@pqmail.local", subject="Quarterly numbers")
    login(client, "bob@pqmail.local", demo_world["passphrase"])
    html = client.get("/inbox").get_data(as_text=True)
    assert "Quarterly numbers" in html
    assert database.get_db().stats("bob@pqmail.local")["unread_emails"] == 1   # preview didn't mark read


def test_f18_tampered_message_subject_not_shown(client, demo_world, alice_keys):
    send("alice@pqmail.local", alice_keys, "bob@pqmail.local", subject="Quarterly numbers")
    mid = database.get_db().list_envelopes("bob@pqmail.local", "inbox")[0]["message_id"]
    mail_service.simulate_tampering(mid, "bob@pqmail.local")
    login(client, "bob@pqmail.local", demo_world["passphrase"])
    html = client.get("/inbox").get_data(as_text=True)
    assert "Quarterly numbers" not in html and "Unverified" in html


# ---------------------------------------------------------------------------
# F19  registration messages
# ---------------------------------------------------------------------------
def test_f19_short_passphrase_gives_a_clear_error(client):
    resp = post(client, "/register", {"email": "new1@pqmail.test", "display_name": "N",
                                      "passphrase": "short", "confirm": "short"},
                page="/register", follow_redirects=True)
    html = resp.get_data(as_text=True)
    assert "at least 8 characters" in html and "storage error" not in html
    assert not KeyStore.store_path_for(cfg.KEYS_DIR, "new1@pqmail.test").exists()


def test_f19_display_name_is_cleaned():
    from app.bootstrap import clean_display_name

    assert clean_display_name("  Ann\x00\n  Lee\t") == "Ann Lee"


# ---------------------------------------------------------------------------
# F20  caching headers
# ---------------------------------------------------------------------------
def test_f20_pages_are_not_cached(client, demo_world):
    login(client, demo_world["alice"], demo_world["passphrase"])
    assert client.get("/inbox").headers["Cache-Control"] == "no-store"
    assert "no-store" not in client.get("/static/css/style.css").headers.get("Cache-Control", "")


# ---------------------------------------------------------------------------
# F23  BB84
# ---------------------------------------------------------------------------
def test_f23_bb84_minimum_and_large_runs():
    import random

    from app.qkd import bb84

    with pytest.raises(bb84.QKDParameterError):
        bb84.run_bb84(cfg.BB84_MIN_BITS - 1)
    result = bb84.run_bb84(cfg.BB84_MAX_BITS, eve_present=False, rng=random.Random(1))
    assert result.keys_match and result.final_key_length > 0


def test_f23_eve_is_usually_detected_even_at_minimum_size():
    import random

    from app.qkd import bb84

    detected = sum(bb84.run_bb84(cfg.BB84_MIN_BITS, True, rng=random.Random(seed)).eve_detected
                   for seed in range(200))
    assert detected >= 190        # misses should be rare (~1% at 128 qubits)


# ---------------------------------------------------------------------------
# F24  mailbox isolation between sender and recipient
# ---------------------------------------------------------------------------
def test_f24_sender_cannot_tamper_with_recipients_copy(client, demo_world, alice_keys, bob_keys):
    send("alice@pqmail.local", alice_keys, "bob@pqmail.local", body="intact")
    db = database.get_db()
    row = db.list_envelopes("bob@pqmail.local", "inbox")[0]
    login(client, "alice@pqmail.local", demo_world["passphrase"])
    post(client, f"/message/{row['message_id']}/tamper", page="/inbox")
    after = db.get_envelope(row["message_id"], "bob@pqmail.local")
    assert after["envelope_json"] == row["envelope_json"] and after["tampered_demo"] == 0
    assert mail_service.open_email(message_id=row["message_id"], owner_email="bob@pqmail.local",
                                   owner_keys=bob_keys).body == "intact"


def test_f24_wrong_mailbox_rows_are_not_reachable(demo_world, alice_keys):
    send("alice@pqmail.local", alice_keys, "bob@pqmail.local")
    db = database.get_db()
    inbox_id = db.list_envelopes("bob@pqmail.local", "inbox")[0]["message_id"]
    sent_id = db.list_envelopes("alice@pqmail.local", "sent")[0]["message_id"]
    assert db.get_envelope(inbox_id, "alice@pqmail.local") is None
    assert db.get_envelope(sent_id, "bob@pqmail.local") is None


# ---------------------------------------------------------------------------
# misc: log injection
# ---------------------------------------------------------------------------
def test_log_fields_cannot_forge_lines():
    from app.log import _clean

    cleaned = _clean("evil@x.test\nINFO fake line\r\n")
    assert "\n" not in cleaned and "\r" not in cleaned
    assert len(_clean("a" * 1000)) < 300


def test_fingerprint_is_160_bits_in_ten_groups():
    fp = fingerprints.public_key_fingerprint(b"abc")
    assert len(fp.split()) == 10 and all(len(g) == 4 for g in fp.split())
