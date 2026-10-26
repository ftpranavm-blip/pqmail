"""Tests for the feature round: hybrid KEM, attachments, replay protection, trash,
reply/forward drafts and the key transparency log."""
from __future__ import annotations

import base64
import json
import uuid

import pytest

from app import config as cfg
from app import db as database
from app.bootstrap import create_identity
from app.crypto import hybrid, pqc
from app.crypto.key_manager import load_identity, rotate_keys
from app.email import message_format
from app.email.message_format import Attachment
from app.services import directory, mail_service
from app.services.mail_service import MailServiceError

PASS = "longenough-passphrase"


def make_user(prefix="user"):
    email = f"{prefix}-{uuid.uuid4().hex[:8]}@pqmail.test"
    create_identity(email, prefix.title(), PASS)
    return email, load_identity(cfg.KEYS_DIR, email, PASS)


def send(sender, keys, recipient, subject="Subject", body="body text", attachments=None):
    return mail_service.send_email(sender_email=sender, recipient_email=recipient, subject=subject,
                                   body=body, sender_keys=keys, attachments=attachments)


def inbox_row(email):
    return database.get_db().list_envelopes(email, "inbox")[0]


def open_(mid, email, keys):
    return mail_service.open_email(message_id=mid, owner_email=email, owner_keys=keys)


# ---------------------------------------------------------------------------
# Hybrid X25519 + ML-KEM
# ---------------------------------------------------------------------------
def test_hybrid_roundtrip_and_binding():
    kem = pqc.generate_kem_keypair()
    xk = pqc.generate_x25519_keypair()
    shared, ct, eph = hybrid.hybrid_encapsulate(kem.public_key, xk.public_key)
    assert len(shared) == 32 and len(ct) == 1088 and len(eph) == 32
    assert hybrid.hybrid_decapsulate(kem.private_key, xk.private_key, ct, eph) == shared
    # wrong ephemeral key or wrong X25519 key -> different secret (never the same)
    other = pqc.generate_x25519_keypair()
    assert hybrid.hybrid_decapsulate(kem.private_key, other.private_key, ct, eph) != shared
    assert hybrid.hybrid_decapsulate(kem.private_key, xk.private_key, ct, other.public_bytes()) != shared


def test_hybrid_requires_both_halves():
    """Knowing only one of the two secrets must not reproduce the key."""
    kem = pqc.generate_kem_keypair()
    xk = pqc.generate_x25519_keypair()
    shared, ct, eph = hybrid.hybrid_encapsulate(kem.public_key, xk.public_key)
    wrong_kem = pqc.generate_kem_keypair()
    assert hybrid.hybrid_decapsulate(wrong_kem.private_key, xk.private_key, ct, eph) != shared


def test_low_order_x25519_point_rejected():
    kem = pqc.generate_kem_keypair()
    xk = pqc.generate_x25519_keypair()
    _s, ct, _e = hybrid.hybrid_encapsulate(kem.public_key, xk.public_key)
    with pytest.raises(pqc.DecapsulationError):
        hybrid.hybrid_decapsulate(kem.private_key, xk.private_key, ct, b"\x00" * 32)


def test_new_mail_is_hybrid_v2(demo_world, alice_keys, bob_keys):
    result = send("alice@pqmail.local", alice_keys, "bob@pqmail.local")
    assert result.hybrid is True
    env = json.loads(inbox_row("bob@pqmail.local")["envelope_json"])
    assert env["version"] == "2.0" and env["algorithm"]["kem"] == "X25519+ML-KEM-768"
    assert len(base64.b64decode(env["x25519_ephemeral"])) == 32
    opened = open_(result.message_id, "bob@pqmail.local", bob_keys)
    assert opened.trusted and opened.envelope_version == "2.0"


def test_v2_ephemeral_field_is_signed_and_bound(demo_world, alice_keys, bob_keys):
    result = send("alice@pqmail.local", alice_keys, "bob@pqmail.local")
    row = inbox_row("bob@pqmail.local")
    env = json.loads(row["envelope_json"])
    env["x25519_ephemeral"] = base64.b64encode(pqc.generate_x25519_keypair().public_bytes()).decode()
    database.get_db().update_envelope(result.message_id, "bob@pqmail.local", env)
    opened = open_(result.message_id, "bob@pqmail.local", bob_keys)
    assert not opened.signature_valid and not opened.integrity_valid and opened.body == ""


def test_downgrade_and_unknown_fields_rejected(demo_world, alice_keys):
    send("alice@pqmail.local", alice_keys, "bob@pqmail.local")
    env = json.loads(inbox_row("bob@pqmail.local")["envelope_json"])
    downgraded = dict(env, version="1.0")                        # claim v1 but keep v2 fields/suite
    with pytest.raises(message_format.EnvelopeFormatError):
        message_format.validate_envelope(downgraded)
    with pytest.raises(message_format.EnvelopeFormatError, match="Unexpected"):
        message_format.validate_envelope(dict(env, injected="x"))
    stripped = {k: v for k, v in env.items() if k != "x25519_ephemeral"}
    with pytest.raises(message_format.EnvelopeFormatError):
        message_format.validate_envelope(stripped)


def test_legacy_recipient_without_x25519_gets_v1(demo_world, alice_keys):
    """A contact whose directory entry has no X25519 key still receives PQ-only mail."""
    email = f"legacy-{uuid.uuid4().hex[:6]}@remote.test"
    info = create_keystore_info()
    bundle = base64.b64encode(json.dumps({
        "email": email,
        "algorithms": {"kem": cfg.KEM_ALGORITHM, "signature": cfg.SIG_ALGORITHM},
        "kem_public_key_b64": info["kem_public_b64"],
        "signature_public_key_b64": info["sig_public_b64"]}).encode()).decode()
    directory.import_bundle(bundle)
    result = send("alice@pqmail.local", alice_keys, email)
    assert result.hybrid is False
    env = json.loads(database.get_db().list_envelopes(email, "inbox")[0]["envelope_json"])
    assert env["version"] == "1.0" and env["algorithm"]["kem"] == "ML-KEM-768"


def create_keystore_info():
    from app.crypto.key_manager import create_keystore

    return create_keystore(cfg.KEYS_DIR.parent / "tmp-keys", f"t{uuid.uuid4().hex[:6]}@a.test", PASS)


def test_old_x25519_less_identity_is_upgraded_and_published(demo_world):
    """An identity published before hybrid existed gets its X25519 key attached."""
    email, keys = make_user("up")
    db = database.get_db()
    with db._connect() as conn:                                    # simulate a pre-hybrid directory row
        conn.execute("UPDATE public_keys SET x25519_public_b64 = NULL WHERE email = ?", (email,))
    assert directory.sync_own_keys(db, keys) == "attached"
    assert db.get_active_public_key(email)["x25519_public_b64"]
    assert directory.sync_own_keys(db, keys) == "ok"


def test_directory_mismatch_is_reported(demo_world):
    email, keys = make_user("mm")
    db = database.get_db()
    other = create_keystore_info()
    with db._connect() as conn:
        conn.execute("UPDATE public_keys SET kem_public_b64 = ? WHERE email = ?",
                     (other["kem_public_b64"], email))
    assert directory.sync_own_keys(db, keys) == "mismatch"


def test_rotation_keeps_hybrid_mail_readable(demo_world):
    alice, akeys = make_user("alice")
    bob, bkeys = make_user("bob")
    old = send(alice, akeys, bob, body="before")
    info = rotate_keys(cfg.KEYS_DIR, bob, PASS, PASS + "x")
    database.get_db().publish_public_keys(
        email=bob, kem_algo=cfg.KEM_ALGORITHM, sig_algo=cfg.SIG_ALGORITHM,
        kem_public_b64=info["kem_public_b64"], sig_public_b64=info["sig_public_b64"],
        fingerprint=info["sig_fingerprint"], x25519_public_b64=info["x25519_public_b64"])
    new_bob = load_identity(cfg.KEYS_DIR, bob, PASS + "x")
    assert new_bob.previous_x25519[0] is not None
    assert open_(old.message_id, bob, new_bob).body == "before"
    new = send(alice, akeys, bob, body="after")
    assert open_(new.message_id, bob, new_bob).body == "after"


# ---------------------------------------------------------------------------
# Attachments
# ---------------------------------------------------------------------------
def test_attachment_roundtrip(demo_world, alice_keys, bob_keys):
    files = [Attachment("report.pdf", "application/pdf", b"%PDF-1.4 " + bytes(range(256)) * 50),
             Attachment("notes.txt", "text/plain", "héllo wörld".encode())]
    result = send("alice@pqmail.local", alice_keys, "bob@pqmail.local", attachments=files)
    assert result.attachment_count == 2
    opened = open_(result.message_id, "bob@pqmail.local", bob_keys)
    assert [(a.name, a.size) for a in opened.attachments] == [("report.pdf", len(files[0].data)),
                                                              ("notes.txt", len(files[1].data))]
    got = mail_service.get_attachment(message_id=result.message_id, owner_email="bob@pqmail.local",
                                      owner_keys=bob_keys, index=1)
    assert got.data == files[1].data and got.name == "notes.txt"
    # the sender's own copy carries them too
    sent_row = database.get_db().list_envelopes("alice@pqmail.local", "sent")[0]
    assert len(open_(sent_row["message_id"], "alice@pqmail.local", alice_keys).attachments) == 2


def test_attachments_never_stored_in_plaintext(demo_world, alice_keys):
    marker = b"UNIQUE-ATTACHMENT-MARKER-0123456789"
    send("alice@pqmail.local", alice_keys, "bob@pqmail.local",
         attachments=[Attachment("secret.bin", "application/octet-stream", marker)])
    raw = database.get_db().db_path.read_bytes()
    assert marker not in raw and b"secret.bin" not in raw and base64.b64encode(marker) not in raw


def test_attachment_limits_enforced(demo_world, alice_keys):
    too_many = [Attachment(f"f{i}.txt", "text/plain", b"x") for i in range(cfg.MAX_ATTACHMENTS + 1)]
    with pytest.raises(MailServiceError, match="At most"):
        send("alice@pqmail.local", alice_keys, "bob@pqmail.local", attachments=too_many)
    huge = [Attachment("big.bin", "application/octet-stream", b"0" * (cfg.MAX_ATTACHMENT_TOTAL_BYTES + 1))]
    with pytest.raises(MailServiceError, match="too large"):
        send("alice@pqmail.local", alice_keys, "bob@pqmail.local", attachments=huge)


def test_max_size_attachment_fits_in_an_envelope(demo_world, alice_keys, bob_keys):
    data = bytes(range(256)) * (cfg.MAX_ATTACHMENT_TOTAL_BYTES // 256)
    result = send("alice@pqmail.local", alice_keys, "bob@pqmail.local",
                  attachments=[Attachment("max.bin", "application/octet-stream", data)])
    assert mail_service.get_attachment(message_id=result.message_id, owner_email="bob@pqmail.local",
                                       owner_keys=bob_keys, index=0).data == data


@pytest.mark.parametrize("raw,clean", [("../../etc/passwd", "passwd"), ("C:\\Windows\\x.exe", "x.exe"),
                                       ("a<b>:c?.txt", "a_b_c_.txt"), ("", "attachment"),
                                       ("...", "attachment"), ("tab\tname.txt", "tab_name.txt")])
def test_safe_filename(raw, clean):
    assert message_format.safe_filename(raw) == clean


def test_safe_filename_length_cap_keeps_extension():
    name = message_format.safe_filename("a" * 500 + ".pdf")
    assert len(name) <= cfg.MAX_FILENAME_LEN and name.endswith(".pdf")


def test_tampered_message_withholds_attachments(demo_world, alice_keys, bob_keys):
    result = send("alice@pqmail.local", alice_keys, "bob@pqmail.local",
                  attachments=[Attachment("a.txt", "text/plain", b"data")])
    mail_service.simulate_tampering(result.message_id, "bob@pqmail.local")
    opened = open_(result.message_id, "bob@pqmail.local", bob_keys)
    assert opened.attachments == [] and not opened.trusted
    with pytest.raises(MailServiceError, match="withheld"):
        mail_service.get_attachment(message_id=result.message_id, owner_email="bob@pqmail.local",
                                    owner_keys=bob_keys, index=0)


def test_attachment_index_out_of_range(demo_world, alice_keys, bob_keys):
    result = send("alice@pqmail.local", alice_keys, "bob@pqmail.local")
    for index in (0, -1, 99):
        with pytest.raises(MailServiceError, match="not found"):
            mail_service.get_attachment(message_id=result.message_id, owner_email="bob@pqmail.local",
                                        owner_keys=bob_keys, index=index)


def test_malformed_payload_is_integrity_failure_not_crash():
    with pytest.raises(message_format.EnvelopeFormatError):
        message_format.parse_payload(b'{"subject": 1, "body": "x"}')
    with pytest.raises(message_format.EnvelopeFormatError):
        message_format.parse_payload(b'{"subject": "s", "body": "b", "attachments": [{"name": "n", "data_b64": "!!"}]}')
    assert message_format.parse_payload(b'{"subject": "s", "body": "b"}').attachments == []


# ---------------------------------------------------------------------------
# Replay protection + trash
# ---------------------------------------------------------------------------
def test_deleted_message_cannot_be_replayed(demo_world, alice_keys):
    send("alice@pqmail.local", alice_keys, "bob@pqmail.local")
    db = database.get_db()
    row = inbox_row("bob@pqmail.local")
    env = json.loads(row["envelope_json"])
    assert mail_service.import_envelope(env, "bob@pqmail.local") == "duplicate"
    assert db.trash_envelope(row["message_id"], "bob@pqmail.local")
    assert mail_service.import_envelope(env, "bob@pqmail.local") == "duplicate"      # still in trash
    assert db.purge_envelope(row["message_id"], "bob@pqmail.local")
    assert not db.has_envelope(row["message_id"])
    outcome = mail_service.import_envelope(env, "bob@pqmail.local")
    assert outcome.startswith("skipped: replay")                                    # ledger remembers
    assert db.list_envelopes("bob@pqmail.local", "inbox") == []


def test_old_envelopes_are_not_imported(demo_world, alice_keys, monkeypatch):
    send("alice@pqmail.local", alice_keys, "bob@pqmail.local")
    env = json.loads(inbox_row("bob@pqmail.local")["envelope_json"])
    with database.get_db()._connect() as conn:
        conn.execute("DELETE FROM envelopes")
        conn.execute("DELETE FROM message_ledger")
    monkeypatch.setattr(cfg, "MAX_ENVELOPE_AGE_DAYS", -1)       # everything counts as too old
    assert "too old" in mail_service.import_envelope(env, "bob@pqmail.local")


def test_trash_restore_purge_lifecycle(demo_world, alice_keys):
    send("alice@pqmail.local", alice_keys, "bob@pqmail.local")
    db = database.get_db()
    mid = inbox_row("bob@pqmail.local")["message_id"]
    assert db.stats("bob@pqmail.local")["inbox_emails"] == 1
    assert db.trash_envelope(mid, "bob@pqmail.local")
    assert db.list_envelopes("bob@pqmail.local", "inbox") == []
    assert len(db.list_envelopes("bob@pqmail.local", "inbox", trashed=True)) == 1
    stats = db.stats("bob@pqmail.local")
    assert (stats["inbox_emails"], stats["trash_emails"]) == (0, 1)
    assert not db.purge_envelope(mid, "alice@pqmail.local")          # not Alice's to purge
    assert db.restore_envelope(mid, "bob@pqmail.local")
    assert len(db.list_envelopes("bob@pqmail.local", "inbox")) == 1
    assert not db.purge_envelope(mid, "bob@pqmail.local")            # only trashed mail can be purged
    db.trash_envelope(mid, "bob@pqmail.local")
    assert db.empty_trash("bob@pqmail.local") == 1
    assert db.stats("bob@pqmail.local")["trash_emails"] == 0


def test_only_the_owner_can_trash(demo_world, alice_keys):
    send("alice@pqmail.local", alice_keys, "bob@pqmail.local")
    db = database.get_db()
    mid = inbox_row("bob@pqmail.local")["message_id"]
    assert not db.trash_envelope(mid, "alice@pqmail.local")
    assert len(db.list_envelopes("bob@pqmail.local", "inbox")) == 1


def test_pagination_and_unread_filter(demo_world, alice_keys, bob_keys):
    for i in range(5):
        send("alice@pqmail.local", alice_keys, "bob@pqmail.local", subject=f"m{i}")
    db = database.get_db()
    assert db.count_envelopes("bob@pqmail.local", "inbox") == 5
    first = db.list_envelopes("bob@pqmail.local", "inbox", limit=2, offset=0)
    second = db.list_envelopes("bob@pqmail.local", "inbox", limit=2, offset=2)
    assert len({r["message_id"] for r in first + second}) == 4
    db.mark_read(first[0]["message_id"], "bob@pqmail.local")
    assert db.count_envelopes("bob@pqmail.local", "inbox", unread_only=True) == 4


def test_migrated_database_gets_ledger_and_log(tmp_path):
    """An old-schema database is upgraded in place (ledger backfilled, log started)."""
    import sqlite3

    path = tmp_path / "old.db"
    conn = sqlite3.connect(path)
    conn.executescript("""
        CREATE TABLE users (email TEXT PRIMARY KEY, display_name TEXT NOT NULL, created_at TEXT NOT NULL,
                            is_demo INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE public_keys (email TEXT NOT NULL, fingerprint TEXT NOT NULL, kem_algo TEXT NOT NULL,
            sig_algo TEXT NOT NULL, kem_public_b64 TEXT NOT NULL, sig_public_b64 TEXT NOT NULL,
            created_at TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (email, fingerprint));
        CREATE TABLE envelopes (message_id TEXT PRIMARY KEY, sender_email TEXT NOT NULL,
            recipient_email TEXT NOT NULL, subject_hint TEXT NOT NULL, sender_fingerprint TEXT NOT NULL,
            envelope_json TEXT NOT NULL, received_at TEXT, sent_at TEXT NOT NULL,
            folder TEXT NOT NULL CHECK (folder IN ('inbox','sent')), read INTEGER NOT NULL DEFAULT 0,
            tampered_demo INTEGER NOT NULL DEFAULT 0);
        INSERT INTO users VALUES ('a@x.test','A','2026-01-01T00:00:00+00:00',0);
        INSERT INTO public_keys VALUES ('a@x.test','AAAA','ML-KEM-768','ML-DSA-65','k','s','2026-01-01T00:00:00+00:00',0);
        INSERT INTO envelopes VALUES ('pqmail-1','b@x.test','a@x.test','h','f','{}',NULL,'2026-01-01','inbox',0,0);
    """)
    conn.commit()
    conn.close()
    db = database.Database(path)
    assert db.ledger_has("a@x.test", "pqmail-1")
    report = db.verify_key_log()
    assert report["ok"] and report["entries"] == 1
    assert db.get_user("a@x.test")["source"] == "local"


# ---------------------------------------------------------------------------
# Reply / forward drafts
# ---------------------------------------------------------------------------
def test_reply_and_forward_drafts(demo_world, alice_keys, bob_keys):
    result = send("alice@pqmail.local", alice_keys, "bob@pqmail.local", subject="Plan",
                  body="line one\n\nline three",
                  attachments=[Attachment("a.txt", "text/plain", b"x")])
    opened = open_(result.message_id, "bob@pqmail.local", bob_keys)
    reply = mail_service.build_draft(opened, "bob@pqmail.local", "reply")
    assert reply["to"] == "alice@pqmail.local" and reply["subject"] == "Re: Plan"
    assert "> line one\n>\n> line three" in reply["body"]
    fwd = mail_service.build_draft(opened, "bob@pqmail.local", "forward")
    assert fwd["to"] == "" and fwd["subject"] == "Fwd: Plan" and "Forwarded message" in fwd["body"]
    assert "attachment(s) were not forwarded" in fwd["body"]
    again = mail_service.build_draft(
        mail_service.OpenResult(**{**opened.__dict__, "subject": "Re: Plan"}), "bob@pqmail.local", "reply")
    assert again["subject"] == "Re: Plan"                    # prefix is not stacked


def test_reply_to_own_sent_message_goes_to_recipient(demo_world, alice_keys):
    send("alice@pqmail.local", alice_keys, "bob@pqmail.local", subject="Hi")
    row = database.get_db().list_envelopes("alice@pqmail.local", "sent")[0]
    opened = open_(row["message_id"], "alice@pqmail.local", alice_keys)
    assert mail_service.build_draft(opened, "alice@pqmail.local", "reply")["to"] == "bob@pqmail.local"


def test_cannot_reply_to_unverified_message(demo_world, alice_keys, bob_keys):
    result = send("alice@pqmail.local", alice_keys, "bob@pqmail.local")
    mail_service.simulate_tampering(result.message_id, "bob@pqmail.local")
    opened = open_(result.message_id, "bob@pqmail.local", bob_keys)
    with pytest.raises(MailServiceError, match="verified"):
        mail_service.build_draft(opened, "bob@pqmail.local", "reply")


# ---------------------------------------------------------------------------
# Key transparency log
# ---------------------------------------------------------------------------
def test_log_records_publish_import_and_rotation(demo_world):
    email, keys = make_user("log")
    db = database.get_db()
    before = len(db.list_key_log())
    info = rotate_keys(cfg.KEYS_DIR, email, PASS, PASS + "2")
    db.publish_public_keys(email=email, kem_algo=cfg.KEM_ALGORITHM, sig_algo=cfg.SIG_ALGORITHM,
                           kem_public_b64=info["kem_public_b64"], sig_public_b64=info["sig_public_b64"],
                           fingerprint=info["sig_fingerprint"], x25519_public_b64=info["x25519_public_b64"])
    entries = db.list_key_log(email)
    assert [e["action"] for e in entries] == ["publish", "publish"]
    assert len(db.list_key_log()) == before + 1
    report = db.verify_key_log()
    assert report["ok"] and report["entries"] == len(db.list_key_log())
    assert len(report["head"]) == 64


def test_log_detects_edited_entries(demo_world):
    make_user("tamper")
    db = database.get_db()
    assert db.verify_key_log()["ok"]
    with db._connect() as conn:
        conn.execute("UPDATE key_log SET fingerprint = 'EVIL' WHERE seq = (SELECT MAX(seq) FROM key_log)")
    report = db.verify_key_log()
    assert not report["ok"] and any("do not match their hash" in e for e in report["chain_errors"])


def test_log_detects_deleted_or_reordered_entries(demo_world):
    make_user("gap1")
    make_user("gap2")
    db = database.get_db()
    with db._connect() as conn:
        conn.execute("DELETE FROM key_log WHERE seq = (SELECT MIN(seq) + 1 FROM key_log)")
    report = db.verify_key_log()
    assert not report["ok"] and report["chain_errors"]


def test_log_detects_silent_directory_key_swap(demo_world):
    email, _ = make_user("swap")
    db = database.get_db()
    other = create_keystore_info()
    with db._connect() as conn:                              # attacker edits the DB directly
        conn.execute("UPDATE public_keys SET kem_public_b64 = ? WHERE email = ?",
                     (other["kem_public_b64"], email))
    report = db.verify_key_log()
    assert not report["ok"] and any("differs from the logged" in m for m in report["directory_mismatches"])
    assert report["chain_errors"] == []                       # the log itself is intact


def test_log_covers_imports_replacements_and_revocation(demo_world):
    db = database.get_db()
    email = f"ext-{uuid.uuid4().hex[:6]}@remote.test"

    def bundle(info):
        return base64.b64encode(json.dumps({
            "email": email, "algorithms": {"kem": cfg.KEM_ALGORITHM, "signature": cfg.SIG_ALGORITHM},
            "kem_public_key_b64": info["kem_public_b64"],
            "signature_public_key_b64": info["sig_public_b64"],
            "x25519_public_key_b64": info["x25519_public_b64"]}).encode()).decode()

    first, second = create_keystore_info(), create_keystore_info()
    directory.import_bundle(bundle(first))
    directory.import_bundle(bundle(second), confirm_replace=True)
    db.revoke_public_keys(email)
    assert [e["action"] for e in reversed(db.list_key_log(email))] == ["import", "replace", "revoke", "revoke"]
    assert db.verify_key_log()["ok"]
    assert db.get_active_public_key(email) is None


def test_attach_x25519_is_logged(demo_world):
    email, keys = make_user("att")
    db = database.get_db()
    with db._connect() as conn:
        conn.execute("UPDATE public_keys SET x25519_public_b64 = NULL WHERE email = ?", (email,))
        conn.execute("DELETE FROM key_log WHERE email = ?", (email,))
    # the chain is now broken by the manual delete: rebuild it as a fresh DB would
    fresh = database.Database(db.db_path.parent / "fresh.db")
    fresh.upsert_user(email, "X")
    row = db.get_active_public_key(email)
    fresh.publish_public_keys(email, cfg.KEM_ALGORITHM, cfg.SIG_ALGORITHM, row["kem_public_b64"],
                              row["sig_public_b64"], row["fingerprint"])
    assert directory.sync_own_keys(fresh, keys) == "attached"
    assert [e["action"] for e in reversed(fresh.list_key_log(email))] == ["publish", "attach-x25519"]
    assert fresh.verify_key_log()["ok"]
