"""SQLite persistence: users, contacts, public keys, envelopes, and stats.

Design notes
============
* Email bodies are only ever stored **encrypted** (the whole RFC-8321-style
  envelope is persisted as JSON). Plaintext exists solely in RAM while a
  message is being composed or opened, and is never written to disk.
* This file is demo-oriented; in Real Email Mode the same envelopes are
  sent through SMTP/IMAP instead of (or in addition to) this mailbox.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from app import config as cfg
from app.log import event

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    email          TEXT PRIMARY KEY,
    display_name   TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    is_demo        INTEGER NOT NULL DEFAULT 0,
    -- 'local': has a keystore on this machine; 'imported': public key only
    source         TEXT NOT NULL DEFAULT 'local'
);

CREATE TABLE IF NOT EXISTS public_keys (
    email              TEXT NOT NULL,
    fingerprint        TEXT NOT NULL,
    kem_algo           TEXT NOT NULL,
    sig_algo           TEXT NOT NULL,
    kem_public_b64     TEXT NOT NULL,
    sig_public_b64     TEXT NOT NULL,
    created_at         TEXT NOT NULL,
    revoked            INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (email, fingerprint),
    FOREIGN KEY (email) REFERENCES users(email) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS envelopes (
    message_id         TEXT PRIMARY KEY,
    sender_email       TEXT NOT NULL,
    recipient_email    TEXT NOT NULL,
    subject_hint       TEXT NOT NULL,          -- non-sensitive label ("Encrypted message")
    sender_fingerprint TEXT NOT NULL,
    envelope_json      TEXT NOT NULL,          -- full encrypted envelope
    received_at        TEXT,
    sent_at            TEXT NOT NULL,
    folder             TEXT NOT NULL CHECK (folder IN ('inbox', 'sent')),
    read               INTEGER NOT NULL DEFAULT 0,
    tampered_demo      INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (sender_email) REFERENCES users(email) ON DELETE CASCADE,
    FOREIGN KEY (recipient_email) REFERENCES users(email) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_envelopes_recipient ON envelopes(recipient_email, folder);
CREATE INDEX IF NOT EXISTS idx_envelopes_sender ON envelopes(sender_email, folder);

CREATE TABLE IF NOT EXISTS contacts (
    owner_email        TEXT NOT NULL,
    contact_email      TEXT NOT NULL,
    label              TEXT,
    added_at           TEXT NOT NULL,
    PRIMARY KEY (owner_email, contact_email),
    FOREIGN KEY (owner_email) REFERENCES users(email) ON DELETE CASCADE
);

-- Every message id a mailbox has ever received. It survives deletion, so a
-- captured envelope cannot be replayed into the mailbox after the user deleted it.
CREATE TABLE IF NOT EXISTS message_ledger (
    owner_email        TEXT NOT NULL,
    message_id         TEXT NOT NULL,
    seen_at            TEXT NOT NULL,
    PRIMARY KEY (owner_email, message_id)
);

-- Append-only, hash-chained log of every change to the public-key directory.
CREATE TABLE IF NOT EXISTS key_log (
    seq                INTEGER PRIMARY KEY,
    email              TEXT NOT NULL,
    action             TEXT NOT NULL,
    fingerprint        TEXT NOT NULL,
    key_digest         TEXT NOT NULL,
    created_at         TEXT NOT NULL,
    prev_hash          TEXT NOT NULL,
    entry_hash         TEXT NOT NULL
);

-- TOTP replay protection and single-use recovery codes.
CREATE TABLE IF NOT EXISTS totp_state (
    email              TEXT PRIMARY KEY,
    last_step          INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS recovery_used (
    email              TEXT NOT NULL,
    code_hash          TEXT NOT NULL,
    used_at            TEXT NOT NULL,
    PRIMARY KEY (email, code_hash)
);
"""

GENESIS_HASH = "0" * 64


def key_digest(kem_public_b64: str, sig_public_b64: str, x25519_public_b64: str | None) -> str:
    """Digest of the complete public key set published for one identity."""
    material = "|".join((kem_public_b64, sig_public_b64, x25519_public_b64 or ""))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _log_entry_hash(seq: int, email: str, action: str, fingerprint: str, digest: str,
                    created_at: str, prev_hash: str) -> str:
    material = "|".join((str(seq), email, action, fingerprint, digest, created_at, prev_hash))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


# SQL predicate (two "?" parameters: owner twice) selecting rows in ``owner``'s mailbox.
_OWNER = ("((folder = 'inbox' AND recipient_email = ?) OR "
          "(folder = 'sent' AND sender_email = ?))")


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Database:
    """Thin, explicit wrapper over sqlite3 (row factory + param binding)."""

    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(_SCHEMA)
            self._migrate(conn)

    @staticmethod
    def _migrate(conn: sqlite3.Connection) -> None:
        """Bring databases created by older versions up to the current schema."""
        def columns(table: str) -> set[str]:
            return {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}

        if "source" not in columns("users"):
            conn.execute("ALTER TABLE users ADD COLUMN source TEXT NOT NULL DEFAULT 'local'")
        if "x25519_public_b64" not in columns("public_keys"):
            conn.execute("ALTER TABLE public_keys ADD COLUMN x25519_public_b64 TEXT")
        if "deleted_at" not in columns("envelopes"):
            conn.execute("ALTER TABLE envelopes ADD COLUMN deleted_at TEXT")
        # Older databases: remember what each inbox already holds, and start the
        # transparency log with the keys that are already in the directory.
        conn.execute(
            """INSERT OR IGNORE INTO message_ledger (owner_email, message_id, seen_at)
               SELECT recipient_email, message_id, COALESCE(received_at, sent_at)
               FROM envelopes WHERE folder = 'inbox'""")
        if conn.execute("SELECT COUNT(*) AS n FROM key_log").fetchone()["n"] == 0:
            for row in conn.execute(
                    "SELECT * FROM public_keys ORDER BY created_at, rowid").fetchall():
                Database._append_key_log(
                    conn, row["email"], "publish", row["fingerprint"],
                    key_digest(row["kem_public_b64"], row["sig_public_b64"], row["x25519_public_b64"]),
                    created_at=row["created_at"])

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            with conn:  # commits on success, rolls back on exception
                yield conn
        finally:
            conn.close()

    # -- users ---------------------------------------------------------------
    def upsert_user(self, email: str, display_name: str, is_demo: bool = False,
                    source: str = "local") -> None:
        """Create a user, or update the display name of an existing one.

        An existing user's ``source`` is never changed: an imported contact can
        not be silently turned into (or take over) a local identity.
        """
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO users (email, display_name, created_at, is_demo, source)
                   VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(email) DO UPDATE SET display_name = excluded.display_name""",
                (email.lower().strip(), display_name.strip(), utc_now_iso(),
                 int(is_demo), source),
            )

    def get_user(self, email: str) -> sqlite3.Row | None:
        with self._connect() as conn:
            return conn.execute(
                "SELECT * FROM users WHERE email = ?", (email.lower().strip(),)
            ).fetchone()

    def list_users(self) -> list[sqlite3.Row]:
        with self._connect() as conn:
            return conn.execute(
                "SELECT * FROM users ORDER BY created_at"
            ).fetchall()

    # -- public keys ----------------------------------------------------------
    @staticmethod
    def _append_key_log(conn: sqlite3.Connection, email: str, action: str, fingerprint: str,
                        digest: str, created_at: str | None = None) -> None:
        last = conn.execute(
            "SELECT seq, entry_hash FROM key_log ORDER BY seq DESC LIMIT 1").fetchone()
        seq = (last["seq"] + 1) if last else 1
        prev_hash = last["entry_hash"] if last else GENESIS_HASH
        created_at = created_at or utc_now_iso()
        email = email.lower().strip()
        conn.execute(
            """INSERT INTO key_log (seq, email, action, fingerprint, key_digest, created_at,
                                    prev_hash, entry_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (seq, email, action, fingerprint, digest, created_at, prev_hash,
             _log_entry_hash(seq, email, action, fingerprint, digest, created_at, prev_hash)))

    def publish_public_keys(self, email: str, kem_algo: str, sig_algo: str,
                            kem_public_b64: str, sig_public_b64: str,
                            fingerprint: str, x25519_public_b64: str | None = None,
                            action: str = "publish") -> None:
        """Add a key set to the directory (idempotent) and record it in the key log.

        When the same signing key is already listed without an X25519 key, the
        X25519 key is attached to that entry instead (identity upgrade).
        """
        email = email.lower().strip()
        with self._connect() as conn:
            cur = conn.execute(
                """INSERT OR IGNORE INTO public_keys
                   (email, fingerprint, kem_algo, sig_algo,
                    kem_public_b64, sig_public_b64, created_at, revoked, x25519_public_b64)
                   VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)""",
                (email, fingerprint, kem_algo, sig_algo,
                 kem_public_b64, sig_public_b64, utc_now_iso(), x25519_public_b64),
            )
            if cur.rowcount:
                self._append_key_log(conn, email, action, fingerprint,
                                     key_digest(kem_public_b64, sig_public_b64, x25519_public_b64))
            elif x25519_public_b64:
                upd = conn.execute(
                    """UPDATE public_keys SET x25519_public_b64 = ?
                       WHERE email = ? AND fingerprint = ? AND x25519_public_b64 IS NULL
                         AND kem_public_b64 = ? AND sig_public_b64 = ?""",
                    (x25519_public_b64, email, fingerprint, kem_public_b64, sig_public_b64))
                if upd.rowcount:
                    self._append_key_log(
                        conn, email, "attach-x25519", fingerprint,
                        key_digest(kem_public_b64, sig_public_b64, x25519_public_b64))
        event("Public keys published to directory", user=email)

    def get_active_public_key(self, email: str) -> sqlite3.Row | None:
        """Most recent non-revoked public key entry for a user."""
        with self._connect() as conn:
            return conn.execute(
                """SELECT * FROM public_keys
                   WHERE email = ? AND revoked = 0
                   ORDER BY created_at DESC, rowid DESC LIMIT 1""",
                (email.lower().strip(),),
            ).fetchone()

    def get_public_key_by_fingerprint(self, email: str, fingerprint: str) -> sqlite3.Row | None:
        """A specific (possibly superseded) non-revoked key of ``email``.

        Used to verify signatures on mail sent before the sender rotated keys.
        """
        with self._connect() as conn:
            return conn.execute(
                """SELECT * FROM public_keys
                   WHERE email = ? AND fingerprint = ? AND revoked = 0""",
                (email.lower().strip(), fingerprint),
            ).fetchone()

    def list_public_keys(self, email: str) -> list[sqlite3.Row]:
        with self._connect() as conn:
            return conn.execute(
                """SELECT * FROM public_keys
                   WHERE email = ? ORDER BY created_at DESC, rowid DESC""",
                (email.lower().strip(),),
            ).fetchall()

    def revoke_public_keys(self, email: str) -> int:
        email = email.lower().strip()
        with self._connect() as conn:
            for row in conn.execute(
                    "SELECT * FROM public_keys WHERE email = ? AND revoked = 0", (email,)).fetchall():
                self._append_key_log(
                    conn, email, "revoke", row["fingerprint"],
                    key_digest(row["kem_public_b64"], row["sig_public_b64"], row["x25519_public_b64"]))
            cur = conn.execute(
                "UPDATE public_keys SET revoked = 1 WHERE email = ? AND revoked = 0",
                (email,),
            )
        event("Public keys revoked", user=email)
        return cur.rowcount

    # -- key transparency log --------------------------------------------------------
    def list_key_log(self, email: str | None = None, limit: int | None = None) -> list[sqlite3.Row]:
        query, params = "SELECT * FROM key_log", []
        if email:
            query += " WHERE email = ?"
            params.append(email.lower().strip())
        query += " ORDER BY seq DESC"
        if limit:
            query += " LIMIT ?"
            params.append(limit)
        with self._connect() as conn:
            return conn.execute(query, params).fetchall()

    def verify_key_log(self) -> dict[str, Any]:
        """Re-compute the whole hash chain and cross-check the live directory.

        Returns ``{"ok", "entries", "head", "chain_errors", "directory_mismatches"}``.
        ``directory_mismatches`` lists directory rows whose keys differ from what the
        log recorded - i.e. a key that was swapped *without* going through the app.
        """
        chain_errors: list[str] = []
        latest_digest: dict[tuple[str, str], str] = {}
        prev = GENESIS_HASH
        count = 0
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM key_log ORDER BY seq").fetchall()
            keys = conn.execute("SELECT * FROM public_keys").fetchall()
        for index, row in enumerate(rows, start=1):
            count += 1
            if row["seq"] != index:
                chain_errors.append(f"entry #{index}: sequence gap or reorder (found {row['seq']})")
            if row["prev_hash"] != prev:
                chain_errors.append(f"entry #{row['seq']}: previous-hash link is broken")
            expected = _log_entry_hash(row["seq"], row["email"], row["action"], row["fingerprint"],
                                       row["key_digest"], row["created_at"], row["prev_hash"])
            if row["entry_hash"] != expected:
                chain_errors.append(f"entry #{row['seq']}: contents do not match their hash")
            prev = row["entry_hash"]
            if row["action"] != "revoke":
                latest_digest[(row["email"], row["fingerprint"])] = row["key_digest"]
        mismatches: list[str] = []
        for row in keys:
            expected_digest = latest_digest.get((row["email"], row["fingerprint"]))
            actual = key_digest(row["kem_public_b64"], row["sig_public_b64"], row["x25519_public_b64"])
            if expected_digest is None:
                mismatches.append(f"{row['email']} [{row['fingerprint'][:9]}…]: key is in the directory but not in the log")
            elif expected_digest != actual:
                mismatches.append(f"{row['email']} [{row['fingerprint'][:9]}…]: key differs from the logged one")
        return {"ok": not chain_errors and not mismatches, "entries": count, "head": prev,
                "chain_errors": chain_errors, "directory_mismatches": mismatches}

    # -- TOTP / recovery codes -----------------------------------------------------
    def totp_last_step(self, email: str) -> int:
        with self._connect() as conn:
            row = conn.execute("SELECT last_step FROM totp_state WHERE email = ?",
                               (email.lower().strip(),)).fetchone()
        return row["last_step"] if row else 0

    def totp_record_step(self, email: str, step: int) -> bool:
        """Remember the newest accepted time-step; False if it was already used."""
        email = email.lower().strip()
        with self._connect() as conn:
            conn.execute("INSERT OR IGNORE INTO totp_state (email, last_step) VALUES (?, 0)", (email,))
            cur = conn.execute(
                "UPDATE totp_state SET last_step = ? WHERE email = ? AND last_step < ?",
                (step, email, step))
        return cur.rowcount > 0

    def recovery_use(self, email: str, code_hash: str) -> bool:
        """Mark a recovery code as used; False when it was already consumed."""
        with self._connect() as conn:
            cur = conn.execute(
                "INSERT OR IGNORE INTO recovery_used (email, code_hash, used_at) VALUES (?, ?, ?)",
                (email.lower().strip(), code_hash, utc_now_iso()))
        return cur.rowcount > 0

    def recovery_used_count(self, email: str) -> int:
        with self._connect() as conn:
            return conn.execute("SELECT COUNT(*) AS n FROM recovery_used WHERE email = ?",
                                (email.lower().strip(),)).fetchone()["n"]

    def totp_reset(self, email: str) -> None:
        email = email.lower().strip()
        with self._connect() as conn:
            conn.execute("DELETE FROM totp_state WHERE email = ?", (email,))
            conn.execute("DELETE FROM recovery_used WHERE email = ?", (email,))

    # -- envelopes --------------------------------------------------------------
    def store_envelope(self, *, message_id: str, sender: str, recipient: str,
                       subject_hint: str, sender_fingerprint: str,
                       envelope: dict[str, Any], folder: str) -> None:
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO envelopes
                   (message_id, sender_email, recipient_email, subject_hint,
                    sender_fingerprint, envelope_json, sent_at, received_at, folder)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (message_id, sender.lower().strip(), recipient.lower().strip(),
                 subject_hint, sender_fingerprint, json.dumps(envelope),
                 envelope.get("timestamp", utc_now_iso()),
                 utc_now_iso() if folder == "inbox" else None, folder),
            )
            if folder == "inbox":
                conn.execute(
                    "INSERT OR IGNORE INTO message_ledger (owner_email, message_id, seen_at) "
                    "VALUES (?, ?, ?)",
                    (recipient.lower().strip(), message_id, utc_now_iso()))

    def has_envelope(self, message_id: str) -> bool:
        with self._connect() as conn:
            return conn.execute(
                "SELECT 1 FROM envelopes WHERE message_id = ?", (message_id,)
            ).fetchone() is not None

    def update_envelope(self, message_id: str, owner: str, envelope: dict[str, Any],
                        tampered_demo: bool = False) -> bool:
        """Replace a stored envelope (tamper demo); only the mailbox owner may."""
        who = owner.lower().strip()
        with self._connect() as conn:
            cur = conn.execute(
                "UPDATE envelopes SET envelope_json = ?, tampered_demo = ? "
                "WHERE message_id = ? AND " + _OWNER,
                (json.dumps(envelope), int(tampered_demo), message_id, who, who),
            )
        return cur.rowcount > 0

    def ledger_has(self, owner: str, message_id: str) -> bool:
        """True if ``owner``'s mailbox has ever received ``message_id`` (even if deleted)."""
        with self._connect() as conn:
            return conn.execute(
                "SELECT 1 FROM message_ledger WHERE owner_email = ? AND message_id = ?",
                (owner.lower().strip(), message_id)).fetchone() is not None

    @staticmethod
    def _mailbox_filter(owner: str, folder: str, trashed: bool, unread_only: bool) -> tuple[str, list]:
        who = owner.lower().strip()
        if folder == "inbox":
            where, params = "folder = 'inbox' AND recipient_email = ?", [who]
        else:
            where, params = "folder = 'sent' AND sender_email = ?", [who]
        where += " AND deleted_at IS NOT NULL" if trashed else " AND deleted_at IS NULL"
        if unread_only and folder == "inbox":
            where += " AND read = 0"
        return where, params

    def list_envelopes(self, owner: str, folder: str, *, trashed: bool = False,
                       unread_only: bool = False, limit: int | None = None,
                       offset: int = 0) -> list[sqlite3.Row]:
        """List envelopes where `owner` is recipient (inbox) or sender (sent).

        Trashed (soft-deleted) rows are excluded unless ``trashed`` is true.
        """
        where, params = self._mailbox_filter(owner, folder, trashed, unread_only)
        query = f"SELECT * FROM envelopes WHERE {where} ORDER BY sent_at DESC, rowid DESC"
        if limit is not None:
            query += " LIMIT ? OFFSET ?"
            params += [limit, max(0, offset)]
        with self._connect() as conn:
            return conn.execute(query, params).fetchall()

    def count_envelopes(self, owner: str, folder: str, *, trashed: bool = False,
                        unread_only: bool = False) -> int:
        where, params = self._mailbox_filter(owner, folder, trashed, unread_only)
        with self._connect() as conn:
            return conn.execute(f"SELECT COUNT(*) AS n FROM envelopes WHERE {where}",
                                params).fetchone()["n"]

    def trash_envelope(self, message_id: str, owner: str) -> bool:
        who = owner.lower().strip()
        with self._connect() as conn:
            cur = conn.execute(
                "UPDATE envelopes SET deleted_at = ? WHERE message_id = ? AND deleted_at IS NULL AND "
                + _OWNER, (utc_now_iso(), message_id, who, who))
        return cur.rowcount > 0

    def restore_envelope(self, message_id: str, owner: str) -> bool:
        who = owner.lower().strip()
        with self._connect() as conn:
            cur = conn.execute(
                "UPDATE envelopes SET deleted_at = NULL WHERE message_id = ? AND deleted_at IS NOT NULL AND "
                + _OWNER, (message_id, who, who))
        return cur.rowcount > 0

    def purge_envelope(self, message_id: str, owner: str) -> bool:
        """Permanently delete a trashed message. The replay ledger entry is kept."""
        who = owner.lower().strip()
        with self._connect() as conn:
            cur = conn.execute(
                "DELETE FROM envelopes WHERE message_id = ? AND deleted_at IS NOT NULL AND "
                + _OWNER, (message_id, who, who))
        return cur.rowcount > 0

    def empty_trash(self, owner: str) -> int:
        who = owner.lower().strip()
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM envelopes WHERE deleted_at IS NOT NULL AND " + _OWNER,
                               (who, who))
        return cur.rowcount

    def get_envelope(self, message_id: str, owner: str) -> sqlite3.Row | None:
        """Fetch one envelope from ``owner``'s own mailbox.

        Inbox rows belong to the recipient and sent rows to the sender: the
        sender of a message must not be able to read, mark or modify the
        recipient's copy (or vice versa).
        """
        who = owner.lower().strip()
        with self._connect() as conn:
            return conn.execute(
                "SELECT * FROM envelopes WHERE message_id = ? AND " + _OWNER,
                (message_id, who, who),
            ).fetchone()

    def mark_read(self, message_id: str, owner: str) -> None:
        with self._connect() as conn:
            who = owner.lower().strip()
            conn.execute(
                "UPDATE envelopes SET read = 1 WHERE message_id = ? AND " + _OWNER,
                (message_id, who, who),
            )

    def mark_tampered_demo(self, message_id: str, owner: str) -> None:
        with self._connect() as conn:
            who = owner.lower().strip()
            conn.execute(
                "UPDATE envelopes SET tampered_demo = 1 WHERE message_id = ? AND " + _OWNER,
                (message_id, who, who),
            )

    # -- contacts ----------------------------------------------------------
    def add_contact(self, owner: str, contact: str, label: str | None = None) -> None:
        with self._connect() as conn:
            conn.execute(
                """INSERT OR IGNORE INTO contacts (owner_email, contact_email, label, added_at)
                   VALUES (?, ?, ?, ?)""",
                (owner.lower().strip(), contact.lower().strip(), label, utc_now_iso()),
            )

    def remove_contact(self, owner: str, contact: str) -> bool:
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM contacts WHERE owner_email = ? AND contact_email = ?",
                               (owner.lower().strip(), contact.lower().strip()))
        return cur.rowcount > 0

    def list_contacts(self, owner: str) -> list[sqlite3.Row]:
        with self._connect() as conn:
            return conn.execute(
                """SELECT c.contact_email, c.label, c.added_at, u.display_name
                   FROM contacts c LEFT JOIN users u ON u.email = c.contact_email
                   WHERE c.owner_email = ? ORDER BY c.added_at""",
                (owner.lower().strip(),),
            ).fetchall()

    # -- statistics ----------------------------------------------------------
    def stats(self, owner: str) -> dict[str, int]:
        """Mailbox counters for ``owner`` only (never other users' totals)."""
        owner = owner.lower().strip()
        with self._connect() as conn:
            inbox = conn.execute(
                "SELECT COUNT(*) AS n, COALESCE(SUM(read = 0), 0) AS unread "
                "FROM envelopes WHERE recipient_email = ? AND folder = 'inbox' AND deleted_at IS NULL",
                (owner,),
            ).fetchone()
            sent = conn.execute(
                "SELECT COUNT(*) AS n FROM envelopes "
                "WHERE sender_email = ? AND folder = 'sent' AND deleted_at IS NULL",
                (owner,),
            ).fetchone()
            trash = conn.execute(
                "SELECT COUNT(*) AS n FROM envelopes WHERE deleted_at IS NOT NULL AND " + _OWNER,
                (owner, owner),
            ).fetchone()
            users = conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()
        return {
            "total_emails": (inbox["n"] or 0) + (sent["n"] or 0),
            "inbox_emails": inbox["n"] or 0,
            "unread_emails": inbox["unread"] or 0,
            "sent_emails": sent["n"] or 0,
            "trash_emails": trash["n"] or 0,
            "users": users["n"] or 0,
        }


_default_db: Database | None = None


def get_db() -> Database:
    """Process-wide default database (created lazily)."""
    global _default_db
    if _default_db is None:
        cfg.ensure_data_dirs()
        _default_db = Database(cfg.DB_PATH)
    return _default_db


def set_db(db: Database) -> None:
    """Override the default database (used by tests)."""
    global _default_db
    _default_db = db
