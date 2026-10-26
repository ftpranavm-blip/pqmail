"""Attack lab: run real attacks against PQMail's own code and show what stops them.

Every scenario executes in a **sandbox**: a temporary SQLite database and freshly
generated in-memory identities (alice / bob / mallory / eve @lab.test). It calls
the same ``mail_service`` / ``directory`` / ``message_format`` functions the real
app uses, so a "BLOCKED" result is a live check of the actual defences - and if a
defence were ever removed, the matching test fails.
"""
from __future__ import annotations

import base64
import json
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from app import config as cfg
from app import db as database
from app.crypto import fingerprints, pqc
from app.crypto.key_manager import IdentityKeys, generate_identity_keys, utc_now_iso
from app.email import message_format
from app.security import LoginThrottle
from app.services import directory, mail_service


@dataclass
class ScenarioResult:
    id: str
    title: str
    attacker_goal: str
    defence: str
    steps: list[str] = field(default_factory=list)
    outcome: str = ""
    blocked: bool = False


class _Lab:
    """Sandbox: temp database + generated identities."""

    def __init__(self, directory_path: Path):
        self.db = database.Database(directory_path / "lab.db")
        self.alice = self.identity("alice@lab.test")
        self.bob = self.identity("bob@lab.test")
        self.mallory = self.identity("mallory@lab.test")
        self.eve = self.identity("eve@lab.test")

    def identity(self, email: str, publish: bool = True) -> IdentityKeys:
        kem, dsa, xkey = generate_identity_keys()
        keys = IdentityKeys(email=email, kem=kem, dsa=dsa, created_at=utc_now_iso(), x25519=xkey)
        self.db.upsert_user(email, email.split("@")[0].title(), source="local")
        if publish:
            self.db.publish_public_keys(
                email, cfg.KEM_ALGORITHM, cfg.SIG_ALGORITHM,
                base64.b64encode(kem.public_bytes()).decode(),
                base64.b64encode(dsa.public_bytes()).decode(),
                fingerprints.public_key_fingerprint(dsa.public_bytes()),
                x25519_public_b64=base64.b64encode(xkey.public_bytes()).decode())
        return keys

    def send(self, sender: IdentityKeys, recipient: IdentityKeys, subject="Wire transfer approval",
             body="Transfer 10,000 to account 4471 — approved.") -> dict:
        result = mail_service.send_email(sender_email=sender.email, recipient_email=recipient.email,
                                         subject=subject, body=body, sender_keys=sender, db=self.db)
        row = self.db.get_envelope(result.message_id, recipient.email)
        return json.loads(row["envelope_json"])

    def open(self, message_id: str, owner: IdentityKeys):
        return mail_service.open_email(message_id=message_id, owner_email=owner.email,
                                       owner_keys=owner, db=self.db)


def _short(fp: str) -> str:
    return fp[:14] + "…"


# ---------------------------------------------------------------------------
# Scenarios
# ---------------------------------------------------------------------------
def eavesdropper(lab: _Lab) -> ScenarioResult:
    r = ScenarioResult("eavesdrop", "Eavesdropper copies a message in transit",
                       "Read a message addressed to Bob.",
                       "Hybrid X25519 + ML-KEM-768 key exchange, AES-256-GCM encryption.")
    env = lab.send(lab.alice, lab.bob)
    r.steps.append(f"Eve captures the envelope ({len(env['ciphertext'])} base64 characters of ciphertext).")
    payload = mail_service._decrypt_payload(env, lab.eve, env["message_id"])
    r.steps.append("Eve tries to decrypt it with her own keys (the only keys she has).")
    r.blocked = payload is None
    r.outcome = ("Decryption failed: Eve's keys derive a different shared secret, so the AES-GCM tag does not verify."
                 if r.blocked else "Eve read the message!")
    return r


def bit_flip(lab: _Lab) -> ScenarioResult:
    r = ScenarioResult("bitflip", "Attacker flips one bit of the ciphertext",
                       "Silently alter the content of a message.",
                       "AES-GCM authentication tag + ML-DSA-65 signature; fail-closed display.")
    env = lab.send(lab.alice, lab.bob)
    tampered = message_format.tamper_ciphertext(env)
    lab.db.update_envelope(env["message_id"], lab.bob.email, tampered, tampered_demo=True)
    opened = lab.open(env["message_id"], lab.bob)
    r.steps += ["One bit of the stored ciphertext is flipped.",
                f"Bob opens it: signature valid = {opened.signature_valid}, integrity valid = {opened.integrity_valid}."]
    r.blocked = not opened.trusted and opened.body == ""
    r.outcome = "Both checks fail and the content is withheld." if r.blocked else "Tampered text was displayed!"
    return r


def readdress(lab: _Lab) -> ScenarioResult:
    r = ScenarioResult("readdress", "Attacker re-addresses a message",
                       "Make Bob's message look like it was written to Mallory.",
                       "Signature and AES-GCM associated data both cover sender, recipient and key data.")
    env = lab.send(lab.alice, lab.bob)
    spoofed = dict(env, recipient=lab.mallory.email)
    message_format.validate_envelope(spoofed)             # structurally fine...
    sig_ok = pqc.verify(lab.alice.dsa.public_key, base64.b64decode(env["signature"]),
                        message_format.canonical_envelope_bytes(spoofed))
    payload = mail_service._decrypt_payload(spoofed, lab.bob, env["message_id"])
    r.steps += ["The recipient field is changed from Bob to Mallory; the envelope is still well-formed.",
                f"Signature still valid: {sig_ok}. AES-GCM still decrypts: {payload is not None}."]
    r.blocked = (not sig_ok) and payload is None
    r.outcome = "The signature breaks AND decryption fails: the edit is detected twice over." if r.blocked \
        else "Re-addressing went unnoticed!"
    return r


def forged_sender(lab: _Lab) -> ScenarioResult:
    r = ScenarioResult("forge", "Mallory impersonates Alice",
                       "Send Bob a message that claims to be from Alice.",
                       "Signatures are checked against the key Alice registered; unknown keys are untrusted.")
    forged = mail_service.encrypt_and_sign(
        sender_email=lab.alice.email, recipient_email=lab.bob.email, subject="Please wire the money",
        body="From your boss (really).", sender_keys=lab.mallory,
        recipient_public_b64=base64.b64encode(lab.bob.kem_public_bytes).decode(),
        recipient_x25519_b64=base64.b64encode(lab.bob.x25519_public_bytes).decode())
    lab.db.store_envelope(message_id=forged["message_id"], sender=lab.alice.email, recipient=lab.bob.email,
                          subject_hint="x", sender_fingerprint=forged["sender_key_fingerprint"],
                          envelope=forged, folder="inbox")
    opened = lab.open(forged["message_id"], lab.bob)
    r.steps += ["Mallory encrypts a message to Bob, puts alice@lab.test in the sender field and signs it with HER key.",
                f"Bob's client looks for a key of alice@lab.test with fingerprint {_short(forged['sender_key_fingerprint'])}: "
                f"found = {opened.sender_key_known}."]
    r.blocked = not opened.trusted and opened.body == ""
    r.outcome = "Rejected: no registered Alice key matches, so the message is untrusted and withheld." if r.blocked \
        else "The forged message was accepted!"
    return r


def replay(lab: _Lab) -> ScenarioResult:
    r = ScenarioResult("replay", "Attacker replays a captured message",
                       "Re-deliver an old message after Bob deleted it.",
                       "Per-mailbox ledger of every message id ever received (survives deletion).")
    env = lab.send(lab.alice, lab.bob)
    first = mail_service.import_envelope(env, lab.bob.email, lab.db)
    lab.db.trash_envelope(env["message_id"], lab.bob.email)
    lab.db.purge_envelope(env["message_id"], lab.bob.email)
    second = mail_service.import_envelope(env, lab.bob.email, lab.db)
    r.steps += [f"The envelope is delivered again while it is still stored → {first!r}.",
                "Bob deletes it permanently, then the attacker re-sends the captured copy.",
                f"Import result: {second!r}."]
    r.blocked = second.startswith("skipped: replay")
    r.outcome = "Refused: the mailbox remembers it already received this message." if r.blocked \
        else "The replayed message came back!"
    return r


def key_substitution(lab: _Lab) -> ScenarioResult:
    r = ScenarioResult("keyswap", "Mallory publishes her key under Bob's address",
                       "Get future mail for Bob encrypted to Mallory instead.",
                       "Imports can never replace a local identity; directory changes are logged.")
    bundle = json.loads(base64.b64decode(lab.mallory.export_public_bundle_b64()))
    bundle["email"] = lab.bob.email
    blob = base64.b64encode(json.dumps(bundle).encode()).decode()
    before = lab.db.get_active_public_key(lab.bob.email)["fingerprint"]
    try:
        directory.import_bundle(blob, db=lab.db)
        refused = False
    except directory.DirectoryError as exc:
        refused = True
        r.steps.append(f"Import attempt refused: “{exc}”")
    after = lab.db.get_active_public_key(lab.bob.email)["fingerprint"]
    r.steps.insert(0, "Mallory exports her public bundle, edits the email field to bob@lab.test and imports it.")
    r.blocked = refused and before == after
    r.outcome = "Bob's directory key is unchanged." if r.blocked else "Bob's key was replaced!"
    return r


def pinned_key_change(lab: _Lab) -> ScenarioResult:
    r = ScenarioResult("pin", "Attacker offers a new key for a pinned contact",
                       "Swap the key of a contact you already imported (trust-on-first-use).",
                       "Key changes need explicit confirmation showing both fingerprints.")
    carol = lab.identity("carol@lab.test", publish=False)
    other = lab.identity("carol-evil@lab.test", publish=False)

    def bundle(keys: IdentityKeys, email: str) -> str:
        data = json.loads(base64.b64decode(keys.export_public_bundle_b64()))
        data["email"] = email
        return base64.b64encode(json.dumps(data).encode()).decode()

    directory.import_bundle(bundle(carol, "carol@remote.test"), db=lab.db)
    r.steps.append("Carol's real key is imported and pinned.")
    try:
        directory.import_bundle(bundle(other, "carol@remote.test"), db=lab.db)
        r.blocked = False
        r.outcome = "A different key was accepted silently!"
    except directory.KeyChangeNeedsConfirmation as exc:
        r.steps.append(f"A different key for the same address is offered → refused: “{exc}”")
        r.blocked = True
        r.outcome = "Not accepted without an explicit, informed confirmation."
    return r


def downgrade(lab: _Lab) -> ScenarioResult:
    r = ScenarioResult("downgrade", "Attacker downgrades the cipher suite",
                       "Strip the X25519 half so only one algorithm protects the key.",
                       "Strict per-version envelope validation; the suite is signed and AAD-bound.")
    env = lab.send(lab.alice, lab.bob)
    attempts = {
        "claim version 1.0 but keep the v2 fields": dict(env, version="1.0"),
        "delete the X25519 ephemeral key": {k: v for k, v in env.items() if k != "x25519_ephemeral"},
        "rename the KEM to a weaker one": dict(env, algorithm=dict(env["algorithm"], kem="Kyber768")),
        "smuggle in an unsigned extra field": dict(env, note="unsigned"),
    }
    blocked_all = True
    for label, forged in attempts.items():
        try:
            message_format.validate_envelope(forged)
            r.steps.append(f"{label}: ACCEPTED")
            blocked_all = False
        except message_format.EnvelopeFormatError as exc:
            r.steps.append(f"{label}: rejected ({exc})")
    r.blocked = blocked_all
    r.outcome = "Every downgrade attempt is rejected before any crypto runs." if blocked_all \
        else "A downgrade was accepted!"
    return r


def truncated_kem(lab: _Lab) -> ScenarioResult:
    r = ScenarioResult("malformed", "Malformed key-establishment data",
                       "Crash or confuse the receiver with a truncated KEM ciphertext.",
                       "Exact length checks before decapsulation; errors become messages, not crashes.")
    env = lab.send(lab.alice, lab.bob)
    broken = dict(env, kem_ciphertext=base64.b64encode(base64.b64decode(env["kem_ciphertext"])[:-5]).decode())
    try:
        message_format.validate_envelope(broken)
        r.blocked = False
        r.outcome = "Accepted!"
    except message_format.EnvelopeFormatError as exc:
        r.steps += ["The last 5 bytes of the ML-KEM ciphertext are cut off.", f"Validation: {exc}"]
        r.blocked = True
        r.outcome = "Rejected cleanly before decapsulation."
    return r


def directory_tamper(lab: _Lab) -> ScenarioResult:
    r = ScenarioResult("dirtamper", "Someone edits the key directory database directly",
                       "Swap Bob's key without going through the app (so no log entry exists).",
                       "Key transparency log: a hash chain plus a digest of every published key set.")
    assert lab.db.verify_key_log()["ok"]
    with lab.db._connect() as conn:
        conn.execute("UPDATE public_keys SET kem_public_b64 = ? WHERE email = ?",
                     (base64.b64encode(lab.mallory.kem_public_bytes).decode(), lab.bob.email))
    report = lab.db.verify_key_log()
    r.steps += ["The kem_public_b64 column of Bob's directory row is overwritten with Mallory's key.",
                f"Log verification: ok = {report['ok']}; mismatches: {report['directory_mismatches']}"]
    r.blocked = not report["ok"] and bool(report["directory_mismatches"])
    r.outcome = "Detected: the live directory no longer matches what the log recorded." if r.blocked \
        else "The swap went unnoticed!"
    return r


def log_tamper(lab: _Lab) -> ScenarioResult:
    r = ScenarioResult("logtamper", "Someone rewrites the transparency log",
                       "Hide a key change by editing history.",
                       "Each entry hashes the previous one; any edit, deletion or reorder breaks the chain.")
    with lab.db._connect() as conn:
        conn.execute("UPDATE key_log SET fingerprint = 'AAAA AAAA AAAA' WHERE seq = 1")
    report = lab.db.verify_key_log()
    r.steps += ["Entry #1 of the log is edited.", f"Chain errors: {report['chain_errors'][:2]}"]
    r.blocked = bool(report["chain_errors"])
    r.outcome = "Detected: the hash chain no longer verifies." if r.blocked else "The edit went unnoticed!"
    return r


def brute_force(lab: _Lab) -> ScenarioResult:
    r = ScenarioResult("bruteforce", "Passphrase guessing",
                       "Try many passphrases against a login.",
                       "Per-account lockout (checked before the expensive Argon2id) + Argon2id key derivation.")
    throttle = LoginThrottle(cfg.LOGIN_MAX_FAILURES, cfg.LOGIN_WINDOW_SECONDS, cfg.LOGIN_LOCKOUT_SECONDS)
    for _ in range(cfg.LOGIN_MAX_FAILURES):
        throttle.record_failure("acct:alice@lab.test")
    wait = throttle.retry_after("acct:alice@lab.test")
    r.steps += [f"{cfg.LOGIN_MAX_FAILURES} wrong passphrases in a row.",
                f"Next attempt is refused for {wait} seconds without running Argon2id."]
    r.blocked = wait > 0
    r.outcome = "Locked out: guessing is throttled to a handful of tries per window." if r.blocked \
        else "No lockout!"
    return r


def totp_replay(lab: _Lab) -> ScenarioResult:
    from app.services import totp

    r = ScenarioResult("totp", "Attacker replays a stolen one-time code",
                       "Reuse a 6-digit code that was just typed (shoulder-surfing / phishing).",
                       "Each TOTP time-step is accepted only once per account.")
    secret = totp.generate_secret()
    keys = lab.alice
    keys.totp_secret, keys.recovery_hashes = secret, []
    now = 1_700_000_000
    code = totp.totp_at(secret, totp.time_step(now))
    first = totp.check_code(lab.db, keys, code, now=now)
    second = totp.check_code(lab.db, keys, code, now=now + 5)
    r.steps += [f"Alice signs in with code {code} → {first!r}.",
                f"The attacker submits the same code seconds later → {second!r}."]
    r.blocked = first == "totp" and second is None
    r.outcome = "The second use is refused." if r.blocked else "The code was accepted twice!"
    keys.totp_secret = None
    return r


def hostile_filename(lab: _Lab) -> ScenarioResult:
    r = ScenarioResult("filename", "Hostile attachment name",
                       "Use an attachment name to escape the download folder or inject markup.",
                       "File names are reduced to a safe base name; downloads are opaque octet-streams.")
    name = message_format.safe_filename('../../Windows/System32/<script>alert(1)</script>.html')
    r.steps += ["Attachment named “../../Windows/System32/<script>alert(1)</script>.html”.",
                f"Stored and shown as: “{name}”. Served as application/octet-stream with a sandboxed CSP."]
    r.blocked = "/" not in name and "<" not in name and ">" not in name and ".." not in name.split(".")[0]
    r.outcome = "Path and markup characters are stripped." if r.blocked else "Unsafe name kept!"
    return r


SCENARIOS: list[Callable[[_Lab], ScenarioResult]] = [
    eavesdropper, bit_flip, readdress, forged_sender, replay, key_substitution, pinned_key_change,
    downgrade, truncated_kem, directory_tamper, log_tamper, brute_force, totp_replay, hostile_filename,
]


def run_all() -> list[ScenarioResult]:
    """Run every scenario in its own fresh sandbox (they must not influence each other)."""
    results = []
    for scenario in SCENARIOS:
        with tempfile.TemporaryDirectory(prefix="pqmail-lab-") as tmp:
            lab = _Lab(Path(tmp))
            try:
                results.append(scenario(lab))
            except Exception as exc:  # noqa: BLE001 - a broken scenario must be visible, not silent
                results.append(ScenarioResult(scenario.__name__, scenario.__name__.replace("_", " "),
                                              "", "", [f"Scenario crashed: {type(exc).__name__}: {exc}"],
                                              "The scenario itself failed to run.", False))
    return results
