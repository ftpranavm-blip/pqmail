# PQMail — Quantum-Secure Email Client

[![tests](https://github.com/ftpranavm-blip/pqmail/actions/workflows/tests.yml/badge.svg)](https://github.com/ftpranavm-blip/pqmail/actions/workflows/tests.yml)


**Problem Statement / PS ID: 25179 — Quantum Secure Email Client Application**

PQMail is a working educational email client that protects messages with
**Post-Quantum Cryptography (PQC)**: end-to-end encrypted email, post-quantum
key establishment (**ML-KEM-768**, NIST FIPS 203), post-quantum digital
signatures (**ML-DSA-65**, NIST FIPS 204), encrypted private-key storage,
tamper detection, a public-key directory, and an **educational BB84 QKD
simulation** — all behind a clean Gmail-style web UI.

> 📖 New in this version: hybrid X25519 + ML-KEM-768, encrypted attachments, reply/forward/trash, replay protection,
> a key transparency log, TOTP two-factor sign-in, live benchmarks, an attack lab, a much richer QKD simulator, light/dark
> theme and a Hindi UI. See **[FEATURES.md](FEATURES.md)**; earlier security fixes are in
> **[FLAWS_AND_FIXES.md](FLAWS_AND_FIXES.md)**.

> ⚠️ **Honesty note (important).** This is an *educational prototype*.
> The cryptography is real and uses vetted implementations, but the whole
> system has not been audited and is not intended for production secrets.
> The QKD tab is a **classical software simulation** labelled
> "Educational QKD Simulation": it demonstrates *why* eavesdropping is
> detectable in quantum key distribution, but it provides none of the
> security of real QKD (which requires quantum communication hardware).

---

## 1. Features

| Feature | Status | How |
|---|---|---|
| End-to-end encrypted email | ✅ | AES-256-GCM inside an envelope the server can't read |
| Post-quantum key establishment | ✅ | ML-KEM-768 encapsulation (FIPS 203) |
| Hybrid key exchange | ✅ | X25519 + ML-KEM-768: safe unless **both** are broken |
| Encrypted attachments | ✅ | up to 5 files / 4 MiB, inside the encrypted payload |
| Reply, forward, trash, replay protection | ✅ | soft delete + permanent per-mailbox message ledger |
| Key transparency log | ✅ | hash-chained log of every directory change, re-verified on each view |
| Two-factor sign-in | ✅ | TOTP (RFC 6238) + recovery codes, secret inside the encrypted keystore |
| Benchmarks & attack lab | ✅ | live PQC-vs-classical timings; 14 sandboxed attacks, all blocked |
| Languages & themes | ✅ | English / हिन्दी, light/dark, mobile layout |
| Post-quantum digital signatures | ✅ | ML-DSA-65 sign/verify (FIPS 204) |
| Hybrid encryption done correctly | ✅ | ML-KEM → HKDF-SHA-256 → AES-256-GCM |
| Secure private-key storage | ✅ | Argon2id + AES-256-GCM keystore files |
| Email sending/receiving | ✅ | Local demo mailbox (offline) + optional SMTP/IMAP |
| Key management | ✅ | Generate, rotate (archive), export, import, publish |
| Tamper detection demo | ✅ | One-click "Simulate tampering" — fail closed |
| Public-key directory | ✅ | SQLite-backed key directory for demo users |
| BB84 QKD simulation | ✅ | Eve (full/partial), channel noise, QBER, Cascade error correction, privacy amplification |
| Security dashboard & Learn page | ✅ | Plain-language explanations of every mechanism |
| Automated tests | ✅ | 242 tests: all 10 PS scenarios + regression tests for every fixed flaw and new feature |
| Web-app hardening | ✅ | CSRF tokens, login throttling, safe key import, no-store caching, strict CSP |

## 2. Technologies

- **Python 3.11+** (developed and tested on 3.12/3.13, Windows & Linux)
- **Flask** — web UI and routes
- **waitress** — production-grade WSGI server (single process; unlocked keys live in memory)
- **pyca/cryptography ≥ 48** — provides **real ML-KEM-768 and ML-DSA-65**
  implementations (Rust bindings vetted by Trail of Bits). This replaced the
  liboqs suggestion in the PS because liboqs needs a native C build on Windows
  and has no official wheels; pyca/cryptography is the most widely vetted
  Python crypto library and ships prebuilt Windows wheels.
- **argon2-cffi** — Argon2id (RFC 9106) passphrase KDF for keystore files
- **segno** (optional) — pure-Python QR code for two-factor enrolment
- **keyring** (optional) — OS keychain integration (Windows Credential Locker)
- **SQLite** (Python stdlib) — users, keys, envelopes, contacts
- **smtplib / imaplib** (Python stdlib) — optional Real Email Mode

## 3. Cryptographic architecture

```
SENDER                                              RECIPIENT
──────                                              ─────────
1. Fetch recipient's public keys (ML-KEM-768 +
   X25519) from the key directory
2. ss_pq, ct = ML-KEM-768.Encaps(pub_kem)  ──ct──▶  ss_pq = ML-KEM-768.Decaps(priv_kem, ct)
   ss_x = X25519(eph_priv, pub_x)          ─eph──▶  ss_x  = X25519(priv_x, eph_pub)
   shared = HKDF(ss_pq || ss_x ‖ ct ‖ eph ‖ pub_x)  shared = HKDF(ss_pq || ss_x ‖ ct ‖ eph ‖ pub_x)
3. aes_key = HKDF-SHA-256(shared, salt)             aes_key = HKDF-SHA-256(shared, salt)
4. ciphertext = AES-256-GCM(aes_key,                plaintext = AES-256-GCM-open(...)
   nonce, subject+body+attachments, AAD=metadata)
5. signature = ML-DSA-65.Sign(priv,                 verified = ML-DSA-65.Verify(sender_pub,
   canonical envelope bytes)                          signature, canonical envelope bytes)
6. Send only the envelope ──────────────────────────▶ open ONLY if signature AND tag verify
```

Why a *hybrid* exchange? ML-KEM is new; X25519 is old but breakable by a future quantum
computer. Mixing both secrets into the key means an attacker must break **both**.
(Contacts whose directory entry has no X25519 key still get the older ML-KEM-only
envelope v1.0, and the UI tells you.)

A KEM cannot encrypt data — it establishes a shared secret.
AES-256-GCM is fast, authenticated (confidentiality **and** integrity), and
gets a fresh random 96-bit nonce per message. The HKDF salt is random per
message, so every message uses a unique session key.

**Signature & AAD binding.** The ML-DSA signature covers the canonical JSON of
every envelope field except the signature itself. The AES-GCM associated data
(AAD) binds the ciphertext to the same metadata. So changing *anything* —
sender, recipient, KEM ciphertext, nonce, body — breaks both the signature and
decryption. Messages are opened **fail-closed**: content is shown only when the
signature verifies **and** the AES-GCM tag authenticates.

**Envelope format** (JSON; binary fields are Base64; never contains plaintext; version 1.0 = ML-KEM-only is still readable and
used for contacts that have no X25519 key):

```json
{
  "version": "2.0",
  "algorithm": {"kem": "X25519+ML-KEM-768", "signature": "ML-DSA-65",
                "symmetric": "AES-256-GCM", "kdf": "HKDF-SHA-256"},
  "sender": "alice@pqmail.local",
  "recipient": "bob@pqmail.local",
  "timestamp": "2026-09-09T12:00:00+00:00",
  "message_id": "pqmail-<32 hex>",
  "kem_ciphertext": "…", "x25519_ephemeral": "…", "salt": "…", "nonce": "…",
  "ciphertext": "…",
  "sender_key_fingerprint": "BA78 16BF 8F01 CFEA 4141 40DE 5DAE 2223 B003 61A3",
  "signature": "…"
}
```

### A note on algorithm names

ML-KEM was standardised from **CRYSTALS-Kyber**, and ML-DSA from
**CRYSTALS-Dilithium**. Some libraries still expose the older names
`Kyber768` / `Dilithium3`; those are *predecessor implementation names* for the
same lattice problems, not different algorithms. This project uses the
current standardized names (ML-KEM-768 / ML-DSA-65) and the NIST standards
(FIPS 203 / FIPS 204).

## 4. Project structure

```
quantum_secure_email/
├── app.py                     # entry point: python app.py
├── requirements.txt
├── .env.example               # template for Real Email Mode (never commit .env)
├── .gitignore
├── app/
│   ├── __init__.py            # Flask factory, security headers, error handlers
│   ├── config.py              # ALL crypto parameters, .env loading, validation
│   ├── routes.py              # HTTP routes (blueprint)
│   ├── security.py            # CSRF protection + login throttling
│   ├── i18n.py + translations/ # English / Hindi UI
│   ├── routes_extra.py        # trash, transparency, 2FA, benchmarks, attack lab
│   ├── bootstrap.py           # demo users, identity registration
│   ├── db.py                  # SQLite layer (ciphertext-only persistence)
│   ├── log.py                 # safe logging (no keys/plaintext ever)
│   ├── session_keys.py        # RAM-only unlocked-key cache with TTL
│   ├── crypto/
│   │   ├── pqc.py             # ML-KEM-768 + ML-DSA-65 + X25519 wrappers
│   │   ├── hybrid.py          # X25519 + ML-KEM-768 combiner
│   │   ├── encryption.py      # HKDF + AES-256-GCM (TamperError)
│   │   ├── signatures.py      # ML-DSA sign/verify re-exports
│   │   ├── key_manager.py     # identities, keystores, rotation
│   │   └── fingerprints.py    # SHA-256 fingerprints (PGP-style)
│   ├── email/
│   │   ├── message_format.py  # envelope build/canonicalise/validate
│   │   ├── smtp_client.py     # optional SMTP_SSL/STARTTLS sender
│   │   └── imap_client.py     # optional IMAPS fetcher
│   ├── qkd/bb84.py            # BB84 educational simulation
│   ├── storage/secure_storage.py  # Argon2id + AES-256-GCM keystore
│   └── services/
│       ├── mail_service.py    # send/open/import orchestration, fail-closed
│       ├── directory.py       # safe public-key bundle import (TOFU, no hijacking)
│       ├── totp.py            # RFC 6238 two-factor + recovery codes
│       ├── benchmarks.py      # live PQC-vs-classical benchmarks
│       └── attack_lab.py      # sandboxed attack scenarios
├── templates/                 # base, index, login, register, dashboard,
│   └── …                      # inbox, compose, sent, message, contacts,
│                              # keys, security, qkd, learn, settings, error
├── static/css/style.css       # offline-friendly custom stylesheet (no CDN)
├── static/js/app.js
├── tests/                     # 242 automated tests (10 PS scenarios + regressions + features)
└── data/                      # created at runtime; NEVER commit
    ├── pqmail.db              # ciphertext-only mailbox database
    ├── keys/                  # encrypted keystores (outside static/)
    │   └── archive/           # rotated keystores
    ├── demo_mailbox/
    └── logs/
```

## 5. Installation

**Requirements:** Python 3.11+ (no compiler needed — all wheels are prebuilt).

Windows PowerShell:

```powershell
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

`python app.py` serves the app with **waitress** (fast, HTTP/1.1 keep-alive, both `http://127.0.0.1:5000` and
`http://localhost:5000` / `[::1]`). If waitress is not installed it falls back to Flask's slower dev server and says so.

(For the tests: `pip install -r requirements-dev.txt`.)

Linux / macOS:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open **http://127.0.0.1:5000** — demo users are created automatically on
first start.

## 6. Demo credentials (Demo Mode)

> Demo accounts have a **publicly known passphrase**. They are only for a local demo: the app
> refuses to start on a non-loopback address while they are enabled. Set `PQMAIL_DEMO_MODE=0`
> to disable them (and the tamper demo) for anything else.

| User | Email | Keystore passphrase |
|---|---|---|
| Alice | `alice@pqmail.local` | `demo1234` |
| Bob   | `bob@pqmail.local`   | `demo1234` |

Demo Mode needs **no internet, no mail server, no credentials**. The
passphrase comes from `PQMAIL_DEMO_PASSPHRASE` (change it for your demo if
you like — 8+ characters).

### The 2-minute hackathon demo

1. Start the app (`python app.py`), log in as **Alice** / `demo1234`.
2. Show **Security / Keys**: ML-KEM-768 + ML-DSA-65 fingerprints, created date.
3. **Compose** → To: `bob@pqmail.local`, subject/body of your choice →
   **Encrypt & Send**. (Encryption happens locally before anything is stored.)
4. Click **Sign out** (a POST button), log in as **Bob**. Open the **Inbox** → open the message.
5. Point out the security panel: ✓ ML-KEM-768 ✓ AES-256-GCM ✓ ML-DSA-65
   Signature Verified ✓ Sender fingerprint.
6. Click **Simulate tampering** → reopen: 🔴 *Message integrity check failed*,
   content withheld.
7. **QKD Simulator**: run once *without* Eve (keys match, error rate 0%),
   then *with* Eve (≈25% errors → "Eavesdropper detected", aborted).
8. Optional: **Learn** page for the plain-language explanations.

## 7. Real Email Mode (optional)

Copy `.env.example` to `.env` (it is loaded automatically at start-up; real environment
variables take precedence) and fill in SMTP/IMAP settings
(use a mail provider **app password**, never your login password):

```
SMTP_HOST=smtp.gmail.com
SMTP_PORT=465
SMTP_USERNAME=you@gmail.com
SMTP_PASSWORD=your_16_char_app_password
IMAP_HOST=imap.gmail.com
IMAP_PORT=993
IMAP_USERNAME=you@gmail.com
IMAP_PASSWORD=your_16_char_app_password
```

Then switch **Settings → Real Email Mode**. SMTP uses implicit TLS (465) or
STARTTLS; IMAP uses IMAPS (993). **Server certificates are verified.** The visible
`Subject` header is a constant (`[PQMail] Encrypted message`); the real subject is only
inside the encrypted payload. Use **Inbox → Fetch from IMAP** to pull envelopes addressed
to you into your inbox; the sender's public key must be in the directory first
(Contacts → import their `.pqpub` bundle). **Transport encryption is separate from the
end-to-end envelope**: the mail server only ever sees the encrypted envelope,
so it cannot read or forge messages.

### Going real, step by step

Demo Mode and Real Email Mode are two different switches, so for real use you want **both** of these:

| Setting | What it does |
|---|---|
| **Settings → Switch to Real Email Mode** (per session) | Mail is sent through your SMTP account and received through IMAP instead of the local demo mailbox. The *Simulate Tampering* demo button disappears and is refused. |
| `PQMAIL_DEMO_MODE=0` (in `.env`) | Turns off the public Alice/Bob demo accounts (also any that already exist from an earlier demo run), the demo login box and the tamper demo everywhere. Required before listening on a non-local address. |

1. **Create `.env`** next to `app.py` (copy `.env.example`) and fill in your mail provider's SMTP/IMAP settings using an
   **app password**, never your normal login password. Nobody else should ever see this file (it is git-ignored).
   For a clean start also set `PQMAIL_DEMO_MODE=0` and a fresh data folder, e.g. `PQMAIL_DATA_DIR=real-data`.
2. **Restart the app** (`.env` is read at start-up).
3. **Create your identity** with your *real* email address (Create an identity). Pick a strong passphrase: it protects your keys.
4. **Exchange public keys** with each person you will write to: *Keys → Export public keys* gives a `.pqpub` file; they paste yours
   under *Contacts → Import*, and you import theirs. Compare the fingerprints over another channel (phone, in person).
5. **Settings → Switch to Real Email Mode** (it refuses and stays in Demo Mode while SMTP is not configured; the Settings page shows
   whether SMTP and IMAP are configured).
6. **Compose** as usual. Your mail provider only sees an encrypted `.pqmail.json` attachment under a fixed subject. The *recipient must
   also run PQMail* (with their own identity and your public key imported) - an ordinary mail client cannot read it.
7. **Receive:** *Inbox → Fetch from IMAP*. Only mail addressed to you, from senders whose key you imported, is accepted; every
   message is still signature- and integrity-checked when opened, so a message that was altered in transit is withheld with a red warning.

Real mode costs nothing extra beyond your normal mail account; PQMail never talks to any other service.

## 8. Security model & threat model

| Threat | Protection |
|---|---|
| Eavesdropping on messages | End-to-end AES-256-GCM; server stores only ciphertext |
| Server / mailbox compromise | DB contains no plaintext subjects or bodies (only a constant hint label) |
| Harvest-now-decrypt-later | ML-KEM-768 key establishment resists known quantum attacks (FIPS 203) |
| Message tampering | AES-GCM authentication tag + ML-DSA-65 signature; fail-closed display |
| Sender impersonation | ML-DSA-65 signatures verified against directory public keys |
| Metadata swapping (re-addressing) | Signature + AAD bind sender/recipient/ciphertext together |
| Replay / future timestamps | Per-mailbox ledger of every message id ever received (survives deletion), 45-day age limit on IMAP import, >1-day-future timestamps rejected |
| Weakness in one algorithm | Hybrid X25519 + ML-KEM-768: the key is safe unless **both** are broken |
| Silent key swap in the directory | Hash-chained transparency log + per-key digests, re-verified on every view; dashboard warns if your published key differs from your keystore |
| Stolen / phished passphrase (web sign-in) | TOTP second factor with replay protection and one-time recovery codes |
| Malicious attachments | Encrypted with the message; sanitised names; served as opaque downloads under a sandboxing CSP |
| Private key theft | Keystores encrypted with Argon2id + AES-256-GCM; unlocked keys live in RAM only (15-min TTL); never in static/, cookies, logs or UI |
| Weak passphrases | 8-character minimum, no composition rules (NIST SP 800-63B style) |
| XSS / clickjacking | Jinja auto-escaping, strict CSP, X-Frame-Options DENY, nosniff |
| Cross-site request forgery | Per-session CSRF token on every POST; sign-out is POST-only; SameSite=Lax cookie |
| Passphrase guessing / Argon2 DoS | Per-account and per-address lockout after repeated failures |
| Public-key substitution | Imports can never replace a local identity; changing a pinned contact key needs explicit confirmation showing both fingerprints |
| Sender tampering with the recipient's copy | Mailbox rows are scoped by folder: only the recipient reaches the inbox copy |
| Cached plaintext in the browser | `Cache-Control: no-store` on every non-static response |
| MITM on SMTP/IMAP | Certificate and hostname verification (`ssl.create_default_context()`) |

### Remaining limitations (documented honestly)

- **Not audited.** A prototype: the design is standard, the implementation is not professionally reviewed.
- **QKD is simulated** on classical hardware; it is not used by the email flow.
- **Rotation is not forward secrecy**: rotating keys keeps the *retired private keys* inside the
  new (re-encrypted) keystore so old mail stays readable. Anyone who gets the new keystore and
  passphrase can therefore also read old mail. Per-message ratcheting is listed under future work.
- **Trust in the key directory**: demo keys are published/looked up locally
  without a Web-of-Trust or CA; fingerprint comparison out-of-band is advised
  (the UI shows fingerprints for this purpose).
- **Spam/abuse and HTML mail** are out of scope; attachments are limited to 4 MiB in one AES-GCM payload (no streaming).
- **Two-factor does not stop offline guessing** of a stolen keystore file (its secret lives in the keystore); Argon2id does.
- SQLite is fine for a demo; a multi-user deployment needs a real DB and HTTPS.

## 9. Testing

```bash
pytest -v          # 242 tests, ~30 seconds
python scripts/verify_routes.py   # end-to-end UI route checks (self-sandboxed)
```

Coverage of the 10 required test scenarios:

| # | Requirement | Test |
|---|---|---|
| 1 | ML-KEM keypair generation | `test_pqc.py::test_kem_keypair_generation` |
| 2 | Encaps/Decaps shared secrets match | `test_pqc.py::test_encapsulation_decapsulation_shared_secret_matches` |
| 3 | Encrypt/decrypt roundtrip | `test_encryption.py::test_encrypt_decrypt_roundtrip` |
| 4 | Tampered ciphertext fails | `test_encryption.py::test_tampered_ciphertext_fails` + `test_mail_service.py::test_tampered_ciphertext_withheld` |
| 5 | Signature verifies | `test_signatures.py::test_sign_and_verify_succeeds` |
| 6 | Modified data fails signature | `test_signatures.py::test_modified_data_fails_verification` |
| 7 | QKD without Eve → matching keys | `test_qkd.py::test_bb84_without_eve_keys_match` |
| 8 | QKD with Eve → detected | `test_qkd.py::test_bb84_with_eve_is_detected` |
| 9 | Correct passphrase restores keys | `test_key_storage.py::test_keystore_creation_and_unlock` |
| 10 | Wrong passphrase fails | `test_key_storage.py::test_wrong_passphrase_cannot_recover_keys` |

Plus: envelope format/validation (8 mutation cases), AAD binding, nonce
freshness, plaintext-never-on-disk, spoofed recipient rejection, key rotation
archiving, identity-overwrite protection, QKD parameter validation, and
`tests/test_security_fixes.py` — one regression test group for every flaw listed in
[FLAWS_AND_FIXES.md](FLAWS_AND_FIXES.md) and [FEATURES.md](FEATURES.md).

## 10. Safe-logging & secrets policy

- Only non-secret fields are logged (`message_id`, `recipient`, algorithm names) —
  never plaintext, keys, passphrases or session keys.
- Private keys exist in exactly three places: generated in RAM, sealed inside
  the Argon2id+AES-GCM keystore file, and the RAM session cache (TTL 15 min).
- `.env` and `data/` are git-ignored; no credentials are hardcoded anywhere.

## 11. QKD ↔ PQC relationship (read this before demoing)

- **PQC** (ML-KEM / ML-DSA) is *software* cryptography designed to resist
  known quantum attacks. It runs on any device — **this is the project's real
  security mechanism.**
- **QKD** (BB84) distributes keys using quantum physics and — in the real
  world — specialised quantum hardware. It is **not required for PQC**, and
  the two solve different problems. The app's QKD tab is an **educational
  simulation only** and is never used by the email flow. Its demo value:
  without Eve the sifted keys match perfectly; with Eve, the no-cloning
  theorem (simulated) forces a ~25% error rate that Alice and Bob detect.

## 12. Configuration reference

| Variable | Default | Meaning |
|---|---|---|
| `PQMAIL_DATA_DIR` | `data` (project-relative) | DB, keystores, logs, session secret |
| `PQMAIL_SECRET_KEY` | generated once, stored in `data/secret_key` | Flask session signing key |
| `PQMAIL_DEMO_MODE` | `1` | `0` disables demo accounts + tamper demo |
| `PQMAIL_DEMO_PASSPHRASE` | `demo1234` | Passphrase of the demo accounts |
| `PQMAIL_COOKIE_SECURE` | `0` | `1` marks the session cookie Secure (use behind HTTPS) |
| `FLASK_HOST` / `FLASK_PORT` | `127.0.0.1` / `5000` | Bind address (non-loopback is refused while demo mode is on) |
| `SMTP_*`, `IMAP_*` | unset | Real Email Mode (see section 7) |

## 13. Future improvements

1. Multiple recipients per message (per-recipient KEM ciphertexts), CC/BCC
2. Chunked/streaming attachment encryption for large files
3. Signal-style double ratchet for forward secrecy per message
4. Witness/gossip service so independent directories can cross-check transparency logs
6. Real QKD hardware integration via a QKD network API (out of scope here)
7. docker-compose packaging; HTTPS via a reverse proxy
8. Internationalisation and accessibility pass on the UI

## License

No open-source license has been granted. The source is published so it can be read and reviewed; all rights are reserved
by the author. If you would like to reuse it, please ask first.
