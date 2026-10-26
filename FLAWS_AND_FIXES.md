# PQMail — review findings and fixes

Every flaw below was either **reproduced** against the original code in a throw-away
sandbox, or read directly from the code. Each has a regression test in
`tests/test_security_fixes.py` (test names start with the flaw number, e.g. `test_f1_…`).

Baseline before the changes: 65 tests passing (none of them covered these flaws).
After: **132 tests passing** + `scripts/verify_routes.py` clean.

## Critical — security or data loss

| # | Flaw | Evidence | Fix |
|---|---|---|---|
| F1 | **Key hijacking.** `/keys/import` let any signed-in user publish a key under *any* address (e.g. `bob@…`). The directory then served the attacker's key, so mail to Bob was encrypted to the attacker and the attacker could sign as Bob. | Reproduced | New `services/directory.py`: imports can never create/replace a local identity; a different key for an imported contact needs an explicit confirmation showing both fingerprints; size + algorithm + encoding validation. `users.source` column (`local`/`imported`) with an automatic DB migration. |
| F2 | **Bricked account on key rotation.** `rotate_keys` moved the keystore into the archive *before* validating the new passphrase; a short one raised after the move and left no active keystore. | Reproduced | Validate first, stage the new keystore, copy (not move) to archive, atomic `os.replace` last. Any failure changes nothing. |
| F3 | **Path traversal on registration/login.** The email became part of a file path; `..\..\x@y.test` wrote a keystore outside `data/keys`. | Reproduced (file landed in the temp dir) | Strict address syntax (`config.is_valid_email`), enforced in registration, login, import, envelopes, `KeyStore.filename_for` and a resolved-path check. |
| F4 | **No CSRF protection.** Every POST (send mail, rotate keys, import keys, mode switch…) was forgeable from any web page; `/logout` was a GET. | Reproduced | `app/security.py`: per-session token on every state-changing request (constant-time compare), `csrf_field()` in all 17 forms, sign-out is POST-only. |
| F5 | **Keyring enrollment locked you out.** It re-sealed the keystore under the vault key *only*, so the passphrase stopped working, and nothing ever unlocked via the keyring. | From code | Keystore keeps the passphrase-wrapped copy and adds a second vault-wrapped copy. New "Unlock with OS keyring" login, "Remove enrollment" button. |
| F6 | **Real Email Mode leaked the plaintext subject** in the SMTP `Subject:` header, contradicting the "server only sees ciphertext" claim. | From code | Constant subject `[PQMail] Encrypted message`. |
| F7 | **TLS certificates were not verified** (`SMTP_SSL`, `IMAP4_SSL`, `starttls()` without a context), so a man-in-the-middle could capture the mail app password. | From code | `ssl.create_default_context()` (certificate + hostname verification) everywhere. |
| F24 | **Sender could touch the recipient's mailbox copy.** Envelope queries allowed "sender OR recipient" on any row, so Alice could mark-read or flip a bit in Bob's inbox copy via the tamper route. | Found while updating a test | All mailbox queries scope rows by folder (inbox ⇒ recipient, sent ⇒ sender). |

## High — broken behaviour

| # | Flaw | Fix |
|---|---|---|
| F8 | **You could not read your own Sent mail** (it was encrypted only to the recipient → "integrity failed"). *Reproduced.* | The sent copy is a separate envelope encrypted to the sender's own ML-KEM key. |
| F9 | **Rotation broke old signatures** (only the newest key was used to verify; same-second ties picked the wrong key). | Signature key is looked up by the envelope's fingerprint among the sender's keys; deterministic ordering (`created_at, rowid`); UI notes "signed with an earlier key". |
| F10 | **Old mail lost on rotation** (old private keys were archived but never used). | Retired private keys travel inside the new, re-encrypted keystore and are tried when decrypting (max 20). |
| F11 | **`.env` was never loaded**, though README/UI said to use it. | Small built-in loader (real env vars win); relative `PQMAIL_DATA_DIR` anchored to the project. |
| F12 | **IMAP was never wired up** (Real Email Mode could send, not receive). | `Inbox → Fetch from IMAP`: validates, de-duplicates, only imports mail addressed to you from known senders; signatures are still verified on open. |
| F13 | **A timestamp without timezone caused HTTP 500** (`TypeError`); corrupt envelope JSON was also unhandled. *Reproduced.* | Validation hardened (timezone required, id/address/salt-length checks); errors become user messages. |
| F14 | **Keystore weaknesses:** Argon2 parameters in the file were ignored (changing defaults would lock users out), metadata unauthenticated, non-atomic writes (crash ⇒ corrupt keystore), DSA public key never cross-checked. | Format 2: parameters read from the file (bounds-checked), metadata bound as AES-GCM AAD, atomic writes, signing-key self-check. Format-1 keystores unlock and are upgraded automatically (verified on a copy of your original data). |
| F15 | **Session handling:** random secret key per start (sessions died on restart), key-expiry only enforced on some pages, open redirect via `Referer`, Real mode selectable without configuration. | Persistent secret key (`data/secret_key` or `PQMAIL_SECRET_KEY`), expiry ends the session everywhere, same-host-only redirect, 8 h session lifetime, secure-cookie option. |
| F16 | **Demo accounts were always on** with a public passphrase (hard-coded in templates); binding to `0.0.0.0` exposed them to the network. | `PQMAIL_DEMO_MODE=0` disables them and the tamper demo; the app refuses to start on a non-loopback address while demo mode is on; passphrase comes from config. |
| F17 | **No login throttling** (each attempt costs 64 MiB of Argon2 — brute-force and DoS). | Per-account and per-address lockout, checked *before* running Argon2. |

## Medium / low

| # | Flaw | Fix |
|---|---|---|
| F18 | Dashboard showed **system-wide** counts to every user; lists showed no subjects (a constant label). | Per-user stats incl. unread; subjects decrypted + verified in RAM for lists (never stored, not marked read). |
| F19 | Registration said "storage error" for a short passphrase; display name unsanitised; orphan keystore if the DB write failed. | Clear messages, cleaned names, rollback. |
| F20 | Decrypted pages could stay in the browser cache / back-forward cache. | `Cache-Control: no-store` on everything except static files; CSP gained `form-action`, `base-uri`. |
| F21 | **Docs/metadata wrong:** "Cat 1/3" security label, `demo123` vs `demo1234` docstring, fingerprint format (5 vs 10 groups), README claims about IMAP/.env, `verify_routes.py` posted the wrong form fields so its "with Eve" check never ran Eve. | Corrected; README gained a configuration reference and the new threat-model rows. |
| F22 | **Packaging:** zip shipped a `venv` from another PC, `__pycache__`, logs, runtime data; `.gitignore` incomplete; `pytest` in runtime requirements. | Clean export, fuller `.gitignore`, `requirements-dev.txt`. |
| F23 | BB84 rebuilt a `set()` inside a loop (O(n²)); 64 qubits gave ≈6 % chance to miss Eve. | Hoisted; minimum raised to 128 qubits (≈1 %). |

## Behaviour changes you may notice

* **Sign out is a button (POST)**, not a link.
* **Sent mail created by the old version** (rows whose id ends in `:sent`) cannot be decrypted — it never could; the UI now says so. Your shipped database had none.
* Rotating keys now **keeps** old mail readable — the consequence (stated in the README) is that the new keystore also contains the retired private keys.
* QKD minimum is 128 qubits.
* `data/` (keystores, DB) is no longer part of the export; demo users are regenerated on first start.

## Not changed on purpose (documented limitations)

* It is still a prototype and **not audited**; the Flask dev server is used (single process — the unlocked-key cache is in-process).
* Public-key bundles carry no proof of ownership — compare fingerprints out-of-band (the UI says so).
* No replay cache, attachments, HTML mail, or per-message forward secrecy.


---

## Round 2 — new features (see [FEATURES.md](FEATURES.md))

While adding features, the new tests exposed a few more problems; all are fixed and covered by tests:

| # | Problem | Fix |
|---|---|---|
| R2-1 | First error-correction attempt left residual errors and wrongly aborted honest noisy QKD runs | Real Cascade with back-tracking + verification (0 failures in 3000 random trials) |
| R2-2 | A keyring-enrolled keystore would have lost its keyring copy whenever it was re-sealed | Re-sealing re-wraps the keyring copy (tested) |
| R2-3 | Re-delivering a *deleted* message would have re-imported it once delete existed | Permanent per-mailbox message ledger (replay protection) |
| R2-4 | Failed send discarded the typed message | Form re-rendered with the user's text |
| R2-5 | i18n helper mangled a lone `%` in text without placeholders | Format only when values are given |
| R2-6 | Benchmark mixed DER-wrapped and raw key sizes | Native encodings everywhere |
| R2-7 | Existing data (format-1 keystores, old database) must keep working | Automatic migrations; verified against the original zip's data |
| R2-8 | **Pages felt slow and flashed black, worst after switching language.** Browsers resolve `localhost` to IPv6 `::1` first; Flask's dev server only listened on IPv4, so every connection waited ~200 ms (measured: 208 ms vs 3 ms), and the HTTP/1.0 dev server opened a new connection for each of the page's 4 files, with the blocking stylesheet/script making the page blank for up to ~1 s | New `app/server.py`: **waitress** (HTTP/1.1 keep-alive, threads) listening on `127.0.0.1` **and** `::1`; falls back to the dev server if waitress is missing. Page now loads in ~35 ms (was ~1 s) |
| R2-9 | Static files were re-validated on every page view | Fingerprinted URLs (`?v=<mtime>`) + 7-day cache |
| R2-10 | **Language links gave "405 Method not allowed"** on pages that are the result of a POST (QKD simulation result, Attack-lab result, failed compose, 2FA) | `lang_url()` links to the matching GET page, keeps the query string (`?page=2&filter=unread`), and the one-time recovery-codes page hides the switcher so the codes can't be lost |
| R2-11 | `backdrop-filter: blur` on the sticky nav (known to cause black-screen flicker on some GPUs) and no explicit Devanagari font | Blur removed; font stack now lists Nirmala UI / Noto Sans Devanagari / Mangal |
| R2-12 | Switching to *Real Email Mode* did not hide the **Simulate Tampering** button (only `PQMAIL_DEMO_MODE=0` did), so a real mailbox copy could be deliberately corrupted | The demo is hidden *and* refused in Real Email Mode as well as when demo mode is off; real tampering is still detected and withheld in every mode |
| R2-13 | With `PQMAIL_DEMO_MODE=0`, demo accounts **that already existed** (public passphrase `demo1234`) could still sign in | Demo accounts are refused at sign-in whenever demo mode is off |
