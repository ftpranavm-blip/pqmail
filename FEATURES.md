# PQMail — feature guide (round 2)

This file describes what was added after the security review in
[FLAWS_AND_FIXES.md](FLAWS_AND_FIXES.md): how each feature works, where it lives,
its limits, and how it is tested. Everything uses only free Python packages
(`segno` — a tiny pure-Python QR generator — is the only new dependency, and it is optional).

| # | Feature | Where to try it |
|---|---|---|
| 1 | Hybrid **X25519 + ML-KEM-768** key exchange | Compose → every new message; message page shows `v2.0` |
| 2 | Encrypted **attachments** | Compose → "Attachments"; download on the message page |
| 3 | **Reply / forward / delete / trash** | Message page buttons; **Trash** in the menu |
| 4 | **Replay protection** | Delete a message permanently, re-deliver it: refused |
| 5 | **Key transparency log** | Security → Transparency log |
| 6 | **TOTP two-factor** sign-in + recovery codes | Settings → Two-factor authentication |
| 7 | **Benchmarks** (PQC vs classical, live) | Learn → Benchmarks |
| 8 | **Attack lab** (14 live attacks) | Security → Attack lab |
| 9 | **QKD**: noise, partial Eve, Cascade error correction, privacy amplification | Learn → QKD simulator |
| 10 | **UI**: light/dark theme, mobile menu, pagination, unread badge, shortcuts, accessibility | everywhere |
| 11 | **Hindi translation** (English / हिन्दी) | language links in the top bar |
| 12 | Contact removal, per-contact "Write" link, hybrid badge in the directory | Contacts |

---

## 1. Hybrid X25519 + ML-KEM-768 (envelope v2)

`app/crypto/hybrid.py` runs both key exchanges and feeds *both* secrets into HKDF:

```
shared = HKDF-SHA-256( ss_mlkem || ss_x25519,
                       info = label || len(ct) || ct || x25519_ephemeral_pub || recipient_x25519_pub )
```

An attacker must break **both** ML-KEM (young, lattice-based) **and** X25519 (old, elliptic-curve) to recover
the message key — the construction TLS uses for `X25519MLKEM768`. The ciphertext, the ephemeral key and the
recipient's key are mixed into the derivation so the secret is bound to that exact exchange.

* **Envelope v2.0** adds the signed field `x25519_ephemeral`; the KEM name becomes `X25519+ML-KEM-768`.
  Version 1.0 (ML-KEM only) is still readable, and still *sent* to contacts whose directory entry has no X25519 key
  (the UI says so with a warning). Downgrade attempts (changing the version, deleting the ephemeral key, renaming the
  suite, adding unsigned fields) are rejected by strict per-version validation *before* any crypto runs.
* **Keystore format 3** holds the X25519 private key. Older keystores are upgraded automatically the first time they are
  unlocked with the passphrase (a new X25519 key is generated, the directory entry gets it attached and logged).
* **Rotation** creates a new X25519 key too; retired X25519 keys are kept next to the retired ML-KEM keys so old mail stays
  readable.
* Tests: `tests/test_features.py` (hybrid binding, both-halves requirement, low-order points, downgrade, legacy fallback,
  rotation).

## 2. Attachments

Files are placed **inside the same AES-256-GCM payload** as subject and body, so names, types, sizes and contents are
all ciphertext (the database only holds the envelope). Limits (`app/config.py`): 5 files, 4 MiB total.

* The download route decrypts on demand and serves the file as `application/octet-stream` with
  `Content-Disposition: attachment`, `nosniff` and `Content-Security-Policy: sandbox`, so a hostile `.html`/`.svg`
  attachment can never run inside the app's origin.
* File names are reduced to a safe base name (no paths, no `<>:"|?*`, control characters, length-capped, extension kept).
* Verified messages only: a tampered message withholds its attachments too.
* Not done on purpose: chunked/streaming encryption (single-shot AES-GCM is fine at 4 MiB) and forwarding of
  attachments (the forward draft says they were not forwarded).

## 3. Reply, forward, delete, trash

* **Reply / Forward** prefill the compose form from a *verified* message (decrypted in RAM, never stored); replying to
  your own sent mail goes to the recipient; `Re:`/`Fwd:` prefixes do not stack.
* **Delete** is a soft delete (`deleted_at`): the message moves to **Trash**, where it can be restored or deleted
  permanently ("Empty trash"). Only the mailbox owner can do any of this (inbox rows belong to the recipient, sent rows to
  the sender).
* A failed send now re-shows the form with what you typed instead of discarding it.
* Inbox/Sent are paginated (20 per page), with an *Unread only* filter and an unread badge in the menu.

## 4. Replay protection

Table `message_ledger` records every message id a mailbox has ever received. It **survives permanent deletion**, so a
captured envelope cannot be re-delivered after the user deleted it. IMAP imports additionally refuse envelopes older
than 45 days. (`tests/test_features.py::test_deleted_message_cannot_be_replayed`.)

## 5. Key transparency log

Table `key_log` is an append-only **hash chain**: each entry stores the SHA-256 of its own fields plus the previous
entry's hash. Every directory change is logged (`publish`, `import`, `replace`, `revoke`, `attach-x25519`) together with a
digest of the complete public key set. The page re-verifies everything on every view:

* edit / delete / re-order a log entry → **chain broken**;
* change a key directly in the database (bypassing the app) → **directory ≠ log**, reported per address;
* the dashboard warns you if the key published for *your* address does not match your keystore.

Compare the **head hash** with other users out-of-band; if it differs, your directories disagree about history. (A single
local log cannot prove it is the same log everyone else sees — that needs a witness/gossip service, out of scope.)

## 6. TOTP two-factor authentication

`app/services/totp.py` implements RFC 4226/6238 (HMAC-SHA1, 6 digits, 30 s, ±1 step) with the RFC test vectors in the tests.

* The secret and the SHA-256 hashes of 8 **one-time recovery codes** live **inside the encrypted keystore**, never in
  clear on disk or in the database. `segno` renders the QR code (optional — the secret is always shown too).
* Sign-in is two steps. After the passphrase the session is *pending*: no page, API call or menu is reachable until the code
  is accepted (also for the OS-keyring sign-in). Failed codes are throttled like passphrases.
* Each time-step is accepted once per account (replay protection); each recovery code works once.
* Two-factor survives key rotation; turning it on/off or regenerating recovery codes needs the passphrase.
* **Limit (stated in the UI):** 2FA protects the *web sign-in*. Someone who steals the keystore *file* and guesses the
  passphrase offline gets the TOTP secret as well — Argon2id is what defends against that.

## 7. Benchmarks

`app/services/benchmarks.py` measures ML-KEM-768, ML-DSA-65, X25519, the hybrid exchange, AES-256-GCM, HKDF and Argon2id,
and compares ML-DSA with RSA-3072, ECDSA P-256 and Ed25519 — all live on your machine (about a second; one run at a
time with a 15 s cool-down). Sizes come from real encoded objects (raw native encodings). It shows the honest trade-off:
post-quantum signatures are fast enough but 10–50× larger than classical ones.

## 8. Attack lab

`app/services/attack_lab.py` runs 14 attacks against PQMail's *own* code inside a sandbox (temporary database, freshly
generated identities) and reports whether each was **BLOCKED**: eavesdropping, bit-flipping, re-addressing, forged sender,
replay, key substitution, pinned-key change, cipher-suite downgrade, malformed KEM data, directory tampering, log
tampering, passphrase guessing, TOTP replay, hostile file names. `tests/test_web_features.py::test_every_attack_is_blocked`
fails if any defence is ever removed, and another test proves the sandbox never touches real data.

## 9. QKD simulator (BB84) upgrades

New in `app/qkd/bb84.py` (still an *educational simulation*, clearly labelled):

* **Channel noise** (0–8 %) that Alice and Bob must correct without mistaking it for Eve.
* **Partial eavesdropping**: Eve intercepts a chosen fraction of the qubits; a lazy Eve can hide below the 10 % threshold,
  but learns only that fraction of the key.
* **Cascade error correction** with back-tracking and a 20-parity verification step (3000 random trials, including 32-bit
  keys: no residual errors, none silently wrong). Every announced parity is counted as leaked information.
* **Privacy amplification**: Toeplitz hashing down to the Shor–Preskill length `n·(1 − 2·h₂(QBER))` minus a safety margin.
* A 7-step **step-through** view (Prepare → Transmit → Measure → Sift → Estimate → Correct → Amplify) and an oracle line showing
  how much of the key Eve really knows (possible only in a simulation).
* Minimum raised to 128 qubits. Not modelled: authenticated classical channels and finite-key security bounds.

## 10. UI and accessibility

Light/dark theme (remembered in the browser, follows the system by default), grouped navigation with dropdown menus, a
mobile menu, skip link, visible focus rings, `aria` labels, reduced-motion support, print styles, and keyboard shortcuts
(`g` then `i`/`s`/`d`/`t`/`c`/`k`, or `c` to compose; ignored while typing). Charts are SVG (the strict CSP forbids inline styles).

## 11. Translations

`app/i18n.py` is a tiny dependency-free gettext-style layer: `_("English text")` in templates and code, `?lang=hi` (remembered in
the session, preserved across sign-in) with `Accept-Language` as fallback. `app/translations/hi.py` has 445 strings;
`tests/test_i18n.py` fails if any `_()` string is missing from the catalog, if a translation drops a `%(placeholder)s`, or if an
entry is stale. Long-form educational pages (Learn, Security model) and service-level error messages stay in English.
To add a language, create `app/translations/<code>.py` with a `CATALOG` dict and list it in `LANGUAGES`.

---

## 12. Speed and serving

`app/server.py` runs the app with waitress on IPv4 **and** IPv6 loopback (so `localhost` is as fast as `127.0.0.1`), static files are
fingerprinted and cached, and language links always point at a real GET page. See R2-8…R2-11 in
[FLAWS_AND_FIXES.md](FLAWS_AND_FIXES.md).

## Problems found while building these (and fixed)

| What | Fix |
|---|---|
| The first error-correction attempt (no back-tracking) left residual errors and wrongly aborted honest noisy runs | Full Cascade with back-tracking + verification; stress-tested on 3000 random keys |
| `gettext("lone % sign")` was mangled by `%`-formatting | Format only when placeholders are supplied; `%%` always renders as `%` |
| Benchmark compared a DER-wrapped ML-KEM key (1206 B) with raw classical keys | All sizes now use native encodings (ML-KEM 1184 B, ML-DSA 1952 B) |
| A keyring-enrolled keystore would have lost its keyring copy when re-sealed (2FA enable, upgrade) | Re-sealing re-wraps the keyring copy automatically (tested) |
| Compose lost the typed message when sending failed | The form is re-shown with the text intact |
| Contacts could not be removed | Added |
