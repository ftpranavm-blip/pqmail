# Hackathon Demo Script — PQMail (Quantum-Secure Email Client)

**Total demo time:** ~8 minutes (timings per stage below).
**Golden rule:** say what it does, show that it works, never claim more than it is.

---

## New demo moves (≈ 3 extra minutes)

1. **Hybrid + attachments:** compose to Bob with a PDF; on Bob's message page point at *X25519+ML-KEM-768 · v2.0* and download the file.
2. **Attack lab:** *Security → Attack lab → Run all attacks* — 14 live attacks, all **BLOCKED**; open "Mallory impersonates Alice".
3. **Transparency log:** *Security → Transparency log*; then explain the dashboard warning that appears if someone swaps your key.
4. **Two-factor:** *Settings → Two-factor authentication*, scan the QR, sign out and back in.
5. **Benchmarks:** *Learn → Benchmarks* — "fast, but ML-DSA signatures are ~50× larger than Ed25519".
6. **QKD:** run with 3 % noise and a 20 % Eve; step through *Correct errors* and *Amplify privacy*.
7. **Hindi + light theme:** click हिन्दी and the ◐ button.

## 0. Pre-demo checklist (2 minutes before you present)

- [ ] Server running: `.\venv\Scripts\activate` → `python app.py` → open `http://127.0.0.1:5000/`
- [ ] Landing page loads (this is your title slide backdrop)
- [ ] Browser zoom at 110–125%, close other tabs
- [ ] Have this open in a second window: the `/security` page (backup if you lose your place)
- [ ] Rehearse line 1 of Stage 1 out loud once.

**If the demo breaks live:** fall back to `pytest tests/ -v` output — say
"the automated test suite covers all of this" and show `scripts\verify_routes.py` results.

---

## 1. Hook + Problem (0:00–1:00) — *Landing page on screen*

**Say:**
> "Every email you send today is protected by public-key cryptography — RSA, elliptic curves.
> A large quantum computer will break all of it. Attackers are already harvesting encrypted
> traffic now, waiting to decrypt it later. This is PQMail — an email client where the
> quantum threat is already priced in."

**Point at the screen:**
> "Real, standardized post-quantum cryptography — ML-KEM-768 and ML-DSA-65 — the NIST
> standards from 2024, running live in this browser. Not a mockup; let me show you."

---

## 2. Identity & Keys (1:00–2:00) — *Click: "Open the demo" → login page*

**Do:** On the login page, hover over the demo account buttons but **type manually**:
enter `alice@pqmail.local` and passphrase `demo1234`, then click **Unlock keys & sign in**.

**Say (while it unlocks):**
> "Alice's private keys never live as files on disk. They're sealed with Argon2id plus
> AES-256-GCM. That passphrase just decrypted them into RAM — for this session only.
> If anyone steals the database, they get ciphertext-on-ciphertext."

**Do:** Click **Security / Keys** in the nav.

**Say:**
> "Here is Alice's quantum-safe identity: two keypairs. ML-KEM-768 to *establish* keys,
> ML-DSA-65 to *sign*. The fingerprints are how contacts verify each other out-of-band —
> same idea as Signal's safety numbers, but post-quantum."

**Do:** Click **⬇ Export public keys** briefly, show the JSON, go back.

**Say:**
> "Public keys are meant to be shared. Private keys never leave this page — there is no
> screen, API, or log line that can print them. That's by construction."

---

## 3. The Kill Shot — Send (2:00–3:30) — *Click: Compose*

**Do:** Fill in:
- **To:** `bob@pqmail.local`
- **Subject:** `Q3 roadmap`
- **Message:** `Hello Bob, this message is protected using post-quantum cryptography.`

**Point at the Security panel on the right:**
> "Notice these three checkboxes — End-to-End Encryption, Post-Quantum Key Exchange,
> Digital Signature — are always on. There's no 'turn off security' toggle. Security is
> the default, not an option."

**Do:** Click **🔒 Encrypt & Send**. Read the success flash message aloud:

> "Encrypted and sent — and look at the numbers: a ~1 KB ML-KEM ciphertext and a ~3 KB
> ML-DSA signature. Here's what just happened in those milliseconds:"

**Say (count on fingers):**
> "One: Alice fetched Bob's KEM public key from the directory. Two: ML-KEM encapsulation
> produced a shared secret — this is the part quantum computers can't break. Three: HKDF
> derived a 256-bit AES key from it. Four: AES-256-GCM encrypted the message. Five: the
> whole envelope was signed with ML-DSA-65. The server stored exactly one thing: ciphertext."

---

## 4. Receive + Verify (3:30–4:45) — *Click: Sign out → login as Bob*

**Do:** Sign out, sign in as **Bob** (`bob@pqmail.local` / `demo1234`), open **Inbox**.

**Say:**
> "Notice the inbox listing shows '🔐 Encrypted message' — not the subject line. Even the
> subject is inside the encrypted payload. A compromised server learns who wrote to whom,
> and nothing else."

**Do:** Click the message.

**Say (point at each green check as you go):**
> "Bob's side, automatically: signature verified against Alice's published public key.
> ML-KEM decapsulation with Bob's private key. AES-GCM authenticated decryption. If *any*
> of those steps failed, you would not be reading this text — the app withholds content
> it cannot trust. It fails closed."

---

## 5. Tamper Detection (4:45–5:45) — *Stay on the message; click: ⚡ Simulate Tampering*

**Do:** Click **⚡ Simulate Tampering** (confirm the dialog).

**Say (while it flips the bit):**
> "This flips one single bit of the ciphertext — a man-in-the-middle making a tiny edit."

**Do:** Attempt to open / show the failed state.

**Say:**
> "One bit. AES-GCM's authentication tag catches it instantly, and the signature check
> fails too. The app doesn't show the 'closest' plaintext or a warning-beside-content —
> it refuses to display untrusted data. Integrity failure is a hard stop."

---

## 6. QKD Simulation (5:45–7:00) — *Click: QKD Sim*

**Say (before clicking anything):**
> "Separate question: how do two parties *agree* on a key by physics alone? That's Quantum
> Key Distribution. This page is an honest simulation — it teaches BB84, it is not real
> quantum hardware, and the email protection you just saw does not depend on it. The
> banner on the page says exactly that."

**Do:** Set qubits to 256, leave **Include Eve** unchecked, click **Run simulation**.

**Say:**
> "No eavesdropper: Alice and Bob sift matching bases and end up with identical keys.
> Error rate near zero."

**Do:** Check **Include Eve (intercept–resend eavesdropper)**, click **Run simulation**.

**Say:**
> "Now Eve measures every qubit and resends her own. Quantum mechanics says measurement
> disturbs the state — the error rate jumps to roughly 25% and the app prints
> **DETECTED**. That's the beautiful trick of BB84: spying leaves fingerprints."

---

## 7. Close + Architecture (7:00–8:00) — *Click: Security (or Learn)*

**Say:**
> "To summarize the stack: ML-KEM-768 for key establishment — harvest-now-decrypt-later
> is dead on arrival against this. AES-256-GCM for content — symmetric crypto was already
> quantum-resistant. ML-DSA-65 for signatures — sender impersonation fails. Encrypted
> keystore — stolen devices reveal nothing. And SMTP/IMAP still work underneath: this is
> real email infrastructure, just with an end-to-end quantum-safe envelope on top.
> Sixty-five automated tests cover every guarantee I just claimed — including the
> failure cases: tampering, wrong keys, wrong passwords."

**Final line (memorize):**
> "Post-quantum isn't a future migration plan. It's a hundred lines of Python and an
> afternoon — and it's already running. Thank you."

---

## Judge Q&A cheat sheet

| Question | Answer |
|---|---|
| "Is this real PQC or a simulation?" | "Real — pyca/cryptography's ML-KEM (FIPS 203) and ML-DSA (FIPS 204). Only the QKD page is a simulation, and it's labeled as such in the UI." |
| "Why not liboqs?" | "pyca/cryptography ships audited, maintained FIPS-standard implementations with Windows wheels. Same standards, stronger supply chain." |
| "Why AES-GCM and not encrypt with ML-KEM directly?" | "KEMs establish keys; they don't bulk-encrypt. The hybrid pattern is exactly what TLS 1.3 + PQC does: KEM → HKDF → AEAD. Fast, and the message can be arbitrarily large." |
| "What about forward secrecy?" | "Each email gets a fresh encapsulated session key, so one leaked key doesn't unlock other emails. Rotation keeps old keys so old mail stays readable, which is *not* forward secrecy; a per-message ratchet is future work — I say so in the README's limitations." |
| "Can it send to real Gmail?" | "Yes — Real Email Mode with SMTP/IMAP via env vars, TLS enforced. Demo Mode exists so no credentials touch the demo machine." |
| "What if the server is malicious?" | "It stores ciphertext and opaque metadata only; subjects are never in plaintext at rest. It can deny service, but it can't read or forge mail — that's the E2EE threat model." |
| "Why ML-KEM-768 and not 512/1024?" | "768 is NIST's recommended category (roughly AES-192 equivalent), and it's what Chrome/OpenSSH deployed in practice." |
| "Replay attacks?" | "Unique random message IDs plus timestamps are validated; a full anti-replay window is documented as future work." |

---

## Timing safety valves

- **Running long?** Skip Stage 6's no-Eve run (do Eve only) and compress Stage 7 to the final line.
- **Running short?** In Stage 2, click **rotate keys** and explain nothing is silently overwritten — old fingerprint stays in history.
- **Never skip:** Stage 5 (tamper). It is the single most persuasive 60 seconds of the demo.
