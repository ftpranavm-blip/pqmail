"""Route verification through Flask's test client (no live server needed).

Exercises the complete UI flow end to end: landing, login as Alice,
dashboard, keys, compose -> send to Bob, inbox as Bob, open message,
tamper demo, QKD pages, security/learn/settings, logout.
"""
from __future__ import annotations

import os
import re
import sys
import tempfile

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)

_SANDBOX = tempfile.mkdtemp(prefix="pqmail-routes-")
os.environ["PQMAIL_DATA_DIR"] = _SANDBOX

from app import bootstrap  # noqa: E402  (after env var is set)
from app import create_app  # noqa: E402

FAILURES: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    status = "PASS" if condition else "FAIL"
    print(f"[{status}] {name}" + (f"  ({detail})" if detail and not condition else ""))
    if not condition:
        FAILURES.append(name)


def csrf(client, path: str = "/login") -> str:
    """Fetch a page and return its CSRF token (every POST needs one)."""
    html = client.get(path).get_data(as_text=True)
    found = re.search(r'name="csrf_token" value="([^"]+)"', html)
    return found.group(1) if found else ""


def post(client, path: str, data: dict | None = None, page: str = "/login", **kwargs):
    payload = dict(data or {})
    payload["csrf_token"] = csrf(client, page)
    return client.post(path, data=payload, **kwargs)


def main() -> int:
    bootstrap.ensure_demo_users()
    app = create_app()
    client = app.test_client()

    # --- Logged out -------------------------------------------------------
    r = client.get("/")
    check("GET / (landing page)", r.status_code == 200 and "PQMail" in r.get_data(as_text=True))
    r = client.get("/login")
    check("GET /login", r.status_code == 200)
    r = client.get("/dashboard", follow_redirects=False)
    check("GET /dashboard unauthenticated redirects", r.status_code in (301, 302))

    # --- Login as Alice ---------------------------------------------------
    r = client.post("/login", data={"email": "alice@pqmail.local", "passphrase": "demo1234"})
    check("POST /login without CSRF token is rejected", r.status_code == 400)
    r = post(client, "/login", {"email": "alice@pqmail.local", "passphrase": "demo1234"},
             follow_redirects=True)
    body = r.get_data(as_text=True)
    check("POST /login as Alice", r.status_code == 200 and "Dashboard" in body)
    r = client.get("/dashboard")
    check("GET /dashboard (Alice)", r.status_code == 200)
    r = client.get("/keys")
    check("GET /keys shows ML-KEM-768 fingerprint", r.status_code == 200 and "ML-KEM-768" in r.get_data(as_text=True))
    r = client.get("/contacts")
    check("GET /contacts (Alice sees Bob)", r.status_code == 200 and "Bob" in r.get_data(as_text=True))

    # --- Compose + send Alice -> Bob -------------------------------------
    r = client.get("/compose")
    check("GET /compose", r.status_code == 200)
    r = post(
        client, "/compose",
        {"to": "bob@pqmail.local", "subject": "Route check", "body": "Hello Bob, post-quantum hello!"},
        page="/compose", follow_redirects=True,
    )
    body = r.get_data(as_text=True)
    check("POST /compose (encrypt & send)", r.status_code == 200 and "sent to bob@pqmail.local" in body)

    # --- Alice views her message / security pages -------------------------
    r = client.get("/sent")
    check("GET /sent (Alice) shows the subject", r.status_code == 200 and "Route check" in r.get_data(as_text=True))
    m_sent = re.search(r'/message/([A-Za-z0-9\-_]+)', r.get_data(as_text=True))
    if m_sent:
        r = client.get(f"/message/{m_sent.group(1)}")
        check("Alice can read her own sent message",
              r.status_code == 200 and "post-quantum hello" in r.get_data(as_text=True))

    # --- Logout, login as Bob ---------------------------------------------
    r = client.get("/logout")
    check("GET /logout is not allowed (POST only)", r.status_code == 405)
    r = post(client, "/logout", page="/dashboard", follow_redirects=True)
    check("POST /logout", r.status_code == 200)
    r = post(client, "/login", {"email": "bob@pqmail.local", "passphrase": "demo1234"},
             follow_redirects=True)
    check("POST /login as Bob", r.status_code == 200)

    r = client.get("/inbox")
    check("GET /inbox (Bob)", r.status_code == 200)
    body = r.get_data(as_text=True)
    check("Inbox lists the message subject", "Route check" in body)

    # --- Open the message (decrypt + verify) -------------------------------
    # Find the message id link
    m = re.search(r'/message/([A-Za-z0-9\-_]+)', body)
    check("Inbox contains message link", bool(m))
    if m:
        r = client.get(f"/message/{m.group(1)}")
        msg_body = r.get_data(as_text=True)
        check(
            "GET /message/<id> shows decrypted content",
            r.status_code == 200 and "post-quantum hello" in msg_body,
        )
        check(
            "Security panel: signature verified",
            "Signature Verified" in msg_body or "Verified" in msg_body,
        )
        check("Security panel: ML-KEM-768 present", "ML-KEM-768" in msg_body)

    # --- QKD + info pages ---------------------------------------------------
    r = client.get("/qkd")
    check("GET /qkd", r.status_code == 200)
    r = post(client, "/qkd/run", {"bits": "256"}, page="/qkd", follow_redirects=True)
    qkd_body = r.get_data(as_text=True)
    check("POST /qkd/run without Eve: key agreed",
          r.status_code == 200 and "Protocol aborted" not in qkd_body)
    r = post(client, "/qkd/run", {"bits": "512", "eve": "on"}, page="/qkd", follow_redirects=True)
    qkd_body = r.get_data(as_text=True)
    check("POST /qkd/run with Eve: eavesdropper detected, protocol aborted",
          r.status_code == 200 and "Protocol aborted" in qkd_body)
    r = client.get("/security")
    check("GET /security", r.status_code == 200)
    r = client.get("/learn")
    check("GET /learn", r.status_code == 200)
    r = client.get("/settings")
    check("GET /settings", r.status_code == 200)

    # --- Security: private keys never reachable ----------------------------
    r = client.get("/keys/export")
    exported = r.get_data(as_text=True)
    check(
        "Exported keys contain no PRIVATE material",
        r.status_code == 200 and "PRIVATE KEY" not in exported and "seed" not in exported.lower(),
    )

    # --- Feature round: attachments, reply, trash, transparency, lab, benchmarks, 2FA page -----
    import io

    r = client.get("/logout")  # (Bob is still signed in here; POST sign-out comes at the very end)
    check("GET /logout still not allowed", r.status_code == 405)
    r = client.get("/message/" + (m.group(1) if m else "x"))
    check("Message page shows the hybrid suite", "X25519+ML-KEM-768" in r.get_data(as_text=True))
    r = client.get("/compose?reply_to=" + (m.group(1) if m else "x"))
    check("Reply prefills the compose form", 'value="Re: Route check"' in r.get_data(as_text=True))

    payload = bytes(range(256)) * 8
    r = client.post("/compose", data={
        "to": "alice@pqmail.local", "subject": "Reply with file", "body": "see attachment",
        "csrf_token": csrf(client, "/compose"),
        "attachments": [(io.BytesIO(payload), "report.bin")]}, content_type="multipart/form-data")
    check("POST /compose with an attachment", r.status_code == 302)
    post(client, "/logout", page="/dashboard")
    post(client, "/login", {"email": "alice@pqmail.local", "passphrase": "demo1234"})
    inbox = client.get("/inbox").get_data(as_text=True)
    mid = re.search(r'/message/(pqmail-[0-9a-f]{32})', inbox)
    check("Alice's inbox lists the reply with a paperclip", bool(mid) and "Reply with file" in inbox)
    if mid:
        r = client.get(f"/message/{mid.group(1)}/attachment/0")
        check("Attachment downloads intact as an opaque file",
              r.status_code == 200 and r.data == payload and r.mimetype == "application/octet-stream")
        post(client, f"/message/{mid.group(1)}/delete", page=f"/message/{mid.group(1)}")
        check("Deleted message appears in the trash",
              "Reply with file" in client.get("/trash").get_data(as_text=True))
        post(client, f"/message/{mid.group(1)}/restore", page="/trash")
        check("Restored message is back in the inbox",
              "Reply with file" in client.get("/inbox").get_data(as_text=True))

    r = client.get("/transparency")
    check("Transparency log verifies", r.status_code == 200 and "Log verified" in r.get_data(as_text=True))
    r = client.get("/attack-lab")
    check("GET /attack-lab", r.status_code == 200)
    r = post(client, "/attack-lab/run", page="/attack-lab")
    html = r.get_data(as_text=True)
    check("Attack lab: every attack blocked",
          r.status_code == 200 and "NOT BLOCKED" not in html and re.search(r"(\d+) of \1 attacks blocked", html) is not None)
    r = client.get("/benchmarks")
    check("GET /benchmarks", r.status_code == 200)
    r = client.get("/settings/2fa")
    check("GET /settings/2fa shows a QR code and key", r.status_code == 200 and 'class="key-display"' in r.get_data(as_text=True))
    r = client.get("/settings?lang=hi")
    check("Hindi UI renders", r.status_code == 200 and "सेटिंग्स" in r.get_data(as_text=True))
    client.get("/settings?lang=en")
    r = post(client, "/qkd/run", {"bits": "512", "noise": "2"}, page="/qkd")
    check("QKD with noise: error correction + privacy amplification",
          "Step through the protocol" in r.get_data(as_text=True) and "Key agreement succeeded" in r.get_data(as_text=True))

    print()
    if FAILURES:
        print(f"RESULT: {len(FAILURES)} failure(s): {FAILURES}")
        return 1
    print("RESULT: all route checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
