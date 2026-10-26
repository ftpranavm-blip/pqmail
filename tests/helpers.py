"""Small helpers shared by the web-level tests."""
from __future__ import annotations

import re
import uuid

from app import config as cfg
from app.bootstrap import create_identity
from app.crypto.key_manager import load_identity

PASS = "longenough-passphrase"


def make_user(prefix="user"):
    """Register a fresh local identity; returns (email, unlocked keys)."""
    email = f"{prefix}-{uuid.uuid4().hex[:8]}@pqmail.test"
    create_identity(email, prefix.title(), PASS)
    return email, load_identity(cfg.KEYS_DIR, email, PASS)


def token(client, path="/login"):
    html = client.get(path).get_data(as_text=True)
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)


def post(client, path, data=None, page="/login", **kw):
    data = dict(data or {})
    data["csrf_token"] = token(client, page)
    return client.post(path, data=data, **kw)


def login(client, email, passphrase=PASS):
    return post(client, "/login", {"email": email, "passphrase": passphrase})
