"""In-memory cache of unlocked identity keys for active browser sessions.

Security properties:

* unlocked private keys are held in RAM only, never written to disk;
* entries expire after ``SESSION_KEY_TTL_SECONDS`` and are swept lazily;
* passphrases themselves are never stored anywhere;
* access is guarded by a lock (the dev server is multi-threaded).
"""
from __future__ import annotations

import secrets
import threading
import time

from app import config as cfg
from app.crypto.key_manager import IdentityKeys

_cache: dict[str, tuple[float, IdentityKeys]] = {}
_lock = threading.Lock()


def new_token() -> str:
    return secrets.token_urlsafe(32)


def store(token: str, keys: IdentityKeys) -> None:
    with _lock:
        _cache[token] = (time.time(), keys)
        _sweep()


def get(token: str | None) -> IdentityKeys | None:
    if not token:
        return None
    with _lock:
        entry = _cache.get(token)
        if entry is None:
            return None
        stored_at, keys = entry
        if time.time() - stored_at > cfg.SESSION_KEY_TTL_SECONDS:
            _cache.pop(token, None)
            return None
        _cache[token] = (time.time(), keys)  # refresh sliding TTL
        return keys


def pop(token: str | None) -> None:
    if token:
        with _lock:
            _cache.pop(token, None)


def clear() -> None:
    """Drop every unlocked key (used by tests)."""
    with _lock:
        _cache.clear()


def _sweep() -> None:
    """Remove expired entries; caller must hold ``_lock``."""
    now = time.time()
    expired = [t for t, (ts, _k) in _cache.items() if now - ts > cfg.SESSION_KEY_TTL_SECONDS]
    for token in expired:
        _cache.pop(token, None)
