"""Request-level security helpers: CSRF protection and login throttling.

CSRF
====
Every state-changing request (POST/PUT/PATCH/DELETE) must carry the
per-session token, either as the ``csrf_token`` form field or the
``X-CSRF-Token`` header. Without it any web page the user visits could submit
forms to this app (send mail, rotate keys, import keys, log the user out...).
The token is random per session, compared in constant time, and rendered into
forms with ``{{ csrf_field() }}``.

Login throttling
================
Each login attempt costs a 64 MiB Argon2id derivation, so unlimited guessing is
both a brute-force and a denial-of-service risk. Failed attempts are counted per
account and per client address; once the limit is hit the app answers "too many
attempts" *without* running Argon2 until the lockout expires. State is in-memory
(per process), which matches the app's single-process design.
"""
from __future__ import annotations

import hmac
import secrets
import threading
import time

from flask import Flask, abort, request, session
from markupsafe import Markup

from app import config as cfg

_SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}
_FORM_FIELD = "csrf_token"
_HEADER = "X-CSRF-Token"


# ---------------------------------------------------------------------------
# CSRF
# ---------------------------------------------------------------------------
def csrf_token() -> str:
    token = session.get("_csrf")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf"] = token
    return token


def csrf_field() -> Markup:
    return Markup(f'<input type="hidden" name="{_FORM_FIELD}" value="{csrf_token()}">')


def _check_csrf() -> None:
    if request.method in _SAFE_METHODS:
        return
    expected = session.get("_csrf")
    supplied = request.form.get(_FORM_FIELD) or request.headers.get(_HEADER) or ""
    if not expected or not hmac.compare_digest(str(expected), str(supplied)):
        abort(400, description="csrf")


def init_csrf(app: Flask) -> None:
    app.before_request(_check_csrf)
    app.jinja_env.globals["csrf_token"] = csrf_token
    app.jinja_env.globals["csrf_field"] = csrf_field


# ---------------------------------------------------------------------------
# Login throttling
# ---------------------------------------------------------------------------
class LoginThrottle:
    def __init__(self, max_failures: int, window: int, lockout: int):
        self.max_failures = max_failures
        self.window = window
        self.lockout = lockout
        self._failures: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def _recent(self, key: str, now: float) -> list[float]:
        recent = [t for t in self._failures.get(key, []) if now - t < self.window]
        if recent:
            self._failures[key] = recent
        else:
            self._failures.pop(key, None)
        return recent

    def retry_after(self, key: str, limit: int | None = None) -> int:
        """Seconds until ``key`` may try again (0 when not locked out)."""
        limit = limit or self.max_failures
        now = time.time()
        with self._lock:
            recent = self._recent(key, now)
            if len(recent) >= limit:
                return max(1, int(recent[-1] + self.lockout - now))
        return 0

    def record_failure(self, key: str) -> None:
        with self._lock:
            now = time.time()
            self._recent(key, now)
            self._failures.setdefault(key, []).append(now)

    def reset(self, key: str) -> None:
        with self._lock:
            self._failures.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._failures.clear()


login_throttle = LoginThrottle(cfg.LOGIN_MAX_FAILURES, cfg.LOGIN_WINDOW_SECONDS,
                               cfg.LOGIN_LOCKOUT_SECONDS)

# One address may legitimately mistype for several accounts; allow it more tries.
IP_FAILURE_LIMIT = cfg.LOGIN_MAX_FAILURES * 4


def login_lockout_seconds(email: str, client_addr: str | None) -> int:
    wait = login_throttle.retry_after(f"acct:{email}")
    if client_addr:
        wait = max(wait, login_throttle.retry_after(f"ip:{client_addr}", IP_FAILURE_LIMIT))
    return wait


def login_failed(email: str, client_addr: str | None) -> None:
    login_throttle.record_failure(f"acct:{email}")
    if client_addr:
        login_throttle.record_failure(f"ip:{client_addr}")


def login_succeeded(email: str) -> None:
    login_throttle.reset(f"acct:{email}")
