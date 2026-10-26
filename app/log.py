"""Safe application logging.

Rules enforced by convention in this codebase:

* never log private keys, passphrases, session keys or plaintext content;
* log only events with explicitly passed, non-sensitive fields;
* `event()` is the only function application code should use.
"""
from __future__ import annotations

import logging
import sys
from logging.handlers import RotatingFileHandler

from app import config as cfg

_LOGGER: logging.Logger | None = None


def get_logger() -> logging.Logger:
    """Return the shared 'pqmail' logger, (re)binding the file handler if
    the configured log file path changed (e.g. in tests)."""
    global _LOGGER
    if _LOGGER is None:
        _LOGGER = logging.getLogger("pqmail")
        _LOGGER.setLevel(logging.INFO)
        _LOGGER.propagate = False

    target = str(cfg.LOG_FILE)
    already_bound = any(getattr(h, "_pqmail_target", None) == target for h in _LOGGER.handlers)
    if not already_bound:
        for handler in list(_LOGGER.handlers):
            _LOGGER.removeHandler(handler)
            handler.close()
        cfg.ensure_data_dirs()
        file_handler = RotatingFileHandler(
            cfg.LOG_FILE, maxBytes=512 * 1024, backupCount=2, encoding="utf-8", delay=True
        )
        file_handler._pqmail_target = target  # type: ignore[attr-defined]
        file_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        _LOGGER.addHandler(file_handler)
        console = logging.StreamHandler(sys.stderr)
        console.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
        _LOGGER.addHandler(console)
    return _LOGGER


def event(message: str, **fields: object) -> None:
    """Record an application event.

    Example safe usage::

        event("Email encryption successful", message_id=mid, recipient=addr)

    Never pass plaintext bodies, keys or passphrases into ``fields``.
    """
    extras = " | ".join(f"{key}={_clean(value)}" for key, value in fields.items())
    get_logger().info(f"{message}" + (f" | {extras}" if extras else ""))


def _clean(value: object, limit: int = 200) -> str:
    """One-line, bounded rendering so user-supplied text (e.g. an email typed
    on the login form) cannot forge extra log lines."""
    # Control characters (CR/LF included) are not printable and become "?".
    text = "".join(ch if ch.isprintable() else "?" for ch in str(value))
    return text if len(text) <= limit else text[:limit] + "..."
