"""Shared pytest fixtures for the PQMail test suite.

Isolation strategy:

* ``PQMAIL_DATA_DIR`` is pointed at a fresh temporary directory **before**
  any ``app`` import, so every config path (DB, keystores, logs) lands in
  the sandbox instead of the developer's ``data/`` folder.
* Each test gets its own SQLite database (``db.set_db``) so tests never
  see each other's envelopes. Keystores persist across tests within the
  session sandbox (they are expensive and idempotent to create).
* Argon2id parameters are lowered *in the test configuration only* to keep
  the suite fast; production parameters are unchanged (config.py).
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

_SANDBOX = Path(tempfile.mkdtemp(prefix="pqmail-tests-"))
os.environ["PQMAIL_DATA_DIR"] = str(_SANDBOX)

# Import app modules ONLY after the environment variable is set.
from app import config as cfg  # noqa: E402

# Faster (still genuine) Argon2id for tests; seal and unseal both read the
# live config values, so parameters stay consistent within the test run.
cfg.ARGON2_TIME_COST = 1
cfg.ARGON2_MEMORY_COST = 8192  # 8 MiB instead of 64 MiB
cfg.ARGON2_PARALLELISM = 1

DEMO_PASSPHRASE = cfg.DEMO_PASSPHRASE  # "demo1234"


@pytest.fixture(autouse=True)
def isolated_db(tmp_path):
    """Give every test a fresh SQLite database."""
    from app import db as database

    database.set_db(database.Database(tmp_path / "test.db"))
    yield
    database.set_db(None)


@pytest.fixture()
def demo_world():
    """Demo users (Alice & Bob) with keystores and published public keys."""
    from app.bootstrap import ensure_demo_users

    ensure_demo_users()
    return {
        "alice": "alice@pqmail.local",
        "bob": "bob@pqmail.local",
        "passphrase": DEMO_PASSPHRASE,
    }


@pytest.fixture()
def alice_keys(demo_world):
    from app.crypto.key_manager import load_identity

    return load_identity(cfg.KEYS_DIR, "alice@pqmail.local", DEMO_PASSPHRASE)


@pytest.fixture()
def bob_keys(demo_world):
    from app.crypto.key_manager import load_identity

    return load_identity(cfg.KEYS_DIR, "bob@pqmail.local", DEMO_PASSPHRASE)


@pytest.fixture()
def client(demo_world):
    """Flask test client with clean login-throttle and unlocked-key state."""
    from app import create_app, security, session_keys
    from app.services import benchmarks  # noqa: F401  (import check)

    security.login_throttle.clear()
    session_keys.clear()
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()
