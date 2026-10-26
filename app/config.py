"""Centralised configuration and cryptographic parameters.

Every cryptographic parameter (algorithm names, KDF cost factors, HKDF info
string, message format version, QKD thresholds) lives here so that it is
consistent across the whole application and easy to audit.
"""
from __future__ import annotations

import os
import re
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def _load_dotenv(path: Path) -> None:
    """Minimal ``.env`` reader (KEY=VALUE lines, ``#`` comments).

    Real environment variables always win over the file, so deployments and
    tests can override anything. No third-party dependency is needed.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if key and key not in os.environ:
            os.environ[key] = value


_load_dotenv(BASE_DIR / ".env")

# ---------------------------------------------------------------------------
# Runtime paths (override the data directory with PQMAIL_DATA_DIR)
# ---------------------------------------------------------------------------
def _resolve_data_dir() -> Path:
    raw = os.environ.get("PQMAIL_DATA_DIR")
    if not raw:
        return BASE_DIR / "data"
    path = Path(raw).expanduser()
    # A relative path (as in .env.example) is anchored to the project, not to
    # whatever directory the process happens to start in.
    return path if path.is_absolute() else BASE_DIR / path


DATA_DIR = _resolve_data_dir()
DB_PATH = DATA_DIR / "pqmail.db"
KEYS_DIR = DATA_DIR / "keys"
KEY_ARCHIVE_DIR = KEYS_DIR / "archive"
DEMO_MAILBOX_DIR = DATA_DIR / "demo_mailbox"
LOG_DIR = DATA_DIR / "logs"
LOG_FILE = LOG_DIR / "pqmail.log"
SECRET_KEY_FILE = DATA_DIR / "secret_key"


def ensure_data_dirs() -> None:
    """Create the runtime directory layout (idempotent)."""
    for directory in (DATA_DIR, KEYS_DIR, KEY_ARCHIVE_DIR, DEMO_MAILBOX_DIR, LOG_DIR):
        directory.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Cryptographic parameters — single source of truth
# ---------------------------------------------------------------------------
ENVELOPE_VERSION_V1 = "1.0"   # ML-KEM-768 only (still readable, still sendable to legacy keys)
ENVELOPE_VERSION_V2 = "2.0"   # hybrid X25519 + ML-KEM-768
ENVELOPE_VERSION = ENVELOPE_VERSION_V2
KEYSTORE_BUNDLE_VERSION = "1.0"   # public key bundle format

# Key establishment: ML-KEM-768 (NIST FIPS 203).
KEM_ALGORITHM = "ML-KEM-768"
KEM_STANDARD_REF = "NIST FIPS 203"
# Historical naming note: ML-KEM-768 was standardised from CRYSTALS-Kyber.
# Some libraries still expose the name "Kyber768"; that is the predecessor
# implementation name, not a different algorithm.
KEM_LEGACY_NAME = "CRYSTALS-Kyber768 (predecessor implementation name)"
KEM_SECURITY_BITS = "NIST Category 3 (~192-bit classical strength)"

# Hybrid key establishment: X25519 (RFC 7748) combined with ML-KEM-768. The
# message key is derived from BOTH shared secrets, so it stays safe unless an
# attacker breaks X25519 *and* ML-KEM (the approach used by TLS X25519MLKEM768).
CLASSICAL_KEM_ALGORITHM = "X25519"
CLASSICAL_KEM_STANDARD_REF = "RFC 7748"
HYBRID_KEM_ALGORITHM = "X25519+ML-KEM-768"
HKDF_INFO_HYBRID = b"pqmail/hybrid-kem/x25519+mlkem768/v1"

# Digital signatures: ML-DSA-65 (NIST FIPS 204).
SIG_ALGORITHM = "ML-DSA-65"
SIG_STANDARD_REF = "NIST FIPS 204"
SIG_LEGACY_NAME = "CRYSTALS-Dilithium3 (predecessor implementation name)"
SIG_SECURITY_BITS = "NIST Category 3 (~192-bit classical strength)"

AEAD_ALGORITHM = "AES-256-GCM"      # message encryption (NIST SP 800-38D)
KDF_ALGORITHM = "HKDF-SHA-256"      # session key derivation (RFC 5869)
HKDF_INFO_EMAIL = b"pqmail/email/aes-256-gcm/v1"
HKDF_KEY_LENGTH = 32                # bytes -> AES-256
AES_NONCE_BYTES = 12                # 96-bit GCM nonce; fresh random per message

STORAGE_KDF_ALGORITHM = "Argon2id"  # passphrase-based keystore KDF (RFC 9106)
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536          # 64 MiB
ARGON2_PARALLELISM = 4
ARGON2_HASH_LEN = 32
ARGON2_SALT_LEN = 16

# ---------------------------------------------------------------------------
# Application settings
# ---------------------------------------------------------------------------
DEFAULT_DEMO_PASSPHRASE = "demo1234"
DEMO_PASSPHRASE = os.environ.get("PQMAIL_DEMO_PASSPHRASE", DEFAULT_DEMO_PASSPHRASE)
# Demo accounts (Alice/Bob with a publicly known passphrase) are convenient for
# a local demo and dangerous anywhere else: set PQMAIL_DEMO_MODE=0 to disable.
DEMO_ENABLED = os.environ.get("PQMAIL_DEMO_MODE", "1").strip().lower() not in ("0", "false", "no", "off")
MIN_PASSPHRASE_LEN = 8
MAX_PASSPHRASE_LEN = 1024
SESSION_KEY_TTL_SECONDS = 900       # unlocked keys live in RAM for 15 minutes
SESSION_LIFETIME_SECONDS = 8 * 3600  # browser session cookie lifetime
COOKIE_SECURE = os.environ.get("PQMAIL_COOKIE_SECURE", "0").strip().lower() in ("1", "true", "yes", "on")

# Login throttling (per account and per client address, in-memory).
LOGIN_MAX_FAILURES = 5
LOGIN_WINDOW_SECONDS = 300
LOGIN_LOCKOUT_SECONDS = 300

# Bounds applied to Argon2 parameters read back from a keystore file so a
# crafted file cannot make the app allocate unbounded memory/CPU.
ARGON2_MAX_TIME_COST = 10
ARGON2_MAX_MEMORY_COST = 1_048_576  # 1 GiB (KiB units)
ARGON2_MAX_PARALLELISM = 16
MAX_PUBLIC_BUNDLE_BYTES = 64 * 1024
MAX_SUBJECT_LEN = 200
MAX_BODY_LEN = 100_000

# Attachments are encrypted inside the same AES-256-GCM payload as the body.
MAX_ATTACHMENTS = 5
MAX_ATTACHMENT_TOTAL_BYTES = 4 * 1024 * 1024      # raw bytes across all files
MAX_FILENAME_LEN = 120
MAX_REQUEST_BYTES = 12 * 1024 * 1024              # Flask MAX_CONTENT_LENGTH

# Replay defence: mail older than this is not imported from IMAP.
MAX_ENVELOPE_AGE_DAYS = 45

# TOTP two-factor authentication (RFC 6238)
TOTP_DIGITS = 6
TOTP_PERIOD = 30
TOTP_WINDOW = 1                    # accept the previous/next 30 s step (clock drift)
TOTP_ISSUER = "PQMail"
RECOVERY_CODE_COUNT = 8

# Pagination
PAGE_SIZE = 20

BB84_DEFAULT_BITS = 256
BB84_MIN_BITS = 128
BB84_MAX_BITS = 2048
BB84_DETECTION_THRESHOLD = 0.10     # error-rate threshold for Eve detection
BB84_MAX_NOISE = 0.08               # channel noise the simulator allows (bit-flip probability)
BB84_SECURITY_MARGIN = 10           # bits removed by privacy amplification as a safety margin

DEMO_USERS = (
    ("alice@pqmail.local", "Alice"),
    ("bob@pqmail.local", "Bob"),
)


def algorithm_display_info() -> dict[str, dict[str, str]]:
    """Human-readable algorithm metadata for the UI (no secrets)."""
    return {
        "kem": {
            "name": KEM_ALGORITHM,
            "standard": KEM_STANDARD_REF,
            "predecessor": KEM_LEGACY_NAME,
            "role": "Post-quantum key establishment (encapsulation)",
            "security_bits": KEM_SECURITY_BITS,
        },
        "hybrid": {
            "name": HYBRID_KEM_ALGORITHM,
            "standard": f"{CLASSICAL_KEM_STANDARD_REF} + {KEM_STANDARD_REF}",
            "predecessor": "—",
            "role": "Hybrid key exchange: safe unless BOTH X25519 and ML-KEM are broken",
            "security_bits": "128-bit classical + NIST Category 3 post-quantum",
        },
        "signature": {
            "name": SIG_ALGORITHM,
            "standard": SIG_STANDARD_REF,
            "predecessor": SIG_LEGACY_NAME,
            "role": "Post-quantum digital signatures",
            "security_bits": SIG_SECURITY_BITS,
        },
        "symmetric": {
            "name": AEAD_ALGORITHM,
            "standard": "NIST SP 800-38D",
            "predecessor": "—",
            "role": "Message encryption (confidentiality + integrity)",
            "security_bits": "256-bit key",
        },
        "kdf": {
            "name": KDF_ALGORITHM,
            "standard": "RFC 5869",
            "predecessor": "—",
            "role": "Derives the AES key from the KEM shared secret",
            "security_bits": "256-bit output",
        },
        "storage_kdf": {
            "name": STORAGE_KDF_ALGORITHM,
            "standard": "RFC 9106",
            "predecessor": "—",
            "role": "Passphrase-based encryption of the local keystore",
            "security_bits": "256-bit output",
        },
    }


# Conservative address syntax. It doubles as a path-safety guard: the address
# becomes part of a keystore filename, so separators, "..", spaces and control
# characters must never get through.
_EMAIL_RE = re.compile(r"^[a-z0-9][a-z0-9._%+-]{0,63}@[a-z0-9][a-z0-9.-]{0,189}$")


def normalize_email(value: str | None) -> str:
    return (value or "").strip().lower()


def is_valid_email(value: str | None) -> bool:
    email = normalize_email(value)
    return bool(_EMAIL_RE.match(email)) and ".." not in email and len(email) <= 254


def get_secret_key() -> str:
    """Flask session-signing key.

    Priority: ``PQMAIL_SECRET_KEY`` env var, then a key persisted in the data
    directory (created once, owner-only), so browser sessions survive restarts
    and work across worker processes.
    """
    env = os.environ.get("PQMAIL_SECRET_KEY")
    if env:
        return env
    ensure_data_dirs()
    try:
        value = SECRET_KEY_FILE.read_text(encoding="utf-8").strip()
        if len(value) >= 32:
            return value
    except OSError:
        pass
    value = secrets.token_hex(32)
    SECRET_KEY_FILE.write_text(value, encoding="utf-8")
    try:
        SECRET_KEY_FILE.chmod(0o600)
    except OSError:  # pragma: no cover - Windows handles ACLs differently
        pass
    return value


def flask_host() -> str:
    return os.environ.get("FLASK_HOST", "127.0.0.1")


def flask_port() -> int:
    try:
        return int(os.environ.get("FLASK_PORT", "5000"))
    except ValueError:
        return 5000


def is_loopback_host(host: str) -> bool:
    return host in ("127.0.0.1", "localhost", "::1")


def check_safe_binding(host: str) -> str | None:
    """Return an error message when the configuration is unsafe, else None.

    Binding to a non-loopback interface while the public demo accounts exist
    would let anyone on the network sign in as Alice or Bob.
    """
    if DEMO_ENABLED and not is_loopback_host(host):
        return (
            f"Refusing to listen on {host!r} while demo accounts are enabled "
            "(their passphrase is public). Set PQMAIL_DEMO_MODE=0, or use FLASK_HOST=127.0.0.1."
        )
    return None


def smtp_config() -> dict[str, str] | None:
    """Read SMTP settings from the environment; None when not configured."""
    host = os.environ.get("SMTP_HOST")
    username = os.environ.get("SMTP_USERNAME")
    password = os.environ.get("SMTP_PASSWORD")
    if not (host and username and password):
        return None
    return {
        "host": host,
        "port": int(os.environ.get("SMTP_PORT", "465")),
        "username": username,
        "password": password,
    }


def imap_config() -> dict[str, str] | None:
    """Read IMAP settings from the environment; None when not configured."""
    host = os.environ.get("IMAP_HOST")
    username = os.environ.get("IMAP_USERNAME")
    password = os.environ.get("IMAP_PASSWORD")
    if not (host and username and password):
        return None
    return {
        "host": host,
        "port": int(os.environ.get("IMAP_PORT", "993")),
        "username": username,
        "password": password,
    }
