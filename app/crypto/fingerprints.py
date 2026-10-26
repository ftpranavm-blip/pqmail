"""Public-key fingerprinting (SHA-256 truncated to a readable form)."""
from __future__ import annotations

import hashlib


def public_key_fingerprint(public_key_der: bytes) -> str:
    """Return a 160-bit SHA-256 fingerprint as ten groups of four hex digits.

    Example: ``BA78 16BF 8F01 CFEA 4141 40DE 5DAE 2223 B003 61A3``. Grouped
    uppercase hex, the same style PGP users expect. The 20 bytes are the first
    20 bytes of the SHA-256 digest of the complete DER public key.
    """
    digest = hashlib.sha256(public_key_der).digest()[:20]
    hexstr = digest.hex().upper()
    return " ".join(hexstr[i:i + 4] for i in range(0, len(hexstr), 4))


def short_fingerprint(public_key_der: bytes, groups: int = 2) -> str:
    """Return the first ``groups`` groups of the fingerprint (compact form)."""
    return " ".join(public_key_fingerprint(public_key_der).split()[:groups])
