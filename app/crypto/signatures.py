"""ML-DSA-65 signing/verification over the canonical envelope bytes."""
from __future__ import annotations

from app.crypto.pqc import (
    DsaKeyPair,
    SignatureVerificationError,
    generate_dsa_keypair,
    sign,
    verify,
)

__all__ = [
    "DsaKeyPair",
    "SignatureVerificationError",
    "generate_dsa_keypair",
    "sign",
    "verify",
]
