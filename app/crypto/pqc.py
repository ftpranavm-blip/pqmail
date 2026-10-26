"""Post-quantum key establishment and signatures (ML-KEM / ML-DSA).

Implementation note — library selection
=======================================

The PS asks for liboqs/liboqs-python, which requires a native C build on
Windows and has no official wheels. This project instead uses
**pyca/cryptography >= 48**, the most widely vetted Python crypto library
(1.2 billion downloads/month), which ships real ML-KEM and ML-DSA
implementations with Rust bindings vetted by Trail of Bits.

* ML-KEM-768  (NIST FIPS 203) — key establishment
* ML-DSA-65   (NIST FIPS 204) — digital signatures

Naming note: ML-KEM was standardised from CRYSTALS-Kyber and ML-DSA from
CRYSTALS-Dilithium. Older libraries expose the names ``Kyber768`` /
``Dilithium3`` — these are predecessor implementation names for the same
lattice problems, not separate algorithms.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem, x25519


class PQCryptoError(Exception):
    """Base class for PQC layer errors."""


class DecapsulationError(PQCryptoError):
    """ML-KEM decapsulation failed (e.g. wrong private key or bad ciphertext)."""


class SignatureVerificationError(PQCryptoError):
    """ML-DSA signature did not verify."""


# ---------------------------------------------------------------------------
# ML-KEM-768 — key establishment (FIPS 203)
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class KemKeyPair:
    private_key: mlkem.MLKEM768PrivateKey
    public_key: mlkem.MLKEM768PublicKey

    def public_bytes(self) -> bytes:
        """SPKI DER encoding (safe to share)."""
        return self.public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def private_bytes(self) -> bytes:
        """PKCS#8 DER encoding (must be encrypted at rest!)."""
        return self.private_key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )


def generate_kem_keypair() -> KemKeyPair:
    """Generate a fresh ML-KEM-768 key pair."""
    private_key = mlkem.MLKEM768PrivateKey.generate()
    return KemKeyPair(private_key, private_key.public_key())


def encapsulate(public_key: mlkem.MLKEM768PublicKey) -> Tuple[bytes, bytes]:
    """Run ML-KEM Encaps: return ``(shared_secret, kem_ciphertext)``.

    The shared secret is the 32-byte value defined by FIPS 203.
    """
    return public_key.encapsulate()


def decapsulate(private_key: mlkem.MLKEM768PrivateKey, ciphertext: bytes) -> bytes:
    """Run ML-KEM Decaps: recover the shared secret from a KEM ciphertext."""
    try:
        return private_key.decapsulate(ciphertext)
    except Exception as exc:  # noqa: BLE001 - normalise library errors
        raise DecapsulationError(
            "ML-KEM decapsulation failed: the KEM ciphertext does not match this key."
        ) from exc


def load_kem_public_key(der: bytes) -> mlkem.MLKEM768PublicKey:
    """Parse a subjectPublicKeyInfo DER ML-KEM-768 public key (validates format)."""
    try:
        key = serialization.load_der_public_key(der)
    except Exception as exc:  # noqa: BLE001
        raise PQCryptoError("Invalid ML-KEM public key encoding.") from exc
    if not isinstance(key, mlkem.MLKEM768PublicKey):
        raise PQCryptoError("Public key is not an ML-KEM-768 key.")
    return key


def load_kem_private_key(der: bytes) -> mlkem.MLKEM768PrivateKey:
    """Parse a PKCS#8 DER ML-KEM-768 private key."""
    try:
        key = serialization.load_der_private_key(der, password=None)
    except Exception as exc:  # noqa: BLE001
        raise PQCryptoError("Invalid ML-KEM private key encoding.") from exc
    if not isinstance(key, mlkem.MLKEM768PrivateKey):
        raise PQCryptoError("Private key is not an ML-KEM-768 key.")
    return key


# ---------------------------------------------------------------------------
# ML-DSA-65 — digital signatures (FIPS 204)
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class DsaKeyPair:
    private_key: mldsa.MLDSA65PrivateKey
    public_key: mldsa.MLDSA65PublicKey

    def public_bytes(self) -> bytes:
        return self.public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def private_bytes(self) -> bytes:
        return self.private_key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )


def generate_dsa_keypair() -> DsaKeyPair:
    """Generate a fresh ML-DSA-65 signing key pair."""
    private_key = mldsa.MLDSA65PrivateKey.generate()
    return DsaKeyPair(private_key, private_key.public_key())


def sign(private_key: mldsa.MLDSA65PrivateKey, data: bytes) -> bytes:
    """Create an ML-DSA-65 signature over ``data``."""
    return private_key.sign(data)


def verify(public_key: mldsa.MLDSA65PublicKey, signature: bytes, data: bytes) -> bool:
    """Verify an ML-DSA-65 signature. Returns True/False, never raises."""
    try:
        public_key.verify(signature, data)
        return True
    except InvalidSignature:
        return False
    except Exception:  # noqa: BLE001 - malformed signature material
        return False


def load_dsa_public_key(der: bytes) -> mldsa.MLDSA65PublicKey:
    try:
        keys = serialization.load_der_public_key(der)
    except Exception as exc:  # noqa: BLE001
        raise PQCryptoError("Invalid ML-DSA public key encoding.") from exc
    if not isinstance(keys, mldsa.MLDSA65PublicKey):
        raise PQCryptoError("Public key is not an ML-DSA-65 key.")
    return keys


def load_dsa_private_key(der: bytes) -> mldsa.MLDSA65PrivateKey:
    try:
        keys = serialization.load_der_private_key(der, password=None)
    except Exception as exc:  # noqa: BLE001
        raise PQCryptoError("Invalid ML-DSA private key encoding.") from exc
    if not isinstance(keys, mldsa.MLDSA65PrivateKey):
        raise PQCryptoError("Private key is not an ML-DSA-65 key.")
    return keys


# ---------------------------------------------------------------------------
# X25519 — classical half of the hybrid key exchange (RFC 7748)
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class X25519KeyPair:
    private_key: x25519.X25519PrivateKey
    public_key: x25519.X25519PublicKey

    def public_bytes(self) -> bytes:
        """Raw 32-byte public key (safe to share)."""
        return self.public_key.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def private_bytes(self) -> bytes:
        """Raw 32-byte private key (must be encrypted at rest!)."""
        return self.private_key.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
            serialization.NoEncryption())


def generate_x25519_keypair() -> X25519KeyPair:
    private_key = x25519.X25519PrivateKey.generate()
    return X25519KeyPair(private_key, private_key.public_key())


def load_x25519_public_key(raw: bytes) -> x25519.X25519PublicKey:
    if not isinstance(raw, (bytes, bytearray)) or len(raw) != 32:
        raise PQCryptoError("Invalid X25519 public key (must be 32 bytes).")
    try:
        return x25519.X25519PublicKey.from_public_bytes(bytes(raw))
    except Exception as exc:  # noqa: BLE001
        raise PQCryptoError("Invalid X25519 public key.") from exc


def load_x25519_private_key(raw: bytes) -> x25519.X25519PrivateKey:
    if not isinstance(raw, (bytes, bytearray)) or len(raw) != 32:
        raise PQCryptoError("Invalid X25519 private key (must be 32 bytes).")
    try:
        return x25519.X25519PrivateKey.from_private_bytes(bytes(raw))
    except Exception as exc:  # noqa: BLE001
        raise PQCryptoError("Invalid X25519 private key.") from exc
