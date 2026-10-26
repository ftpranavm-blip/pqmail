"""Hybrid key establishment: X25519 + ML-KEM-768.

Why hybrid?
===========
ML-KEM is new (standardised in 2024) while X25519 has two decades of scrutiny.
Combining both means an attacker must break **both** to recover the message
key: a future quantum computer cannot (ML-KEM), and an unforeseen flaw in the
young lattice scheme cannot (X25519). This is the construction TLS 1.3 uses for
``X25519MLKEM768``.

Construction
============
    sender:   (ss_pq, ct)  = ML-KEM-768.Encaps(recipient_kem_pub)
              eph          = fresh X25519 key pair
              ss_x         = X25519(eph_priv, recipient_x25519_pub)
              shared       = HKDF-SHA-256(ikm  = ss_pq || ss_x,
                                           info = label || len(ct) || ct
                                                  || eph_pub || recipient_x25519_pub)
    receiver: ss_pq = ML-KEM-768.Decaps(kem_priv, ct)
              ss_x  = X25519(x25519_priv, eph_pub)
              shared = same HKDF

The ciphertext, the ephemeral public key and the recipient's X25519 public key
are mixed into the HKDF ``info`` so the derived secret is bound to this exact
exchange. The result feeds the per-message HKDF (random salt) that produces the
AES-256-GCM key, exactly as in the PQ-only envelope.
"""
from __future__ import annotations

import struct
from typing import Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import mlkem, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app import config as cfg
from app.crypto import pqc


def _combine(ss_pq: bytes, ss_x: bytes, kem_ct: bytes, eph_pub: bytes, recipient_x_pub: bytes) -> bytes:
    info = (cfg.HKDF_INFO_HYBRID + struct.pack(">I", len(kem_ct)) + kem_ct
            + eph_pub + recipient_x_pub)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(ss_pq + ss_x)


def _raw_public(key: x25519.X25519PublicKey) -> bytes:
    from cryptography.hazmat.primitives import serialization

    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def hybrid_encapsulate(kem_public: mlkem.MLKEM768PublicKey,
                       x25519_public: x25519.X25519PublicKey) -> Tuple[bytes, bytes, bytes]:
    """Return ``(shared_secret, kem_ciphertext, x25519_ephemeral_public)``."""
    ss_pq, kem_ct = pqc.encapsulate(kem_public)
    eph = pqc.generate_x25519_keypair()
    try:
        ss_x = eph.private_key.exchange(x25519_public)
    except ValueError as exc:  # low-order point -> all-zero secret is rejected
        raise pqc.PQCryptoError("Recipient X25519 public key is unusable.") from exc
    eph_pub = eph.public_bytes()
    return _combine(ss_pq, ss_x, kem_ct, eph_pub, _raw_public(x25519_public)), kem_ct, eph_pub


def hybrid_decapsulate(kem_private: mlkem.MLKEM768PrivateKey,
                       x25519_private: x25519.X25519PrivateKey,
                       kem_ct: bytes, eph_pub: bytes) -> bytes:
    """Recover the shared secret; raises :class:`pqc.DecapsulationError` on bad input."""
    ss_pq = pqc.decapsulate(kem_private, kem_ct)
    try:
        peer = pqc.load_x25519_public_key(eph_pub)
        ss_x = x25519_private.exchange(peer)
    except (pqc.PQCryptoError, ValueError) as exc:
        raise pqc.DecapsulationError("X25519 key agreement failed (bad ephemeral key).") from exc
    return _combine(ss_pq, ss_x, kem_ct, eph_pub, _raw_public(x25519_private.public_key()))
