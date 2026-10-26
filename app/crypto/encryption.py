"""Hybrid email encryption primitives: ML-KEM-768 -> HKDF-SHA-256 -> AES-256-GCM.

Why hybrid?
===========
ML-KEM cannot encrypt arbitrary data: it encapsulates a 32-byte shared
secret. The correct architecture (used by TLS 1.3 hybrid groups such as
X25519MLKEM768, and by this project) is:

    sender:  (shared, ct) = Encaps(recipient ML-KEM public key)
             aes_key      = HKDF-SHA-256(shared, salt, info)
             ciphertext   = AES-256-GCM(aes_key, nonce, plaintext, aad)
    receiver: shared     = Decaps(own ML-KEM private key, ct)
             aes_key     = HKDF-SHA-256(shared, salt, info)
             plaintext   = AES-256-GCM-open(aes_key, nonce, ciphertext, aad)

The KEM protects the *key establishment* against future quantum computers;
AES-GCM provides fast authenticated encryption for the message itself. The
associated data (AAD) binds the ciphertext to the envelope metadata so that
swapping or editing metadata breaks decryption as well as the signature.

The mail service (app/services/mail_service.py) orchestrates these
primitives; this module intentionally contains no parsing logic.
"""
from __future__ import annotations

import os
from typing import Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app import config as cfg

_GCM_KEY_BYTES = 32  # AES-256


def hkdf_derive(shared_secret: bytes, salt: bytes, info: bytes = cfg.HKDF_INFO_EMAIL,
                length: int = cfg.HKDF_KEY_LENGTH) -> bytes:
    """Derive an AES-256 key from an ML-KEM shared secret (RFC 5869)."""
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info)
    return hkdf.derive(shared_secret)


def aead_encrypt(key: bytes, plaintext: bytes, aad: bytes | None = None,
                 nonce: bytes | None = None) -> Tuple[bytes, bytes]:
    """AES-256-GCM encrypt. Returns ``(nonce, ciphertext_including_tag)``.

    A fresh random 96-bit nonce is generated with the OS CSPRNG for every
    call (or an explicitly provided nonce is used, for protocols that must
    know the nonce before encrypting). A new session key is established for
    every message, so a nonce is never reused with the same key.
    """
    if len(key) != _GCM_KEY_BYTES:
        raise ValueError("AES-256-GCM requires a 32-byte key.")
    nonce = nonce or os.urandom(cfg.AES_NONCE_BYTES)
    if len(nonce) != cfg.AES_NONCE_BYTES:
        raise ValueError("Invalid nonce length.")
    sealed = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce, sealed


def aead_decrypt(key: bytes, nonce: bytes, ciphertext: bytes,
                 aad: bytes | None = None) -> bytes:
    """AES-256-GCM decrypt. Raises :class:`TamperError` on any tampering.

    On failure no plaintext is revealed — GCM authentication covers both
    the ciphertext and the associated data.
    """
    if len(key) != _GCM_KEY_BYTES:
        raise ValueError("AES-256-GCM requires a 32-byte key.")
    if len(nonce) != cfg.AES_NONCE_BYTES:
        raise ValueError("Invalid nonce length.")
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise TamperError(
            "Message integrity check failed - the message may have been modified."
        ) from exc


class TamperError(Exception):
    """Raised when AES-GCM authentication fails (ciphertext/AAD modified)."""
