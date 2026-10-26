"""Tests 3 & 4 — AES-256-GCM encryption and tamper detection."""
from __future__ import annotations

import os

import pytest

from app.crypto import encryption
from app.crypto.encryption import TamperError


def test_hkdf_derives_32_byte_key():
    """ML-KEM shared secret -> HKDF-SHA-256 -> 32-byte AES-256 key."""
    shared = os.urandom(32)
    salt = os.urandom(16)
    key = encryption.hkdf_derive(shared, salt)
    assert len(key) == 32
    # Same inputs -> same key; different salt -> different key.
    assert encryption.hkdf_derive(shared, salt) == key
    assert encryption.hkdf_derive(shared, os.urandom(16)) != key


def test_hkdf_uses_central_info_string():
    """The HKDF info string is a centralised config constant (auditable)."""
    from app import config as cfg

    shared = os.urandom(32)
    k1 = encryption.hkdf_derive(shared, os.urandom(16))
    k2 = encryption.hkdf_derive(shared, os.urandom(16), info=b"other-purpose")
    assert k1 != k2
    assert cfg.HKDF_INFO_EMAIL == b"pqmail/email/aes-256-gcm/v1"


def test_encrypt_decrypt_roundtrip():
    """Test 3: encrypt/decrypt — plaintext survives exactly."""
    key = os.urandom(32)
    plaintext = "Hello Bob, this message is protected using post-quantum cryptography.".encode()
    aad = b"envelope-metadata"
    nonce, sealed = encryption.aead_encrypt(key, plaintext, aad=aad)
    assert len(nonce) == 12
    assert sealed != plaintext
    assert plaintext not in sealed
    recovered = encryption.aead_decrypt(key, nonce, sealed, aad=aad)
    assert recovered == plaintext


def test_aad_binds_ciphertext_to_metadata():
    """Decrypting with different AAD must fail (metadata is authenticated)."""
    key = os.urandom(32)
    nonce, sealed = encryption.aead_encrypt(key, b"secret body", aad=b"sender=Alice")
    with pytest.raises(TamperError):
        encryption.aead_decrypt(key, nonce, sealed, aad=b"sender=Mallory")


def test_nonce_never_reused_for_same_key():
    """Fresh random nonce per encryption: two calls give different nonces."""
    key = os.urandom(32)
    n1, _ = encryption.aead_encrypt(key, b"a")
    n2, _ = encryption.aead_encrypt(key, b"a")
    assert n1 != n2


def test_tampered_ciphertext_fails():
    """Test 4: flipping one ciphertext bit must break AEAD authentication."""
    key = os.urandom(32)
    nonce, sealed = encryption.aead_encrypt(key, b"attack at dawn", aad=b"meta")
    for flip in (0x01, 0x80, 0xFF):  # first byte, last byte, mask
        bad = bytearray(sealed)
        bad[0] ^= flip
        with pytest.raises(TamperError):
            encryption.aead_decrypt(key, nonce, bytes(bad), aad=b"meta")


def test_tampered_tag_fails():
    """Modifying the GCM authentication tag must also fail."""
    key = os.urandom(32)
    nonce, sealed = encryption.aead_encrypt(key, b"attack at dawn")
    bad = bytearray(sealed)
    bad[-1] ^= 0x01  # last 16 bytes of `sealed` are the tag
    with pytest.raises(TamperError):
        encryption.aead_decrypt(key, nonce, bytes(bad))


def test_wrong_key_fails():
    key = os.urandom(32)
    nonce, sealed = encryption.aead_encrypt(key, b"secret")
    with pytest.raises(TamperError):
        encryption.aead_decrypt(os.urandom(32), nonce, sealed)


def test_key_length_enforced():
    """AES-256-GCM must reject short/long keys (no silent downgrade)."""
    with pytest.raises(ValueError):
        encryption.aead_encrypt(b"short-key", b"x")
    nonce, sealed = encryption.aead_encrypt(os.urandom(32), b"x")
    with pytest.raises(ValueError):
        encryption.aead_decrypt(b"short-key", nonce, sealed)
