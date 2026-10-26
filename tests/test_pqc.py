"""Test 1 & 2 — ML-KEM-768 key generation and encapsulation (FIPS 203)."""
from __future__ import annotations

import pytest

from app.crypto import pqc
from app.crypto.pqc import PQCryptoError


def test_kem_keypair_generation():
    """Test 1: ML-KEM-768 keypair generates with correct key sizes.

    ``public_bytes()``/``private_bytes()`` return DER (SPKI / PKCS#8), so the
    raw FIPS 203 sizes are wrapped in a small ASN.1 header (~22-24 bytes)."""
    pair = pqc.generate_kem_keypair()
    pub = pair.public_bytes()
    priv = pair.private_bytes()
    # FIPS 203: 1184-byte encapsulation key (raw); DER adds a small ASN.1 header.
    assert 1184 <= len(pub) <= 1184 + 32
    # pyca serialises ML-KEM private keys in SEED form (32-byte seed, FIPS 203
    # appendix D) — the tiny PKCS#8 DER expands to the full 2400-byte secret key.
    assert 64 <= len(priv) <= 128
    # Fresh randomness: two keypairs must never collide.
    other = pqc.generate_kem_keypair()
    assert other.public_bytes() != pub


def test_kem_is_real_mlkem768_type():
    """The implementation is genuine ML-KEM-768, not a stand-in."""
    pair = pqc.generate_kem_keypair()
    assert isinstance(pair.private_key, pqc.mlkem.MLKEM768PrivateKey)
    assert isinstance(pair.public_key, pqc.mlkem.MLKEM768PublicKey)


def test_kem_serialization_roundtrip():
    pair = pqc.generate_kem_keypair()
    loaded_pub = pqc.load_kem_public_key(pair.public_bytes())
    loaded_priv = pqc.load_kem_private_key(pair.private_bytes())
    shared, ct = pqc.encapsulate(loaded_pub)
    assert pqc.decapsulate(loaded_priv, ct) == shared


def test_encapsulation_decapsulation_shared_secret_matches():
    """Test 2: Encaps/Decaps — both sides derive the identical shared secret."""
    pair = pqc.generate_kem_keypair()
    shared_sender, kem_ct = pqc.encapsulate(pair.public_key)
    shared_receiver = pqc.decapsulate(pair.private_key, kem_ct)
    assert shared_sender == shared_receiver
    assert len(shared_sender) == 32  # FIPS 203: 32-byte shared secret
    # Every encapsulation must be fresh (new ciphertext + new secret).
    shared2, ct2 = pqc.encapsulate(pair.public_key)
    assert ct2 != kem_ct
    assert shared2 != shared_sender


def test_decapsulation_with_wrong_key_fails():
    """A KEM ciphertext decapsulated under a different key must not yield
    the original shared secret (implicit rejection per FIPS 203)."""
    kp1 = pqc.generate_kem_keypair()
    kp2 = pqc.generate_kem_keypair()
    shared, ct = pqc.encapsulate(kp1.public_key)
    wrong = pqc.decapsulate(kp2.private_key, ct)
    # Either an exception or a different (pseudorandom) secret — never match.
    assert wrong != shared


def test_kem_public_key_validation_rejects_garbage():
    with pytest.raises(PQCryptoError):
        pqc.load_kem_public_key(b"\x00" * 64)
    with pytest.raises(PQCryptoError):
        # A valid key of the WRONG algorithm/type must also be rejected.
        sig_pair = pqc.generate_dsa_keypair()
        pqc.load_kem_public_key(sig_pair.public_bytes())
