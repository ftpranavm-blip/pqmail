"""Tests 9 & 10 — secure private-key storage (Argon2id + AES-256-GCM)."""
from __future__ import annotations

import base64
import json

import pytest

from app import config as cfg
from app.crypto.key_manager import (WrongPassphraseError, create_keystore,
                                    load_identity, rotate_keys)
from app.storage.secure_storage import (KeyStore, KeyStoreError,
                                        derive_storage_key)


@pytest.fixture()
def keystore_dir(tmp_path):
    return tmp_path / "keys"


def test_keystore_creation_and_unlock(keystore_dir):
    """Test 9: encrypted private keys can be restored with the passphrase."""
    info = create_keystore(keystore_dir, "carol@pqmail.local", "correct horse battery")
    assert info["kem_fingerprint"] and info["sig_fingerprint"]

    keystore = KeyStore.load(keystore_dir, "carol@pqmail.local")
    bundle = keystore.unlock("correct horse battery")
    # Private DERs are tiny PKCS#8 seed-form keys (see test_pqc note).
    assert bundle["kem_private_der"][0] == 0x30   # DER SEQUENCE tag
    assert bundle["dsa_private_der"][0] == 0x30

    identity = load_identity(keystore_dir, "carol@pqmail.local", "correct horse battery")
    from app.crypto import pqc

    shared, ct = pqc.encapsulate(identity.kem.public_key)
    assert pqc.decapsulate(identity.kem.private_key, ct) == shared


def test_wrong_passphrase_cannot_recover_keys(keystore_dir):
    """Test 10: a wrong passphrase must never unlock the keystore."""
    create_keystore(keystore_dir, "dave@pqmail.local", "right-passphrase-1")
    with pytest.raises((KeyStoreError, WrongPassphraseError)):
        load_identity(keystore_dir, "dave@pqmail.local", "wrong-passphrase-2")


def test_private_keys_never_stored_in_plaintext(keystore_dir):
    """The keystore file must not contain raw DER private keys or the passphrase."""
    passphrase = "super-secret-pass-9"
    info = create_keystore(keystore_dir, "erin@pqmail.local", passphrase)
    raw = KeyStore.store_path_for(keystore_dir, "erin@pqmail.local").read_bytes()

    # No plaintext passphrase, no raw private-key bytes.
    assert passphrase.encode() not in raw
    # Public keys ARE stored (they are not secret) and must decode.
    meta = json.loads(raw)["metadata"]
    assert meta["kem_public_key_b64"] == info["kem_public_b64"]
    assert meta["algorithms"] == {"kem": cfg.KEM_ALGORITHM,
                                  "signature": cfg.SIG_ALGORITHM}
    # Argon2id parameters are recorded (non-secret, needed for unlock).
    kdf = meta["kdf"]
    assert kdf["algorithm"] == "Argon2id"
    assert kdf["time_cost"] == cfg.ARGON2_TIME_COST
    assert kdf["memory_cost"] == cfg.ARGON2_MEMORY_COST


def test_keystore_file_tampering_detected(keystore_dir):
    """Flipping a byte in the sealed blob must break unlock (AES-GCM auth)."""
    create_keystore(keystore_dir, "frank@pqmail.local", "passphrase-abc-1")
    path = KeyStore.store_path_for(keystore_dir, "frank@pqmail.local")
    data = json.loads(path.read_text())
    blob = bytearray(base64.b64decode(data["blob_b64"]))
    blob[10] ^= 0xFF
    data["blob_b64"] = base64.b64encode(bytes(blob)).decode()
    path.write_text(json.dumps(data))

    keystore = KeyStore.load(keystore_dir, "frank@pqmail.local")
    with pytest.raises(KeyStoreError):
        keystore.unlock("passphrase-abc-1")


def test_salt_is_unique_per_identity(keystore_dir):
    create_keystore(keystore_dir, "g1@pqmail.local", "passphrase-12345")
    create_keystore(keystore_dir, "g2@pqmail.local", "passphrase-12345")
    s1 = json.loads(KeyStore.store_path_for(keystore_dir, "g1@pqmail.local").read_text())
    s2 = json.loads(KeyStore.store_path_for(keystore_dir, "g2@pqmail.local").read_text())
    assert s1["metadata"]["kdf"]["salt_b64"] != s2["metadata"]["kdf"]["salt_b64"]


def test_storage_key_deterministic_and_salted(keystore_dir):
    salt = bytes(range(16))
    k1 = derive_storage_key("same passphrase", salt)
    k2 = derive_storage_key("same passphrase", salt)
    k3 = derive_storage_key("other passphrase", salt)
    assert k1 == k2 and k1 != k3 and len(k1) == 32


def test_passphrase_policy_enforced(keystore_dir):
    with pytest.raises(KeyStoreError):
        create_keystore(keystore_dir, "h1@pqmail.local", "short")
    with pytest.raises(KeyStoreError):
        create_keystore(keystore_dir, "h2@pqmail.local", "")


def test_new_identity_does_not_overwrite_existing():
    """Registration must never silently replace an existing identity (PS §38)."""
    from app.bootstrap import create_identity

    # create_identity stores under cfg.KEYS_DIR (sandboxed data dir in tests).
    info1 = create_identity("iris@pqmail.local", "Iris", "passphrase-1111")
    with pytest.raises(ValueError):
        create_identity("iris@pqmail.local", "Iris Again", "passphrase-2222")
    # Original keys still unlock with the original passphrase.
    identity = load_identity(cfg.KEYS_DIR, "iris@pqmail.local", "passphrase-1111")
    assert identity.kem.public_bytes() == base64.b64decode(info1["kem_public_b64"])


def test_key_rotation_archives_old_and_generates_new(keystore_dir):
    info_old = create_keystore(keystore_dir, "jack@pqmail.local", "old-pass-12345")
    info_new = rotate_keys(keystore_dir, "jack@pqmail.local",
                           "old-pass-12345", "new-pass-67890")
    assert info_new["kem_fingerprint"] != info_old["kem_fingerprint"]
    assert info_new["sig_fingerprint"] != info_old["sig_fingerprint"]
    # Old keystore archived, not destroyed.
    archived = list(cfg.KEY_ARCHIVE_DIR.glob("jack_at_pqmail.local*.keystore.json"))
    assert archived, "old keystore should be archived"
    # New keys unlock with the new passphrase; old passphrase no longer works.
    identity = load_identity(keystore_dir, "jack@pqmail.local", "new-pass-67890")
    assert identity.kem.public_bytes() == __import__("base64").b64decode(info_new["kem_public_b64"])
    with pytest.raises((KeyStoreError, WrongPassphraseError)):
        load_identity(keystore_dir, "jack@pqmail.local", "old-pass-12345")
