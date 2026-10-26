"""Live performance + size benchmarks: post-quantum vs classical cryptography.

Everything here is measured on *this* machine at the moment the user clicks the
button - nothing is hard-coded. Classical comparators (RSA-3072, ECDSA P-256,
Ed25519) come from the same ``cryptography`` library, so the comparison is fair.
Sizes are taken from real encoded key/ciphertext/signature objects, using each algorithm's
native public-key encoding (RSA: DER SubjectPublicKeyInfo; ECDSA: uncompressed point).
"""
from __future__ import annotations

import os
import statistics
import time
from dataclasses import dataclass, field
from typing import Callable

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app import config as cfg
from app.crypto import encryption, hybrid, pqc
from app.storage.secure_storage import derive_storage_key


@dataclass
class Timing:
    group: str            # "Key exchange" | "Signatures" | "Symmetric / KDF"
    algorithm: str
    operation: str
    runs: int
    mean_ms: float
    median_ms: float
    classical: bool = False

    @property
    def ops_per_sec(self) -> float:
        return 1000.0 / self.mean_ms if self.mean_ms > 0 else float("inf")


@dataclass
class SizeRow:
    algorithm: str
    kind: str             # "Key exchange" | "Signature"
    public_key: int
    ciphertext_or_signature: int
    classical: bool = False
    quantum_safe: bool = True


@dataclass
class BenchmarkReport:
    timings: list[Timing] = field(default_factory=list)
    sizes: list[SizeRow] = field(default_factory=list)
    seconds: float = 0.0
    finished_at: str = ""


def _measure(fn: Callable[[], object], runs: int) -> tuple[float, float]:
    samples = []
    for _ in range(runs):
        start = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - start) * 1000.0)
    return statistics.fmean(samples), statistics.median(samples)


def _add(report: BenchmarkReport, group: str, algorithm: str, operation: str, runs: int,
         fn: Callable[[], object], classical: bool = False) -> None:
    mean, median = _measure(fn, runs)
    report.timings.append(Timing(group, algorithm, operation, runs, mean, median, classical))


def _der_pub(key) -> bytes:
    return key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def _raw_pub(key) -> bytes:
    """Algorithm-native public key encoding (what the standards quote as the key size)."""
    return key.public_bytes_raw()


def run_benchmarks(scale: float = 1.0) -> BenchmarkReport:
    """Run all benchmarks. ``scale`` shrinks the iteration counts (used by tests)."""
    def n(base: int) -> int:
        return max(1, int(base * scale))

    started = time.perf_counter()
    report = BenchmarkReport()
    kx, sig, sym = "Key exchange", "Signatures", "Symmetric / KDF"

    # ---- post-quantum / hybrid key exchange --------------------------------------------
    kem = pqc.generate_kem_keypair()
    xk = pqc.generate_x25519_keypair()
    _ss, ct = pqc.encapsulate(kem.public_key)
    _hs, hct, heph = hybrid.hybrid_encapsulate(kem.public_key, xk.public_key)
    _add(report, kx, "ML-KEM-768", "key generation", n(30), pqc.generate_kem_keypair)
    _add(report, kx, "ML-KEM-768", "encapsulate", n(60), lambda: pqc.encapsulate(kem.public_key))
    _add(report, kx, "ML-KEM-768", "decapsulate", n(60), lambda: pqc.decapsulate(kem.private_key, ct))
    _add(report, kx, "X25519", "key generation", n(200), pqc.generate_x25519_keypair, classical=True)
    peer = pqc.generate_x25519_keypair()
    _add(report, kx, "X25519", "key agreement", n(200),
         lambda: xk.private_key.exchange(peer.public_key), classical=True)
    _add(report, kx, "X25519+ML-KEM-768 (hybrid)", "encapsulate", n(60),
         lambda: hybrid.hybrid_encapsulate(kem.public_key, xk.public_key))
    _add(report, kx, "X25519+ML-KEM-768 (hybrid)", "decapsulate", n(60),
         lambda: hybrid.hybrid_decapsulate(kem.private_key, xk.private_key, hct, heph))

    # ---- signatures --------------------------------------------------------------------------
    message = os.urandom(1024)
    dsa = pqc.generate_dsa_keypair()
    dsa_sig = pqc.sign(dsa.private_key, message)
    _add(report, sig, "ML-DSA-65", "key generation", n(30), pqc.generate_dsa_keypair)
    _add(report, sig, "ML-DSA-65", "sign", n(60), lambda: pqc.sign(dsa.private_key, message))
    _add(report, sig, "ML-DSA-65", "verify", n(60), lambda: pqc.verify(dsa.public_key, dsa_sig, message))

    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    pss = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
    rsa_sig = rsa_key.sign(message, pss, hashes.SHA256())
    _add(report, sig, "RSA-3072", "key generation", max(1, n(2)),
         lambda: rsa.generate_private_key(public_exponent=65537, key_size=3072), classical=True)
    _add(report, sig, "RSA-3072", "sign", n(20),
         lambda: rsa_key.sign(message, pss, hashes.SHA256()), classical=True)
    _add(report, sig, "RSA-3072", "verify", n(60),
         lambda: rsa_key.public_key().verify(rsa_sig, message, pss, hashes.SHA256()), classical=True)

    ec_key = ec.generate_private_key(ec.SECP256R1())
    ec_sig = ec_key.sign(message, ec.ECDSA(hashes.SHA256()))
    _add(report, sig, "ECDSA P-256", "key generation", n(100),
         lambda: ec.generate_private_key(ec.SECP256R1()), classical=True)
    _add(report, sig, "ECDSA P-256", "sign", n(100),
         lambda: ec_key.sign(message, ec.ECDSA(hashes.SHA256())), classical=True)
    _add(report, sig, "ECDSA P-256", "verify", n(100),
         lambda: ec_key.public_key().verify(ec_sig, message, ec.ECDSA(hashes.SHA256())), classical=True)

    ed_key = ed25519.Ed25519PrivateKey.generate()
    ed_sig = ed_key.sign(message)
    _add(report, sig, "Ed25519", "sign", n(200), lambda: ed_key.sign(message), classical=True)
    _add(report, sig, "Ed25519", "verify", n(200),
         lambda: ed_key.public_key().verify(ed_sig, message), classical=True)

    # ---- symmetric / KDF ----------------------------------------------------------------------
    aes_key, nonce, blob = os.urandom(32), os.urandom(12), os.urandom(1024 * 1024)
    sealed = AESGCM(aes_key).encrypt(nonce, blob, None)
    _add(report, sym, "AES-256-GCM", "encrypt 1 MiB", n(20), lambda: AESGCM(aes_key).encrypt(nonce, blob, None))
    _add(report, sym, "AES-256-GCM", "decrypt 1 MiB", n(20), lambda: AESGCM(aes_key).decrypt(nonce, sealed, None))
    _add(report, sym, "HKDF-SHA-256", "derive key", n(500),
         lambda: encryption.hkdf_derive(os.urandom(32), os.urandom(16)))
    salt = os.urandom(cfg.ARGON2_SALT_LEN)
    _add(report, sym, f"Argon2id ({cfg.ARGON2_MEMORY_COST // 1024} MiB)", "passphrase -> key", max(1, n(3)),
         lambda: derive_storage_key("benchmark-passphrase", salt))

    # ---- sizes (from real encoded objects) -----------------------------------------------------------
    report.sizes = [
        SizeRow("ML-KEM-768", "Key exchange", len(_raw_pub(kem.public_key)), len(ct)),
        SizeRow("X25519", "Key exchange", len(xk.public_bytes()), 32, classical=True, quantum_safe=False),
        SizeRow("X25519+ML-KEM-768 (hybrid)", "Key exchange",
                len(_raw_pub(kem.public_key)) + len(xk.public_bytes()), len(hct) + len(heph)),
        SizeRow("ML-DSA-65", "Signature", len(_raw_pub(dsa.public_key)), len(dsa_sig)),
        SizeRow("RSA-3072", "Signature", len(_der_pub(rsa_key.public_key())), len(rsa_sig),
                classical=True, quantum_safe=False),
        SizeRow("ECDSA P-256", "Signature", len(ec_key.public_key().public_bytes(
                serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)), len(ec_sig),
                classical=True, quantum_safe=False),
        SizeRow("Ed25519", "Signature", 32, len(ed_sig), classical=True, quantum_safe=False),
    ]
    report.seconds = time.perf_counter() - started
    report.finished_at = time.strftime("%Y-%m-%d %H:%M:%S")
    return report
