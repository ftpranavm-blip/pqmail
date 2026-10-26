"""Tests 7 & 8 — BB84 QKD educational simulation (no Eve / with Eve)."""
from __future__ import annotations

import random

import pytest

from app import config as cfg
from app.qkd import bb84
from app.qkd.bb84 import QKDParameterError


def test_bb84_without_eve_keys_match():
    """Test 7: without Eve, Alice and Bob end up with identical keys."""
    result = bb84.run_bb84(256, eve_present=False, rng=random.Random(42))
    assert result.keys_match is True
    assert result.key_alice == result.key_bob
    assert result.qber == 0.0
    assert result.eve_detected is False
    assert result.aborted is False
    assert result.final_key_length > 0
    # Sifting keeps only matching-basis positions (~50%).
    assert 0 < result.sifted_length <= result.n_bits


def test_bb84_with_eve_is_detected():
    """Test 8: intercept-resend Eve raises the error rate above threshold."""
    results = [bb84.run_bb84(256, eve_present=True, rng=random.Random(seed))
               for seed in range(10)]
    detected = sum(1 for r in results if r.eve_detected)
    # Expected QBER ~25% >> 10% threshold; detection may be missed only with
    # tiny probability, so requiring most runs to detect is sound.
    assert detected >= 8, f"Eve detected in only {detected}/10 runs"
    for r in results:
        if r.eve_detected:
            assert r.aborted is True
            assert r.final_key_length == 0  # aborted: no key is produced
            assert r.qber > cfg.BB84_DETECTION_THRESHOLD


def test_bb84_eve_error_rate_far_above_clean_run():
    """Statistical contrast between the two scenarios (the demo point)."""
    clean = bb84.run_bb84(512, eve_present=False, rng=random.Random(1))
    eve = bb84.run_bb84(512, eve_present=True, rng=random.Random(1))
    assert eve.qber > clean.qber
    assert eve.qber > 0.10
    assert clean.qber <= 0.10


def test_transcript_preview_contains_protocol_fields():
    result = bb84.run_bb84(128, eve_present=True, rng=random.Random(7))
    rows = bb84.transcript_preview(result, limit=8)
    assert len(rows) == 8
    row = rows[0]
    assert set(row) >= {"position", "alice_bit", "alice_basis", "bob_basis",
                        "bob_bit", "sifted", "match", "eve_basis", "eve_bit"}
    assert row["alice_basis"] in {"+", "×"}
    # Eve's bases and bits are recorded for every position when present.
    assert len(result.eve_bases) == result.n_bits
    assert len(result.eve_bits) == result.n_bits


def test_bits_to_hex_roundtrip():
    assert bb84.bits_to_hex([]) == "—"
    assert bb84.bits_to_hex([1, 1, 1, 1, 1, 1, 1, 1]) == "ff"
    assert bb84.bits_to_hex([0, 0, 0, 0, 0, 0, 0, 1]) == "01"


def test_qkd_parameter_validation():
    """Test (section 25): invalid QKD parameters are rejected."""
    with pytest.raises(QKDParameterError):
        bb84.run_bb84(32)            # below minimum
    with pytest.raises(QKDParameterError):
        bb84.run_bb84(10_000)        # above maximum
    with pytest.raises(QKDParameterError):
        bb84.run_bb84(cfg.BB84_DEFAULT_BITS, eve_present="yes")  # type: ignore[arg-type]


def test_final_key_excludes_public_sample_bits():
    """The publicly compared sample is sacrificed; the key uses the rest."""
    result = bb84.run_bb84(256, eve_present=False, rng=random.Random(3))
    sample = set(result.sample_positions)
    key_positions = set(range(result.sifted_length)) - sample
    assert result.final_key_length == len(key_positions)


# ---------------------------------------------------------------------------
# Feature round: noise, partial Eve, error correction, privacy amplification
# ---------------------------------------------------------------------------
def test_noise_without_eve_is_corrected_not_mistaken_for_eve():
    for seed in range(20):
        r = bb84.run_bb84(1024, False, rng=random.Random(seed), noise=0.04)
        assert not r.eve_detected and not r.aborted, seed
        assert r.ec_errors_after == 0 and r.keys_match
        assert r.secret_key and r.secret_key == r.secret_key_bob


def test_error_correction_fixes_errors_and_counts_leakage():
    r = bb84.run_bb84(2048, False, rng=random.Random(11), noise=0.05)
    assert r.ec_errors_before > 5 and r.ec_errors_after == 0
    assert r.ec_leaked_bits >= r.ec_errors_before          # at least a parity per fixed error
    assert r.ec_passes >= 1 and r.corrected_bob == r.key_alice


def test_cascade_lite_directly():
    rng = random.Random(5)
    alice = [rng.randint(0, 1) for _ in range(400)]
    bob = list(alice)
    for i in rng.sample(range(400), 12):
        bob[i] ^= 1
    fixed, stats = bb84.cascade(alice, bob, 12 / 400, random.Random(6))
    assert fixed == alice and stats["fixed"] == 12 and stats["parities"] > 12
    assert bob != alice                                    # input list untouched
    clean, stats = bb84.cascade(alice, list(alice), 0.01, random.Random(1))
    assert clean == alice and stats["fixed"] == 0
    assert bb84.cascade([], [], 0.01, random.Random(1))[0] == []


def test_privacy_amplification_shrinks_with_noise():
    lengths = []
    for noise in (0.0, 0.03, 0.06):
        r = bb84.run_bb84(2048, False, rng=random.Random(2), noise=noise)
        lengths.append(r.secret_key_length)
        assert r.secret_key_length < r.final_key_length
    assert lengths[0] > lengths[1] > lengths[2] > 0


def test_secret_key_length_bound():
    n_clean, f_clean = bb84.secret_key_length(1000, 0.0)
    assert f_clean == 1.0 and n_clean == 1000 - cfg.BB84_SECURITY_MARGIN
    assert bb84.secret_key_length(1000, 0.11)[0] == 0      # beyond ~11% nothing is provably secret
    assert bb84.binary_entropy(0.5) == 1.0 and bb84.binary_entropy(0.0) == 0.0


def test_toeplitz_hash_properties():
    rng = random.Random(9)
    key = [rng.randint(0, 1) for _ in range(256)]
    seed = rng.getrandbits(256 + 100 - 1)
    out = bb84.toeplitz_hash(key, 100, seed)
    assert len(out) == 100 and set(out) <= {0, 1}
    assert bb84.toeplitz_hash(key, 100, seed) == out                      # deterministic
    flipped = list(key)
    flipped[0] ^= 1
    assert bb84.toeplitz_hash(flipped, 100, seed) != out                   # input change -> output change
    assert bb84.toeplitz_hash(key, 100, seed ^ ((1 << 200) - 1)) != out
    # linearity over GF(2): H(a xor b) = H(a) xor H(b)
    other = [rng.randint(0, 1) for _ in range(256)]
    xored = [a ^ b for a, b in zip(key, other)]
    assert bb84.toeplitz_hash(xored, 100, seed) == [a ^ b for a, b in zip(out, bb84.toeplitz_hash(other, 100, seed))]
    assert bb84.toeplitz_hash(key, 0, seed) == [] and bb84.toeplitz_hash([], 5, seed) == []


def test_partial_eve_learns_proportionally_and_pa_removes_it():
    low = bb84.run_bb84(2048, True, rng=random.Random(3), intercept_fraction=0.1)
    high = bb84.run_bb84(2048, True, rng=random.Random(3), intercept_fraction=0.5)
    full = bb84.run_bb84(2048, True, rng=random.Random(3), intercept_fraction=1.0)
    assert low.eve_intercepted < high.eve_intercepted < full.eve_intercepted
    assert low.eve_known_bits < high.eve_known_bits < full.eve_known_bits
    assert not low.eve_detected and full.eve_detected          # a lazy Eve may slip under the threshold...
    assert low.qber < high.qber < full.qber
    assert low.secret_key_length < low.final_key_length        # ...but the key shrinks accordingly
    assert full.secret_key == [] and full.aborted


def test_eve_with_zero_interception_is_harmless():
    r = bb84.run_bb84(512, True, rng=random.Random(4), intercept_fraction=0.0)
    assert r.eve_intercepted == 0 and r.eve_known_bits == 0 and r.qber == 0.0 and not r.aborted


@pytest.mark.parametrize("kwargs", [{"noise": -0.01}, {"noise": cfg.BB84_MAX_NOISE + 0.01}, {"noise": "x"},
                                    {"intercept_fraction": 1.5}, {"intercept_fraction": -0.1},
                                    {"noise": True}])
def test_new_parameter_validation(kwargs):
    with pytest.raises(QKDParameterError):
        bb84.run_bb84(256, True, **kwargs)


def test_boolean_is_not_a_valid_qubit_count():
    with pytest.raises(QKDParameterError):
        bb84.run_bb84(True)          # bool is an int subclass; must still be rejected


def test_preview_marks_uninterecepted_positions():
    r = bb84.run_bb84(256, True, rng=random.Random(8), intercept_fraction=0.5)
    rows = bb84.transcript_preview(r, limit=64)
    assert any(row["eve_basis"] == "—" for row in rows) and any(row["eve_basis"] != "—" for row in rows)
    assert all((row["eve_basis"] == "—") == (not r.eve_active[row["position"]]) for row in rows)


def test_hex_views_present_after_success():
    r = bb84.run_bb84(512, False, rng=random.Random(12))
    assert r.secret_key_hex != "—" and r.secret_key_hex == r.secret_key_bob_hex
    assert r.eve_knowledge_percent == "0.0%"


def test_cascade_is_reliable_across_many_noisy_runs():
    """No residual errors over many random keys and error rates (back-tracking works)."""
    rng = random.Random(2024)
    for trial in range(60):
        n = rng.choice([128, 256, 512, 1000])
        rate = rng.choice([0.01, 0.02, 0.04, 0.07, 0.09])
        alice = [rng.randint(0, 1) for _ in range(n)]
        bob = [bit ^ (rng.random() < rate) for bit in alice]
        fixed, stats = bb84.cascade(alice, bob, max(rate, 0.01), random.Random(trial))
        assert fixed == alice, (trial, n, rate)
        assert stats["verified"]


def test_cascade_reports_unverifiable_key_instead_of_lying(monkeypatch):
    """If the key cannot be reconciled, the stats must say so."""
    alice = [0] * 64
    bob = [1] * 64
    monkeypatch.setattr(bb84, "MAX_CASCADE_PASSES", 4)
    monkeypatch.setattr(bb84, "_parity", lambda bits, idx: 0)      # a broken oracle: nothing ever differs
    fixed, stats = bb84.cascade(alice, bob, 0.5, random.Random(1))
    assert fixed == bob and stats["fixed"] == 0
