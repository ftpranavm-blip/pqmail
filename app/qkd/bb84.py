"""BB84 — Educational Quantum Key Distribution simulation.

    ┌─────────┐   quantum channel    ┌─────────┐
    │  ALICE  │ ──── qubits ────▶  │   BOB   │
    └─────────┘   (maybe Eve!)     └─────────┘

Protocol steps simulated here
=============================
1. Alice generates ``n`` random bits and ``n`` random bases (+ or ×).
2. She prepares one qubit per bit: basis ``+`` encodes 0→|0⟩ 1→|1⟩;
   basis ``×`` encodes 0→|+⟩ 1→|−⟩.
3. OPTIONAL Eve: intercept-resend attack on a chosen fraction of the qubits.
   Eve measures each intercepted qubit in her own random basis and resends what
   she found. A noisy channel can also flip bits (the physical error floor).
4. Bob measures every qubit in his own random bases.
5. Sifting: over a public channel Alice and Bob keep only the positions
   where their bases matched (~50%).
6. Error estimation: they publicly compare a random sample of the sifted
   bits and count mismatches → estimated error rate (QBER).
7. If the QBER exceeds the threshold, they ABORT (eavesdropping detected).
8. Error correction (Cascade): they find and fix the remaining errors by
   publicly comparing the parity of blocks, binary-searching mismatches and
   back-tracking into earlier passes. Every
   public parity is information Eve can use, so the leaked bits are counted.
9. Privacy amplification: they hash the corrected key with a random Toeplitz
   matrix down to a shorter key, shrinking whatever Eve may know (from her
   intercepts and from the parities) to practically nothing. The output length
   follows the Shor-Preskill bound ``n·(1 − 2·h2(QBER))`` minus a safety margin.

Expected physics
================
* No Eve, no noise: sifted keys match perfectly (QBER 0).
* Eve intercepting every qubit: she guesses the right basis half the time; when
  wrong she disturbs the state, producing ~25% errors in the sifted key.
* Eve intercepting a fraction f: ≈ 25%·f errors - small f can hide below the
  threshold, but then she also learns only a fraction f of the key, which privacy
  amplification removes.

IMPORTANT DISCLAIMER: this is a classical software simulation for
teaching. It provides NONE of the security of real QKD (which requires
quantum hardware) and is not used by the email flow — the email system's
security comes from post-quantum cryptography (ML-KEM / ML-DSA / AES-GCM).
Real QKD additionally needs authenticated classical channels and a finite-key
security analysis, which are simplified here.
"""
from __future__ import annotations

import math
import random
from dataclasses import dataclass, field

from app import config as cfg

BASIS_PLUS = 0   # rectilinear basis "+"
BASIS_CROSS = 1  # diagonal basis "×"
BASIS_SYMBOLS = {BASIS_PLUS: "+", BASIS_CROSS: "×"}


class QKDParameterError(ValueError):
    """Invalid QKD simulation parameters."""


@dataclass
class BB84Result:
    """Full transcript + statistics of one simulation run."""
    n_bits: int
    eve_present: bool
    noise: float = 0.0
    intercept_fraction: float = 1.0
    alice_bits: list[int] = field(default_factory=list)
    alice_bases: list[int] = field(default_factory=list)
    eve_active: list[bool] = field(default_factory=list)
    eve_bases: list[int] = field(default_factory=list)
    eve_bits: list[int] = field(default_factory=list)
    bob_bases: list[int] = field(default_factory=list)
    bob_results: list[int] = field(default_factory=list)
    sifted_positions: list[int] = field(default_factory=list)
    sifted_alice: list[int] = field(default_factory=list)
    sifted_bob: list[int] = field(default_factory=list)
    sample_positions: list[int] = field(default_factory=list)
    sample_alice: list[int] = field(default_factory=list)
    sample_bob: list[int] = field(default_factory=list)
    sample_errors: int = 0
    qber: float = 0.0
    eve_detected: bool = False
    aborted: bool = False
    key_alice: list[int] = field(default_factory=list)      # remaining bits after the public sample
    key_bob: list[int] = field(default_factory=list)        # Bob's bits before error correction
    keys_match: bool = False                                # after error correction
    # ---- error correction (Cascade-lite) ----
    ec_passes: int = 0
    ec_parities_compared: int = 0
    ec_leaked_bits: int = 0
    ec_errors_before: int = 0
    ec_errors_after: int = 0
    corrected_bob: list[int] = field(default_factory=list)
    # ---- privacy amplification ----
    secret_key: list[int] = field(default_factory=list)
    secret_key_bob: list[int] = field(default_factory=list)
    secret_fraction: float = 0.0
    eve_known_bits: int = 0          # sifted-key bits Eve measured in the right basis (simulation oracle)

    # -- friendly views for the UI -------------------------------------------
    @property
    def sifted_length(self) -> int:
        return len(self.sifted_positions)

    @property
    def final_key_length(self) -> int:
        """Bits left after sampling (before error correction / privacy amplification)."""
        return len(self.key_alice)

    @property
    def secret_key_length(self) -> int:
        return len(self.secret_key)

    @property
    def eve_intercepted(self) -> int:
        return sum(self.eve_active)

    @property
    def key_alice_hex(self) -> str:
        return bits_to_hex(self.key_alice)

    @property
    def key_bob_hex(self) -> str:
        return bits_to_hex(self.key_bob)

    @property
    def corrected_bob_hex(self) -> str:
        return bits_to_hex(self.corrected_bob)

    @property
    def secret_key_hex(self) -> str:
        return bits_to_hex(self.secret_key)

    @property
    def secret_key_bob_hex(self) -> str:
        return bits_to_hex(self.secret_key_bob)

    @property
    def qber_percent(self) -> str:
        return f"{self.qber * 100:.1f}%"

    @property
    def eve_knowledge_percent(self) -> str:
        if not self.sifted_positions:
            return "0.0%"
        return f"{100 * self.eve_known_bits / len(self.sifted_positions):.1f}%"


def validate_parameters(n_bits: int, eve_present: bool, noise: float = 0.0,
                        intercept_fraction: float = 1.0) -> None:
    """Validate user-provided simulation parameters (fail fast, no secrets)."""
    if not isinstance(n_bits, int) or isinstance(n_bits, bool) \
            or not (cfg.BB84_MIN_BITS <= n_bits <= cfg.BB84_MAX_BITS):
        raise QKDParameterError(
            f"Number of qubits must be an integer between "
            f"{cfg.BB84_MIN_BITS} and {cfg.BB84_MAX_BITS}."
        )
    if not isinstance(eve_present, bool):
        raise QKDParameterError("Eve flag must be true or false.")
    if not isinstance(noise, (int, float)) or isinstance(noise, bool) \
            or not (0.0 <= noise <= cfg.BB84_MAX_NOISE):
        raise QKDParameterError(
            f"Channel noise must be between 0% and {cfg.BB84_MAX_NOISE * 100:.0f}%.")
    if not isinstance(intercept_fraction, (int, float)) or isinstance(intercept_fraction, bool) \
            or not (0.0 <= intercept_fraction <= 1.0):
        raise QKDParameterError("Eve's interception rate must be between 0% and 100%.")


def binary_entropy(p: float) -> float:
    """h2(p) = -p·log2(p) - (1-p)·log2(1-p)."""
    if p <= 0.0 or p >= 1.0:
        return 0.0
    return -p * math.log2(p) - (1 - p) * math.log2(1 - p)


def _measure(prepared_basis: int, prepared_bit: int, measuring_basis: int, rng: random.Random,
             noise: float = 0.0) -> int:
    """Simulate a single-qubit measurement in the given basis.

    Matching basis  -> deterministic outcome (the prepared bit).
    Conjugate basis -> uniformly random outcome (Born rule, 50/50).
    ``noise`` is the probability that channel/detector imperfection flips the result.
    """
    bit = prepared_bit if prepared_basis == measuring_basis else rng.randint(0, 1)
    if noise and rng.random() < noise:
        bit ^= 1
    return bit


# ---------------------------------------------------------------------------
# Error correction: Cascade
# ---------------------------------------------------------------------------
VERIFICATION_PARITIES = 20     # random-subset parities compared at the end (each catches a leftover error w.p. 1/2)
MAX_CASCADE_PASSES = 8


def _parity(bits: list[int], indices: list[int]) -> int:
    return sum(bits[i] for i in indices) & 1


def cascade(alice: list[int], bob: list[int], qber_estimate: float,
            rng: random.Random, passes: int = 4) -> tuple[list[int], dict]:
    """Reconcile Bob's key to Alice's using public parity checks (Cascade).

    Pass ``k`` shuffles the positions, splits them into blocks (the first block size
    is about 0.73/QBER and doubles each pass), compares block parities in public and
    binary-searches every block whose parity differs, flipping the wrong bit. Whenever
    a bit is flipped, the blocks of all earlier passes that contain it are re-checked
    ("back-tracking"): they may now have an odd number of errors that earlier passes
    could not see. Finally ``VERIFICATION_PARITIES`` random-subset parities confirm
    that nothing is left; if they disagree, further passes run (up to
    ``MAX_CASCADE_PASSES``).

    Every parity that is announced is information an eavesdropper can use, so the
    count is returned (``stats["parities"]``) and charged by privacy amplification.
    Returns ``(corrected_bob, stats)``; the inputs are not modified.
    """
    n = len(alice)
    corrected = list(bob)
    stats = {"parities": 0, "fixed": 0, "passes": 0, "verified": True}
    if n == 0:
        return corrected, stats
    # ~0.73/QBER from the Cascade paper, but never so large that a short key has fewer than ~8 blocks
    first_block = max(4, min(int(0.73 / max(qber_estimate, 0.01)), n // 8))
    pass_blocks: list[list[list[int]]] = []
    block_of: list[dict[int, int]] = []

    def add_pass(index: int) -> None:
        order = list(range(n))
        if index:
            rng.shuffle(order)
        # Block sizes double over the first passes; extra passes (needed only if the
        # verification fails) cycle through moderate sizes so a fresh shuffle can still
        # separate leftover errors (a block as large as the whole key would be useless).
        size = min(n, first_block * (2 ** (index if index < 4 else index % 3)))
        blocks = [order[i:i + size] for i in range(0, n, size)]
        pass_blocks.append(blocks)
        block_of.append({pos: b for b, block in enumerate(blocks) for pos in block})

    def flip_wrong_bit(indices: list[int]) -> int:
        """Binary search for one wrong bit in a block whose parity is off (leaks one parity per step)."""
        block = indices
        while len(block) > 1:
            half = block[: len(block) // 2]
            stats["parities"] += 1
            block = half if _parity(alice, half) != _parity(corrected, half) else block[len(block) // 2:]
        corrected[block[0]] ^= 1
        stats["fixed"] += 1
        return block[0]

    def process(start_pass: int, start_block: int) -> None:
        work = [(start_pass, start_block)]
        while work:
            p, b = work.pop()
            indices = pass_blocks[p][b]
            stats["parities"] += 1
            if _parity(alice, indices) != _parity(corrected, indices):
                pos = flip_wrong_bit(indices)
                for earlier in range(p):                         # back-tracking
                    work.append((earlier, block_of[earlier][pos]))

    def run_pass(index: int) -> None:
        add_pass(index)
        for b in range(len(pass_blocks[index])):
            process(index, b)
        stats["passes"] += 1

    for index in range(passes):
        run_pass(index)

    def verified() -> bool:
        for _ in range(VERIFICATION_PARITIES):
            subset = [i for i in range(n) if rng.random() < 0.5] or [0]
            stats["parities"] += 1
            if _parity(alice, subset) != _parity(corrected, subset):
                return False
        return True

    while not verified():
        if stats["passes"] >= MAX_CASCADE_PASSES:
            stats["verified"] = False          # could not reconcile: the caller must discard the key
            break
        run_pass(stats["passes"])
    return corrected, stats


cascade_lite = cascade        # backwards-compatible name


# ---------------------------------------------------------------------------
# Privacy amplification: Toeplitz hashing
# ---------------------------------------------------------------------------
def toeplitz_hash(bits: list[int], out_len: int, seed: int) -> list[int]:
    """Multiply the key by a random Toeplitz matrix over GF(2).

    ``seed`` supplies the ``len(bits) + out_len - 1`` public random bits that define
    the matrix. Alice and Bob use the same (public) seed and so get the same output
    when their inputs are equal; an eavesdropper who knows part of the input knows
    almost nothing about the output.
    """
    n = len(bits)
    if out_len <= 0 or n == 0:
        return []
    key_int = 0
    for bit in bits:
        key_int = (key_int << 1) | bit
    mask = (1 << n) - 1
    out = []
    for row in range(out_len):
        # row `row` of the Toeplitz matrix is a sliding n-bit window of the seed
        window = (seed >> row) & mask
        out.append(bin(window & key_int).count("1") & 1)
    return out


def secret_key_length(n_key_bits: int, qber: float) -> tuple[int, float]:
    """Output length and secret fraction from the Shor-Preskill bound."""
    fraction = max(0.0, 1.0 - 2.0 * binary_entropy(qber))
    length = max(0, int(n_key_bits * fraction) - cfg.BB84_SECURITY_MARGIN)
    return length, fraction


def run_bb84(n_bits: int = cfg.BB84_DEFAULT_BITS, eve_present: bool = False,
             rng: random.Random | None = None, noise: float = 0.0,
             intercept_fraction: float = 1.0) -> BB84Result:
    """Run one complete BB84 simulation and return the full transcript."""
    validate_parameters(n_bits, eve_present, noise, intercept_fraction)
    rng = rng or random.SystemRandom()
    result = BB84Result(n_bits=n_bits, eve_present=eve_present, noise=float(noise),
                        intercept_fraction=float(intercept_fraction) if eve_present else 0.0)

    # 1) Alice's random bits and bases
    result.alice_bits = [rng.randint(0, 1) for _ in range(n_bits)]
    result.alice_bases = [rng.randint(0, 1) for _ in range(n_bits)]

    # 3) Eve's intercept-resend on a chosen fraction of qubits (optional)
    channel_basis = list(result.alice_bases)
    channel_bits = list(result.alice_bits)
    if eve_present:
        result.eve_active = [rng.random() < intercept_fraction for _ in range(n_bits)]
        result.eve_bases = [rng.randint(0, 1) for _ in range(n_bits)]
        result.eve_bits = [
            _measure(result.alice_bases[i], result.alice_bits[i], result.eve_bases[i], rng)
            if result.eve_active[i] else result.alice_bits[i]
            for i in range(n_bits)
        ]
        for i in range(n_bits):
            if result.eve_active[i]:
                channel_basis[i] = result.eve_bases[i]
                channel_bits[i] = result.eve_bits[i]
    else:
        result.eve_active = [False] * n_bits

    # 4) Bob's random bases and measurements (with optional channel noise)
    result.bob_bases = [rng.randint(0, 1) for _ in range(n_bits)]
    result.bob_results = [
        _measure(channel_basis[i], channel_bits[i], result.bob_bases[i], rng, noise)
        for i in range(n_bits)
    ]

    # 5) Sifting: keep positions where Alice's and Bob's bases match
    result.sifted_positions = [i for i in range(n_bits)
                               if result.alice_bases[i] == result.bob_bases[i]]
    result.sifted_alice = [result.alice_bits[i] for i in result.sifted_positions]
    result.sifted_bob = [result.bob_results[i] for i in result.sifted_positions]
    # Simulation oracle (not available to the real parties): sifted positions Eve measured
    # in the correct basis, i.e. key bits she knows with certainty.
    result.eve_known_bits = sum(
        1 for i in result.sifted_positions
        if result.eve_active[i] and result.eve_bases[i] == result.alice_bases[i])

    # 6) Error estimation on a random public sample (sacrifice half the key)
    sifted_n = len(result.sifted_positions)
    sample_size = max(1, sifted_n // 2)
    result.sample_positions = sorted(rng.sample(range(sifted_n), sample_size)) if sifted_n else []
    result.sample_alice = [result.sifted_alice[i] for i in result.sample_positions]
    result.sample_bob = [result.sifted_bob[i] for i in result.sample_positions]
    result.sample_errors = sum(1 for a, b in zip(result.sample_alice, result.sample_bob) if a != b)
    result.qber = (result.sample_errors / sample_size) if sample_size else 0.0

    # 7) Eve detection / abort decision
    result.eve_detected = result.qber > cfg.BB84_DETECTION_THRESHOLD
    result.aborted = result.eve_detected
    if result.aborted:
        return result

    # Remaining bits (after the sacrificed sample) form the raw shared key
    sampled = set(result.sample_positions)
    keep = [i for i in range(sifted_n) if i not in sampled]
    result.key_alice = [result.sifted_alice[i] for i in keep]
    result.key_bob = [result.sifted_bob[i] for i in keep]
    result.ec_errors_before = sum(1 for a, b in zip(result.key_alice, result.key_bob) if a != b)

    # 8) Error correction (Cascade)
    result.corrected_bob, stats = cascade(result.key_alice, result.key_bob, result.qber, rng)
    result.ec_passes = stats["passes"]
    result.ec_parities_compared = stats["parities"]
    result.ec_leaked_bits = stats["parities"]            # one public parity bit each
    result.ec_errors_after = sum(1 for a, b in zip(result.key_alice, result.corrected_bob) if a != b)
    result.keys_match = result.key_alice == result.corrected_bob
    if not result.keys_match:
        result.aborted = True                            # reconciliation failed: discard
        return result

    # 9) Privacy amplification: Toeplitz hashing to the length the QBER allows
    out_len, fraction = secret_key_length(len(result.key_alice), result.qber)
    result.secret_fraction = fraction
    if out_len > 0:
        seed = rng.getrandbits(len(result.key_alice) + out_len - 1)
        result.secret_key = toeplitz_hash(result.key_alice, out_len, seed)
        result.secret_key_bob = toeplitz_hash(result.corrected_bob, out_len, seed)
    return result


def bits_to_hex(bits: list[int]) -> str:
    """Pack bits (MSB first) into a hex string for display."""
    if not bits:
        return "—"
    padding = (-len(bits)) % 8
    padded = bits + [0] * padding
    value = 0
    for bit in padded:
        value = (value << 1) | bit
    width = max(1, (len(padded) // 8) * 2)
    return f"{value:0{width}x}"


def transcript_preview(result: BB84Result, limit: int = 32) -> list[dict]:
    """First ``limit`` positions in a UI-friendly table form."""
    rows = []
    sifted_positions = set(result.sifted_positions)
    for i in range(min(limit, result.n_bits)):
        sifted = i in sifted_positions
        row = {
            "position": i,
            "alice_bit": result.alice_bits[i],
            "alice_basis": BASIS_SYMBOLS[result.alice_bases[i]],
            "bob_basis": BASIS_SYMBOLS[result.bob_bases[i]],
            "bob_bit": result.bob_results[i],
            "sifted": sifted,
            "match": result.alice_bits[i] == result.bob_results[i],
        }
        if result.eve_present:
            active = result.eve_active[i]
            row["eve_active"] = active
            row["eve_basis"] = BASIS_SYMBOLS[result.eve_bases[i]] if active else "—"
            row["eve_bit"] = result.eve_bits[i] if active else "—"
        rows.append(row)
    return rows
