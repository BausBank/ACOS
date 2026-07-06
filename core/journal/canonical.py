"""Canonical hashing primitives for the VTR journal (Stage 12).

Everything an *independent* verifier needs to recompute a journal's hashes
byte-for-byte lives here, and ONLY here:

  * ``canonical_bytes`` - a deterministic JSON encoding (sorted keys, no
    whitespace, UTF-8, no NaN/Inf). Two parties that agree on this function
    will hash identical objects to identical digests.
  * ``sha256_hex`` - the chain/commit hash function (SHA-256, stdlib).
  * ``commitment`` - the commit-reveal sealing function: ``H(payload + salt)``
    defined over a canonical ``{"payload": ..., "salt": ...}`` object so the
    byte concatenation is unambiguous across languages.
  * ``merkle_root`` - a batch fingerprint (the Stage-13 anchoring hook: one
    hash that commits to a whole range of entries).

These functions are entity-agnostic: they hash plain JSON values and know
nothing about trades.

Cross-language note (Stage-16 open verifier): a JS/other reimplementation must
match Python's shortest-round-trip float formatting. Journal payloads are
pre-rounded by the producer, which keeps the risk low, but a verifier that
re-hashes from raw floats should canonicalise numbers the same way. Flagged,
not yet hardened (Python verifier is byte-exact today).
"""

from __future__ import annotations

import hashlib
import json
import math
from typing import Any

# A 64-hex-char all-zero string: the chain's "before the first entry" anchor
# and the empty-batch Merkle root.
GENESIS = "0" * 64


def canonical_bytes(obj: Any) -> bytes:
    """Deterministic JSON encoding used for every hash in the journal.

    ``sort_keys`` makes key order irrelevant; the compact separators drop all
    incidental whitespace; ``ensure_ascii=False`` keeps UTF-8 stable; and
    ``allow_nan=False`` rejects NaN/Inf (they have no canonical JSON form and
    would silently break an independent verifier).
    """
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False,
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    """SHA-256 of ``data`` as lower-case hex - the one hash function used
    everywhere in the chain (entry hashes, commitments, Merkle nodes)."""
    return hashlib.sha256(data).hexdigest()


def hash_obj(obj: Any) -> str:
    """SHA-256 over the canonical encoding of a JSON value."""
    return sha256_hex(canonical_bytes(obj))


class NonFiniteValueError(ValueError):
    """A payload carried a NaN / +Inf / -Inf.

    Such a value has no canonical JSON form (``canonical_bytes`` rejects it via
    ``allow_nan=False``) and would silently break an independent verifier. This
    typed error carries the dotted ``path`` to the offending value so a live
    producer can catch it and skip / quarantine just that record - instead of a
    bare ``ValueError`` crashing the run mid-chain with no location.
    """

    def __init__(self, path: str, value: Any) -> None:
        self.path = path
        self.value = value
        super().__init__(f"non-finite value at {path!r}: {value!r}")


def require_finite(obj: Any, _path: str = "") -> None:
    """Recursively assert every float in ``obj`` is finite (no NaN / Inf).

    Walks dicts and lists/tuples; ints, bools, strings and ``None`` are always
    fine. Raises :class:`NonFiniteValueError` (with the key path) on the first
    non-finite float. Call this BEFORE any chain-state mutation so a bad record
    is rejected cleanly rather than half-written.
    """
    if isinstance(obj, bool):
        return  # bool is an int subclass; never a float, always finite
    if isinstance(obj, float):
        if not math.isfinite(obj):
            raise NonFiniteValueError(_path or "<root>", obj)
    elif isinstance(obj, dict):
        for k, v in obj.items():
            # Keys can be non-finite floats too (e.g. {nan: ...}); json.dumps
            # would reject those as a bare ValueError with no location, so flag
            # them here for the typed, path-bearing error instead.
            if isinstance(k, float) and not math.isfinite(k):
                raise NonFiniteValueError(f"{_path}.<key>" if _path else "<key>", k)
            require_finite(v, f"{_path}.{k}" if _path else str(k))
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            require_finite(v, f"{_path}[{i}]")


def commitment(payload: Any, salt: str) -> str:
    """The sealed "envelope": ``SHA-256(canonical({payload, salt}))``.

    Written at commit time *before* the outcome is known. The ``payload`` and
    ``salt`` are NOT stored in the public journal at commit - only this hash is.
    They are disclosed later in the reveal entry, where any verifier recomputes
    this exact value and checks it matches the earlier commit. The random
    ``salt`` makes a low-entropy payload (e.g. "open BTC long") impossible to
    brute-force from the commit hash before reveal.

    Scope note: the hindsight-sensitive fields (side, size, entry/stop/target
    prices) stay sealed until reveal. A caller's ``ref`` may carry low-secrecy
    identifiers (our trade ref is ``dec-<ts>-<symbol>``, so the symbol + decision
    second are visible at commit) - acceptable here because the order itself is
    public on the venue the moment it is placed. Use an opaque ref if pre-reveal
    confidentiality of the *subject* is ever required.
    """
    return hash_obj({"payload": payload, "salt": salt})


def _leaf_hash(h: str) -> str:
    """RFC-6962 leaf hash: ``H(0x00 || leaf)`` (the ``0x00`` tag keeps a leaf
    distinguishable from an internal node)."""
    return sha256_hex(b"\x00" + bytes.fromhex(h))


def _node_hash(left: str, right: str) -> str:
    """RFC-6962 internal-node hash: ``H(0x01 || left || right)``."""
    return sha256_hex(b"\x01" + bytes.fromhex(left) + bytes.fromhex(right))


def merkle_root(leaf_hashes: list[str]) -> str:
    """Single fingerprint committing to an ordered list of entry hashes.

    Used by Stage 13 to anchor a whole batch on-chain with ONE write (and to
    support per-entry inclusion proofs). RFC-6962-style **domain separation**:
    a leaf is hashed with a ``0x00`` prefix and an internal node with ``0x01``,
    so a leaf can never be confused with a pre-combined internal node. Without
    this, ``merkle_root([a, b, c]) == merkle_root([H(a|b), c])`` - different
    leaf sets collide to the same root and inclusion proofs are ambiguous (an
    in-scope defect caught by the Stage-12 adversarial audit). An odd node at a
    level is promoted unchanged to the next level.

      * empty   -> GENESIS (all-zero)
      * 1 leaf  -> ``H(0x00 || leaf)``
      * N leaves-> root of the domain-separated tree
    """
    if not leaf_hashes:
        return GENESIS
    # Tag every leaf so it is distinguishable from an internal node.
    level = [_leaf_hash(h) for h in leaf_hashes]
    while len(level) > 1:
        nxt: list[str] = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                nxt.append(_node_hash(level[i], level[i + 1]))
            else:
                nxt.append(level[i])  # promote the unpaired tail node
        level = nxt
    return level[0]


def merkle_proof(leaf_hashes: list[str], index: int) -> list[tuple[str, str]]:
    """Inclusion proof for ``leaf_hashes[index]``: the ordered sibling path from
    the leaf up to the root. Each step is ``(side, sibling_node_hash)`` where
    ``side`` is ``"L"`` if the sibling sits on the left, ``"R"`` if on the right.

    The proof lets a verifier confirm one entry belongs to an anchored batch
    WITHOUT being shown the whole batch (Stage-16 / site "decision feed"). It
    uses the exact same domain-separated construction as :func:`merkle_root`, so
    a promoted unpaired tail node contributes no proof step at that level.
    """
    if not leaf_hashes:
        raise ValueError("empty leaf set has no inclusion proof")
    if not 0 <= index < len(leaf_hashes):
        raise ValueError(f"index {index} out of range for {len(leaf_hashes)} leaves")
    level = [_leaf_hash(h) for h in leaf_hashes]
    idx = index
    proof: list[tuple[str, str]] = []
    while len(level) > 1:
        nxt: list[str] = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                if i == idx:
                    proof.append(("R", level[i + 1]))   # sibling is on the right
                elif i + 1 == idx:
                    proof.append(("L", level[i]))        # sibling is on the left
                nxt.append(_node_hash(level[i], level[i + 1]))
            else:
                nxt.append(level[i])  # promoted tail: no sibling, no proof step
        idx //= 2
        level = nxt
    return proof


def verify_merkle_proof(leaf_hash: str, proof: list[tuple[str, str]], root: str) -> bool:
    """Recompute a root from a leaf + its :func:`merkle_proof` and check it
    matches ``root``. Mirrors the leaf/node domain separation exactly."""
    node = _leaf_hash(leaf_hash)
    for side, sibling in proof:
        if side == "L":
            node = _node_hash(sibling, node)
        elif side == "R":
            node = _node_hash(node, sibling)
        else:
            raise ValueError(f"bad proof side {side!r} (expected 'L' or 'R')")
    return node == root


__all__ = [
    "GENESIS",
    "canonical_bytes",
    "sha256_hex",
    "hash_obj",
    "require_finite",
    "NonFiniteValueError",
    "commitment",
    "merkle_root",
    "merkle_proof",
    "verify_merkle_proof",
]
