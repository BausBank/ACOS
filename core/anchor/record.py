"""Anchor record - the single 32-byte fingerprint published on-chain (Stage 13).

Stage 12 left an *offline ceiling*: anyone holding the whole journal can
re-chain it from genesis (mint a fresh journal, or truncate a loss off the
tail) and the integrity verifier still PASSes. Anchoring closes that gap by
publishing ONE fingerprint of the chain to a public ledger at a real block
timestamp - a re-mint cannot reproduce a value that is already recorded in a
past block. That published fingerprint is the :class:`AnchorRecord`.

What the fingerprint binds (all three, in one hash):

  * ``journal_head`` - the chain tip after ``end_seq``. Because every entry
    carries ``prev_hash``, this single hash commits to the ENTIRE prefix
    ``[1 .. end_seq]``; binding it defeats both a full re-mint and a
    tail-truncation (drop the losing trades and the head changes).
  * ``batch_root`` - the RFC-6962 Merkle root over the batch's entry hashes.
    Lets a verifier prove ONE entry belongs to the anchored batch without being
    shown the whole batch (per-entry inclusion proof; Stage-16 / site feed).
  * ``prev_anchor`` - the previous anchor's hash, so the anchors themselves form
    a chain (you cannot quietly drop or reorder a published anchor).

The record is entity-agnostic: it consumes plain journal entry dicts and knows
nothing about trades. Computing it is pure and offline; *publishing* the digest
to Arc / Bitcoin is :mod:`core.anchor.backends`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from core.journal.canonical import GENESIS, canonical_bytes, sha256_hex

ANCHOR_SCHEMA = 1

# A 4-byte magic + 1 version byte that tags our anchor calldata so a third party
# can recognise (and skip non-anchor) transactions and recover the digest from a
# fixed offset. "ACAP" = AnchorCapitalArc; the version byte versions the calldata
# LAYOUT (independent of AnchorRecord.anchor_schema, which versions the payload).
ANCHOR_MAGIC = b"ACAP"
CALLDATA_VERSION = 1


def anchor_calldata(digest_hex: str) -> bytes:
    """Tagged EVM calldata carrying a 32-byte anchor digest:
    ``magic(4) || version(1) || digest(32)`` = 37 bytes."""
    digest = bytes.fromhex(digest_hex)
    if len(digest) != 32:
        raise ValueError(f"anchor digest must be 32 bytes, got {len(digest)}")
    return ANCHOR_MAGIC + bytes([CALLDATA_VERSION]) + digest


def parse_anchor_calldata(data: bytes) -> str | None:
    """Recover the digest (hex) from tagged calldata, or ``None`` if ``data`` is
    not one of our anchor transactions (wrong magic / length)."""
    if len(data) != len(ANCHOR_MAGIC) + 1 + 32:
        return None
    if data[: len(ANCHOR_MAGIC)] != ANCHOR_MAGIC:
        return None
    return data[len(ANCHOR_MAGIC) + 1:].hex()


@dataclass(frozen=True)
class AnchorRecord:
    """One anchored batch: a fingerprint of journal entries ``[start_seq, end_seq]``.

    ``anchor_hash`` is the 32-byte value written on-chain. It is the SHA-256 of
    the canonical encoding of :attr:`payload`, so any independent verifier that
    reuses :mod:`core.journal.canonical` reproduces it byte-for-byte.
    """

    start_seq: int
    end_seq: int
    n_entries: int
    journal_head: str          # chain tip after end_seq (commits to prefix 1..end_seq)
    batch_root: str            # RFC-6962 Merkle root over entry hashes [start..end]
    prev_anchor: str = GENESIS  # previous anchor_hash (anchors form their own chain)
    anchor_schema: int = ANCHOR_SCHEMA

    @property
    def payload(self) -> dict[str, Any]:
        """The canonical object that is hashed to ``anchor_hash``. Key order is
        irrelevant (canonical encoding sorts keys); listed logically here."""
        return {
            "anchor_schema": self.anchor_schema,
            "start_seq": self.start_seq,
            "end_seq": self.end_seq,
            "n_entries": self.n_entries,
            "journal_head": self.journal_head,
            "batch_root": self.batch_root,
            "prev_anchor": self.prev_anchor,
        }

    @property
    def anchor_hash(self) -> str:
        """The 32-byte fingerprint (lower-case hex) published on-chain."""
        return sha256_hex(canonical_bytes(self.payload))

    @property
    def digest_bytes(self) -> bytes:
        """The fingerprint as raw bytes (what goes into tx calldata / OTS)."""
        return bytes.fromhex(self.anchor_hash)

    def calldata(self) -> bytes:
        """Tagged calldata for an EVM anchor tx (see :func:`anchor_calldata`)."""
        return anchor_calldata(self.anchor_hash)

    def to_event_body(self) -> dict[str, Any]:
        """The body recorded back into the journal as an ``anchor`` event, so the
        journal is self-describing about what was anchored (receipts are merged
        in by the anchorer)."""
        return {
            "anchor_hash": self.anchor_hash,
            **self.payload,
        }


def build_anchor(
    entries: list[dict[str, Any]],
    *,
    start_seq: int = 1,
    end_seq: int | None = None,
    prev_anchor: str = GENESIS,
) -> AnchorRecord:
    """Compute the :class:`AnchorRecord` over journal entries ``[start_seq, end_seq]``
    (both inclusive; ``end_seq=None`` = up to the last entry).

    Expects an *internally sound* journal (run :func:`core.journal.verify_journal`
    first). Asserts the range is contiguous, since a gap means a missing entry -
    a tampering signal the integrity verifier owns, not something to anchor over.
    """
    # Import here to avoid a heavy import at module load; merkle is cheap.
    from core.journal.canonical import merkle_root

    by_seq = {int(e["seq"]): e for e in entries}
    if not by_seq:
        raise ValueError("cannot anchor an empty journal")
    end = max(by_seq) if end_seq is None else int(end_seq)
    if start_seq < 1 or end < start_seq:
        raise ValueError(f"invalid anchor range [{start_seq}, {end}]")

    in_range = []
    for s in range(start_seq, end + 1):
        if s not in by_seq:
            raise ValueError(
                f"gap at seq {s} in anchor range [{start_seq}, {end}] - "
                "verify the journal's integrity before anchoring"
            )
        in_range.append(by_seq[s])

    head_entry = by_seq[end]
    leaves = [e["hash"] for e in in_range]  # already in seq order
    return AnchorRecord(
        start_seq=start_seq,
        end_seq=end,
        n_entries=len(in_range),
        journal_head=head_entry["hash"],
        batch_root=merkle_root(leaves),
        prev_anchor=prev_anchor,
    )


__all__ = [
    "AnchorRecord",
    "ANCHOR_SCHEMA",
    "ANCHOR_MAGIC",
    "CALLDATA_VERSION",
    "anchor_calldata",
    "parse_anchor_calldata",
    "build_anchor",
]
