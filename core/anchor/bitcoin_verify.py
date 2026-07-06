"""Pure-Python OpenTimestamps upgrade + Bitcoin verification (Stage 13).

The reference ``ots`` CLI depends on ``python-bitcoinlib``'s ctypes OpenSSL bind,
which fails to load on some platforms (e.g. this Windows box). To keep the OTS
rail self-contained and portable - so "don't trust, verify" actually works
without that fragile toolchain - this module reimplements the two network steps
using only ``opentimestamps`` core (urllib-based) + a public block explorer:

  * :func:`upgrade_via_calendar` - the ``ots upgrade`` step: for each pending
    calendar attestation, fetch the completed timestamp from that calendar and
    merge it into the ``.ots`` (this is what pulls in the Bitcoin attestation
    once the calendar's aggregation has been mined).
  * :func:`explorer_bitcoin_verify` - the ``ots verify`` step: for each Bitcoin
    attestation, fetch the REAL block header's merkle root from public explorers
    and confirm the OTS-committed value equals it. A self-fabricated attestation
    cannot match a real, already-mined block's merkle root (the committed value
    is forced by the op-chain from SHA256(digest), a PoW-hard target), so an
    OFFLINE forger cannot produce a confirmation.

Trust boundary (honest): without a local Bitcoin node, validating a merkle root
means trusting a block explorer. A single explorer that is COMPROMISED or
MITM'd could serve an attacker-chosen merkle root and forge a confirmation. To
bound that, :func:`_fetch_block_header` queries SEVERAL independent explorers and
requires them to AGREE (a single honest responder then suffices; any disagreement
is refused). Full trustlessness needs a Bitcoin node and is out of scope here.

Both network hooks are injectable so the whole path is testable offline.
"""

from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable

# Reputable, independently-operated public Bitcoin block explorers (Esplora API
# shape). We require AGREEMENT across responders, so forging a confirmation needs
# compromising every responding explorer at once, not just the first.
DEFAULT_EXPLORERS = (
    "https://blockstream.info/api",
    "https://mempool.space/api",
)


@dataclass(frozen=True)
class _BlockHeader:
    """Just what BitcoinBlockHeaderAttestation.verify_against_blockheader needs."""

    hashMerkleRoot: bytes  # internal (little-endian) byte order
    nTime: int


def _fetch_one(base: str, height: int, timeout: float) -> tuple[bytes, int] | None:
    """Fetch ``(merkle_root_internal_bytes, nTime)`` for ``height`` from one
    explorer, or ``None``. Explorers report the merkle root in display
    (big-endian) hex; OTS commits internal (little-endian), so we reverse."""
    try:
        req = urllib.request.Request(f"{base}/block-height/{height}",
                                     headers={"User-Agent": "capitalarc-anchor"})
        block_hash = urllib.request.urlopen(req, timeout=timeout).read().decode().strip()
        req2 = urllib.request.Request(f"{base}/block/{block_hash}",
                                      headers={"User-Agent": "capitalarc-anchor"})
        blk = json.loads(urllib.request.urlopen(req2, timeout=timeout).read().decode())
        merkle_internal = bytes.fromhex(blk["merkle_root"])[::-1]
        ntime = int(blk["time"] if "time" in blk else blk["timestamp"])
        return merkle_internal, ntime
    except Exception:
        return None


def _fetch_block_header(
    height: int,
    explorers: tuple[str, ...],
    timeout: float,
    *,
    fetch_one: Callable[[str, int, float], tuple[bytes, int] | None] | None = None,
) -> _BlockHeader | None:
    """Fetch block ``height``'s header by polling ALL explorers and requiring the
    responders to AGREE on the merkle root. Returns ``None`` if none respond OR
    if responders disagree (a disagreement signals a compromised/MITM explorer
    and is refused rather than guessed). ``fetch_one`` is injectable for tests."""
    fetch = fetch_one or _fetch_one
    results = [r for base in explorers if (r := fetch(base, height, timeout)) is not None]
    if not results:
        return None
    roots = {mr for mr, _t in results}
    if len(roots) > 1:
        return None  # explorers disagree -> refuse (do not trust the first one)
    mr, ntime = results[0]
    return _BlockHeader(hashMerkleRoot=mr, nTime=ntime)


def _load_detached(ots_path: str) -> Any:
    from opentimestamps.core.serialize import StreamDeserializationContext
    from opentimestamps.core.timestamp import DetachedTimestampFile

    with open(ots_path, "rb") as fh:
        return DetachedTimestampFile.deserialize(StreamDeserializationContext(fh))


def _pending_nodes(timestamp: Any):
    """Yield ``(node, calendar_uri)`` for every pending calendar attestation in
    the timestamp tree (the node's ``msg`` is the commitment to query)."""
    from opentimestamps.core.notary import PendingAttestation

    for att in timestamp.attestations:
        if isinstance(att, PendingAttestation):
            yield timestamp, str(att.uri)
    for _op, child in timestamp.ops.items():
        yield from _pending_nodes(child)


def upgrade_via_calendar(
    ots_path: str,
    *,
    get_timestamp_fn: Callable[[bytes, str], Any] | None = None,
    timeout: float = 20.0,
) -> bool:
    """Pure-Python ``ots upgrade``: pull the completed (Bitcoin-bearing) timestamp
    from each pending calendar and merge it into the ``.ots`` in place. Returns
    True if anything was merged. ``get_timestamp_fn(commitment, uri)`` is
    injectable for tests."""
    from opentimestamps.core.serialize import StreamSerializationContext

    detached = _load_detached(ots_path)

    def _default_get(commitment: bytes, uri: str) -> Any:
        from opentimestamps.calendar import RemoteCalendar

        return RemoteCalendar(uri).get_timestamp(commitment, timeout=timeout)

    get = get_timestamp_fn or _default_get
    changed = False
    for node, uri in list(_pending_nodes(detached.timestamp)):
        try:
            upgraded = get(node.msg, uri)
            node.merge(upgraded)
            changed = True
        except Exception:
            continue
    if changed:
        with open(ots_path, "wb") as fh:
            detached.serialize(StreamSerializationContext(fh))
    return changed


def explorer_bitcoin_verify(
    ots_path: str,
    digest_hex: str,
    *,
    explorers: tuple[str, ...] = DEFAULT_EXPLORERS,
    fetch_header: Callable[[int], _BlockHeader | None] | None = None,
    timeout: float = 20.0,
) -> list[int]:
    """Authoritatively validate the ``.ots``'s Bitcoin attestation(s) against real
    block headers. Returns the validated block height(s) (empty if none verify).

    For each Bitcoin attestation we fetch the real block header at its height and
    require the OTS-committed value to equal the block's merkle root. A forged
    attestation cannot match a real block, so it is rejected. ``fetch_header`` is
    injectable for tests.

    Self-sufficient: we also bind the proof to ``digest_hex`` here (the ``.ots``
    root must commit to ``SHA256(digest)``), so this function is safe to call
    standalone and does not rely on the caller having checked the root.
    """
    import hashlib

    from opentimestamps.core.notary import BitcoinBlockHeaderAttestation

    detached = _load_detached(ots_path)
    # Bind the proof to the claimed digest: the .ots root commits to SHA256(file)
    # where file == the 32-byte digest. A proof for a DIFFERENT (even genuinely
    # anchored) digest must not validate this digest.
    if detached.timestamp.msg != hashlib.sha256(bytes.fromhex(digest_hex)).digest():
        return []
    fetch = fetch_header or (lambda h: _fetch_block_header(h, explorers, timeout))
    validated: list[int] = []
    for msg, att in detached.timestamp.all_attestations():
        if isinstance(att, BitcoinBlockHeaderAttestation):
            header = fetch(int(att.height))
            if header is None:
                continue
            try:
                att.verify_against_blockheader(msg, header)
                validated.append(int(att.height))
            except Exception:
                continue
    return validated


__all__ = [
    "DEFAULT_EXPLORERS",
    "upgrade_via_calendar",
    "explorer_bitcoin_verify",
]
