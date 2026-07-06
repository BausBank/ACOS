"""On-chain anchor-history enumeration - closes Stage-13's residual boundary (Stage 16).

:func:`core.anchor.verify.verify_anchors` checks a (journal, manifest) PAIR: it
recomputes each anchor from the journal and confirms each manifest tx is on-chain.
But it trusts the manifest to be the COMPLETE set of anchors. The residual gap
the Stage-13 code documented: an actor who holds the anchor key can re-mint the
whole journal, recompute a fully-consistent manifest, and broadcast FRESH anchor
txs for the new digests - presenting only the new manifest. Because anchors are
append-only on-chain at real block times, the ORIGINAL anchors still exist on the
chain, timestamped earlier. The only way to catch this is to enumerate EVERY
anchor tx ever sent FROM the anchor address and confirm the presented manifest
omits none (and that on-chain block times are monotonic with the manifest order).

This module does exactly that:

  * :class:`AnchorTxProvider` - a source of "all anchor txs from this address"
    (injectable, so the logic is fully testable offline).
  * :class:`BlockscoutProvider` - a Blockscout/Etherscan-style explorer adapter
    (``?module=account&action=txlist&address=...``); it keeps only txs whose
    calldata parses as our tagged anchor calldata and recovers the digest.
  * :func:`verify_anchor_history` - pure comparison of the on-chain anchor set vs
    the manifest: flags any on-chain anchor the manifest omits (the re-mint
    catch), any manifest anchor missing on-chain, and any block-time order that
    disagrees with the manifest's anchor order.

Best-effort by design (operator decision, Stage 16): a testnet explorer is an
unstable external dependency, so when enumeration is unavailable the report says
so and does NOT fail the overall verdict - the other checks still stand. A
*successful* enumeration that finds an omitted anchor IS a hard failure.
"""

from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Protocol, Sequence

from core.anchor.record import parse_anchor_calldata


@dataclass
class OnchainAnchorTx:
    """One anchor transaction discovered on-chain (calldata carries our digest)."""

    tx_hash: str
    from_addr: str
    digest_hex: str          # recovered from the tagged calldata
    block: int | None = None
    block_time: str | None = None   # ISO-8601 UTC

    def to_dict(self) -> dict[str, Any]:
        return {
            "tx_hash": self.tx_hash, "from": self.from_addr,
            "digest_hex": self.digest_hex, "block": self.block,
            "block_time": self.block_time,
        }


class AnchorTxProvider(Protocol):
    """Yields every anchor tx sent from ``address`` (newest or oldest order ok)."""

    def list_anchor_txs(self, address: str) -> list[OnchainAnchorTx]: ...


def _iso(ts_unix: int | float) -> str:
    return datetime.fromtimestamp(int(ts_unix), tz=timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def _calldata_bytes(raw: Any) -> bytes:
    """Normalise an explorer's ``input`` field (0x-hex str or bytes) to bytes."""
    if isinstance(raw, (bytes, bytearray)):
        return bytes(raw)
    s = str(raw or "")
    s = s[2:] if s.startswith("0x") else s
    if not s:
        return b""
    try:
        return bytes.fromhex(s)
    except ValueError:
        return b""


class BlockscoutProvider:
    """Enumerate anchor txs via a Blockscout/Etherscan-style ``txlist`` endpoint.

    Parameters
    ----------
    base_url
        Explorer API base, e.g. ``https://explorer.testnet.arc.network/api``.
    fetch_fn
        Injectable ``(url) -> dict`` returning the parsed JSON (tests pass a
        fake). Defaults to a real ``urllib`` GET.
    timeout
        HTTP timeout for the default fetcher.
    """

    def __init__(
        self,
        base_url: str,
        *,
        fetch_fn: Callable[[str], dict[str, Any]] | None = None,
        timeout: float = 20.0,
        page_size: int = 10_000,
        max_pages: int = 100,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._fetch_fn = fetch_fn
        self.timeout = timeout
        self.page_size = page_size
        self.max_pages = max_pages

    def _fetch(self, url: str) -> dict[str, Any]:
        if self._fetch_fn is not None:
            return self._fetch_fn(url)
        req = urllib.request.Request(url, headers={"User-Agent": "capitalarc-verify"})
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310
            return json.loads(resp.read().decode("utf-8"))

    def list_anchor_txs(self, address: str) -> list[OnchainAnchorTx]:
        """Enumerate EVERY anchor tx from ``address``, paging to exhaustion.

        Etherscan/Blockscout cap a page at ``offset`` rows and require
        ``page=/offset=`` to walk the rest. Reading only page 1 would let an
        adversary bury the original anchor behind a wall of cheap self-txs and
        evade the re-mint catch - so we page until a short page proves the list is
        drained. If the page guard is hit BEFORE draining, we raise rather than
        return a partial set (an incomplete enumeration must become a SKIP
        upstream, never a false PASS)."""
        out: list[OnchainAnchorTx] = []
        for page in range(1, self.max_pages + 1):
            url = (f"{self.base_url}?module=account&action=txlist&address={address}"
                   f"&sort=asc&page={page}&offset={self.page_size}")
            data = self._fetch(url)
            rows = data.get("result") or []
            if not isinstance(rows, list):
                # Etherscan returns "No transactions found" (status 0) as a string
                # result; treat a non-list as "no more rows", not a parse error.
                break
            for r in rows:
                digest = parse_anchor_calldata(_calldata_bytes(r.get("input")))
                if digest is None:
                    continue  # not one of our anchor txs
                # Only successful txs count (a reverted tx still carries calldata).
                if str(r.get("isError", "0")) == "1":
                    continue
                ts = r.get("timeStamp")
                out.append(OnchainAnchorTx(
                    tx_hash=str(r.get("hash", "")),
                    from_addr=str(r.get("from", "")),
                    digest_hex=digest,
                    block=int(r["blockNumber"]) if r.get("blockNumber") else None,
                    block_time=_iso(ts) if ts else None,
                ))
            if len(rows) < self.page_size:
                break  # short page -> the address history is fully drained
        else:
            raise RuntimeError(
                f"txlist exceeded {self.max_pages} pages of {self.page_size} for "
                f"{address} without draining - enumeration incomplete (refusing to "
                "return a partial anchor history that could hide a re-mint)"
            )
        return out


@dataclass
class AnchorHistoryReport:
    ok: bool = True
    enumerated: bool = False        # did we actually get on-chain data?
    pinned: bool = False            # was an anchor identity supplied?
    n_onchain: int = 0              # anchor txs found from the address
    n_manifest: int = 0
    omitted_onchain: list[str] = field(default_factory=list)   # on-chain, not in manifest
    missing_onchain: list[str] = field(default_factory=list)   # manifest, not on-chain
    missing_broadcast: list[str] = field(default_factory=list)  # broadcast records absent on-chain
    other_identities: list[str] = field(default_factory=list)   # anchors from other addresses
    monotonic_ok: bool = True
    issues: list[str] = field(default_factory=list)
    note: str = ""

    # The guarantee's honest scope (surfaced so a PASS is never over-read).
    SCOPE = ("scope: external txs from the pinned address only; anchors delivered "
             "by a contract/internal tx, or re-anchored from a DIFFERENT key, are "
             "outside this enumeration")

    def summary(self) -> str:
        if not self.enumerated:
            return ("  ANCHOR HISTORY (on-chain enumeration) : SKIPPED\n"
                    f"    {self.note or 'not enumerated (explorer unavailable / best-effort)'}")
        verdict = "PASS" if self.ok else "FAIL"
        lines = [
            f"  ANCHOR HISTORY (on-chain enumeration) : {verdict}",
            f"  on-chain anchors from address={self.n_onchain}  manifest={self.n_manifest}  "
            f"block-time order={'ok' if self.monotonic_ok else 'BROKEN'}"
            f"{'' if self.pinned else '  [ADDRESS UNPINNED - advisory only]'}",
            f"  {self.SCOPE}",
        ]
        if self.omitted_onchain:
            lines.append(f"  OMITTED from manifest ({len(self.omitted_onchain)}): "
                         + ", ".join(d[:16] + '...' for d in self.omitted_onchain[:5]))
        if self.missing_broadcast:
            lines.append(f"  broadcast anchors NOT on-chain ({len(self.missing_broadcast)})")
        if self.other_identities:
            lines.append(f"  manifest anchors from OTHER addresses ({len(self.other_identities)}) "
                         "- not covered by this enumeration")
        if self.issues:
            lines.extend(f"    - {m}" for m in self.issues[:10])
        return "\n".join(lines)


def verify_anchor_history(
    manifest_records: Sequence[dict[str, Any]],
    onchain_txs: Sequence[OnchainAnchorTx] | None,
    *,
    expected_address: str | None = None,
    require_manifest_onchain: bool = False,
) -> AnchorHistoryReport:
    """Compare the on-chain anchor set (from the anchor address) to the manifest.

    ``onchain_txs=None`` means enumeration was not available -> SKIPPED, not FAIL
    (best-effort). When present:

      * any on-chain anchor digest (from the PINNED address) the manifest OMITS
        -> FAIL (a re-mint published anchors it did not disclose). When the
        address is NOT pinned this is downgraded to ADVISORY (the digest is
        public; a stranger could repost it from their own address);
      * each manifest record's own ``dry_run`` flag decides whether it must be
        on-chain: a record marked broadcast (``dry_run=False``) MUST be findable
        from the address -> missing = FAIL (this also catches a fabricated,
        conveniently-off-chain entry and an empty enumeration against a broadcast
        manifest); a ``dry_run=True`` record is legitimately off-chain;
      * manifest receipts that name a DIFFERENT publishing address are flagged -
        an anchor re-published from another key the actor controls is outside a
        single-address enumeration's reach (an honest-boundary caveat, surfaced);
      * block-time order of the paired anchors must agree with the manifest order
        (anchor_no) -> a backdate/reorder breaks it; a paired anchor with no block
        time is flagged (its order can't be confirmed), never silently dropped.
    """
    rep = AnchorHistoryReport(n_manifest=len(manifest_records))
    if onchain_txs is None:
        rep.enumerated = False
        rep.note = "on-chain enumeration unavailable (explorer not reachable)"
        return rep

    rep.enumerated = True
    rep.pinned = bool(expected_address)
    # Restrict to txs actually sent BY the anchor identity (the digest is public;
    # anyone could post it - only the anchor key's own txs count as its history).
    if expected_address:
        addr = expected_address.lower()
        txs = [t for t in onchain_txs if (t.from_addr or "").lower() == addr]
    else:
        txs = list(onchain_txs)
        rep.issues.append("anchor address not pinned - cannot attribute on-chain "
                          "anchors to the anchor key; omitted-anchor detection is "
                          "ADVISORY (a stranger can repost a public digest)")
    rep.n_onchain = len(txs)

    manifest_digests = {str(r.get("anchor_hash")) for r in manifest_records}
    # Records the manifest itself marks as BROADCAST must be on-chain; dry-run
    # records legitimately are not (use the flag that is already in each record).
    broadcast_digests = {
        str(r.get("anchor_hash")) for r in manifest_records if not r.get("dry_run", False)
    }
    # anchor_no order from the manifest, for the monotonicity reference.
    manifest_order = {
        str(r.get("anchor_hash")): int(r.get("anchor_no", i + 1))
        for i, r in enumerate(manifest_records)
    }
    onchain_digests = {t.digest_hex for t in txs}

    # 1. on-chain anchors the manifest omits = the re-mint catch (hard when pinned).
    rep.omitted_onchain = sorted(onchain_digests - manifest_digests)
    for d in rep.omitted_onchain:
        sev = "" if rep.pinned else " [advisory: address unpinned]"
        rep.issues.append(
            f"on-chain anchor {d[:16]}... from the address is NOT in the manifest "
            f"(undisclosed anchor - possible re-mint / hidden segment){sev}"
        )

    # 2. manifest anchors not on-chain; broadcast ones are a hard failure.
    rep.missing_onchain = sorted(manifest_digests - onchain_digests)
    rep.missing_broadcast = sorted(broadcast_digests - onchain_digests)
    for d in rep.missing_broadcast:
        rep.issues.append(
            f"manifest anchor {d[:16]}... is marked broadcast (dry_run=false) but is "
            "NOT on-chain from the address (fabricated or unbroadcast)"
        )
    if require_manifest_onchain:
        for d in sorted(set(rep.missing_onchain) - set(rep.missing_broadcast)):
            rep.issues.append(f"manifest anchor {d[:16]}... not found on-chain")

    # 3. identity cross-reference: an anchor receipt published from a DIFFERENT
    # address than the one we enumerated is out of this enumeration's scope.
    if expected_address:
        addr = expected_address.lower()
        others: set[str] = set()
        for r in manifest_records:
            for rc in (r.get("receipts") or []):   # tolerate receipts: null
                if rc.get("status") in (None, "dry-run"):
                    continue
                frm = (rc.get("detail") or {}).get("from")
                if frm and frm.lower() != addr:
                    others.add(frm.lower())
        rep.other_identities = sorted(others)
        for f in rep.other_identities:
            rep.issues.append(
                f"manifest anchor published from {f} (not the enumerated address) - "
                "re-anchor from another key is outside single-address enumeration"
            )

    # 4. block-time monotonic with manifest order (anchors present in both). A
    # paired anchor with no block time is flagged, not silently skipped.
    paired = [t for t in txs if t.digest_hex in manifest_order]
    for t in paired:
        if not t.block_time:
            rep.issues.append(
                f"anchor {t.digest_hex[:16]}... has no block time - its order cannot "
                "be confirmed"
            )
    paired_bt = sorted((t for t in paired if t.block_time),
                       key=lambda t: manifest_order[t.digest_hex])
    last_bt: str | None = None
    for t in paired_bt:
        if last_bt is not None and t.block_time < last_bt:
            rep.monotonic_ok = False
            rep.issues.append(
                f"anchor {t.digest_hex[:16]}... block-time {t.block_time} precedes "
                f"an earlier-numbered anchor ({last_bt}) - reorder/backdate"
            )
        last_bt = t.block_time

    omitted_fatal = bool(rep.omitted_onchain) and rep.pinned
    missing_fatal = bool(rep.missing_broadcast) or (
        require_manifest_onchain and bool(rep.missing_onchain)
    )
    rep.ok = (not omitted_fatal) and rep.monotonic_ok and (not missing_fatal)
    return rep


__all__ = ["OnchainAnchorTx", "AnchorTxProvider", "BlockscoutProvider",
           "AnchorHistoryReport", "verify_anchor_history"]
