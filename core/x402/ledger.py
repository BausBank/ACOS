"""Append-only JSONL receipt ledger for the Trust Toll cashier (Stage 17).

Every cashier interaction - a 402 challenge, a failed settlement, a paid
verification - is recorded as one JSON line. This is the "persistence" leg of
the wider Stage-17 build: a durable, auditable record of who paid, how much, the
Gateway settlement tx, the verdict and its digest. It doubles as the raw
material for a future earnings dashboard (RFB 5 / traction metrics) and can
itself be journaled / anchored later.

Entity-agnostic: stores plain dicts, knows nothing about *what* was verified.
"""

from __future__ import annotations

import json
import os
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class TollReceipt:
    """One cashier event. ``paid`` distinguishes a real settlement from a 402."""

    ts: str
    request_id: str
    paid: bool
    stage: str = ""                      # 402_issued | settle_failed | paid | verify_error
    payer: str | None = None
    amount_atomic: str | None = None
    asset: str | None = None
    network: str | None = None
    settle_tx: str | None = None         # Gateway transfer UUID on success
    settle_error: str | None = None      # Gateway errorReason on failure
    verdict_ok: bool | None = None       # open_verify PASS/FAIL (None if not run)
    verdict_digest: str | None = None    # sha256 of the verdict, for anchoring
    track_ref: str | None = None         # "request-body" | "default:<file>"
    anchor_ref: str | None = None        # our independent verdict anchor (if any)
    extra: dict[str, Any] = field(default_factory=dict)


class TollLedger:
    """Append-only JSONL ledger. Thread-safe append (single-process)."""

    def __init__(self, path: str) -> None:
        self.path = str(path)
        parent = os.path.dirname(self.path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        self._lock = threading.Lock()

    def record(self, receipt: "TollReceipt | dict[str, Any]") -> None:
        obj = asdict(receipt) if isinstance(receipt, TollReceipt) else dict(receipt)
        line = json.dumps(obj, separators=(",", ":"), ensure_ascii=False)
        with self._lock:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
                fh.flush()

    def load(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        if not os.path.exists(self.path):
            return out
        with open(self.path, encoding="utf-8") as fh:
            for ln in fh:
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    out.append(json.loads(ln))
                except json.JSONDecodeError:
                    continue  # tolerate a torn tail line
        return out

    def stats(self) -> dict[str, Any]:
        """Quick traction summary: counts + total settled USDC atomic units."""
        rows = self.load()
        paid = [r for r in rows if r.get("paid")]
        total_atomic = sum(int(r.get("amount_atomic") or 0) for r in paid)
        payers = {r.get("payer") for r in paid if r.get("payer")}
        return {
            "events": len(rows),
            "paid": len(paid),
            "unique_payers": len(payers),
            "total_atomic": total_atomic,
        }

    def verdict_digests(self) -> list[str]:
        """Ordered list of recorded verdict digests (64-hex, no 0x prefix)."""
        out: list[str] = []
        for r in self.load():
            d = r.get("verdict_digest")
            if d:
                out.append(str(d)[2:] if str(d).startswith("0x") else str(d))
        return out

    def merkle_root(self) -> str | None:
        """RFC-6962 Merkle root over the recorded verdict digests - one anchorable
        fingerprint of the service's whole verdict history.

        This is the **batched** verdict anchor: anchoring this single root on our
        independent Arc rail (one tx for many verdicts) lets a skeptic confirm a
        verdict was issued without trusting Circle - and unlike per-verdict
        anchoring it is economically sane for a sub-cent toll (anchoring each
        $0.001 verdict would cost more gas than the toll earns) and avoids racing
        the live bot's hourly anchor nonce. Returns ``None`` if no verdict has
        been recorded yet. Reuses the Stage-12 Merkle (same domain separation as
        the journal anchor) so existing tooling verifies it unchanged.
        """
        from core.journal.canonical import merkle_root as _merkle_root

        digests = self.verdict_digests()
        return _merkle_root(digests) if digests else None
