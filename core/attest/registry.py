"""AttestRegistry - append-only JSONL log of badge issuances and revocations.

The system-of-record for *which* badges this service has issued. On-chain the
ERC-8004 Validation/Reputation rows are the canonical public registry; this
local log is the operator-side mirror used for idempotency, the revoke CLI, and
a batched, anchorable ``root()`` (RFC-6962 Merkle over the issued request
hashes, reusing the journal Merkle primitive so existing tooling verifies it).

Entity-agnostic: a record's subject is an opaque ``subject`` string.
"""

from __future__ import annotations

import json
import os
import threading
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class AttestRecord:
    """One badge lifecycle event."""

    ts: str
    event: str                       # "issued" | "revoked"
    subject: str                     # opaque actor identifier
    actor_kind: str = ""             # "agent" | "human" | "service" | ...
    agent_id: int | None = None
    request_hash: str | None = None
    verdict_digest: str | None = None
    request_tx: str | None = None
    response_tx: str | None = None
    feedback_tx: str | None = None
    feedback_index: int | None = None
    revoke_feedback_tx: str | None = None
    downgrade_tx: str | None = None
    dry_run: bool = False
    extra: dict[str, Any] = field(default_factory=dict)


class AttestRegistry:
    """Append-only JSONL. Thread-safe append (single-process)."""

    def __init__(self, path: str) -> None:
        self.path = str(path)
        parent = os.path.dirname(self.path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        self._lock = threading.Lock()

    def record(self, rec: "AttestRecord | dict[str, Any]") -> None:
        obj = asdict(rec) if isinstance(rec, AttestRecord) else dict(rec)
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

    # --- writers ----------------------------------------------------------

    def record_issue(
        self, *, subject: str, actor_kind: str, badge_ref: dict[str, Any], ts: str
    ) -> AttestRecord:
        rec = AttestRecord(
            ts=ts,
            event="issued",
            subject=subject,
            actor_kind=actor_kind,
            agent_id=badge_ref.get("agent_id"),
            request_hash=badge_ref.get("request_hash"),
            verdict_digest=badge_ref.get("verdict_digest"),
            request_tx=badge_ref.get("request_tx"),
            response_tx=badge_ref.get("response_tx"),
            feedback_tx=badge_ref.get("feedback_tx"),
            feedback_index=badge_ref.get("feedback_index"),
            dry_run=bool(badge_ref.get("dry_run")),
        )
        self.record(rec)
        return rec

    def record_revoke(
        self, *, subject: str, actor_kind: str, revoke_ref: dict[str, Any], ts: str
    ) -> AttestRecord:
        rec = AttestRecord(
            ts=ts,
            event="revoked",
            subject=subject,
            actor_kind=actor_kind,
            agent_id=revoke_ref.get("agent_id"),
            request_hash=revoke_ref.get("request_hash"),
            revoke_feedback_tx=revoke_ref.get("revoke_feedback_tx"),
            downgrade_tx=revoke_ref.get("downgrade_tx"),
            dry_run=bool(revoke_ref.get("dry_run")),
        )
        self.record(rec)
        return rec

    # --- readers ----------------------------------------------------------

    def find_active(self, agent_id: int, verdict_digest: str) -> dict[str, Any] | None:
        """Return the issued (and not later revoked) badge for this exact
        ``(agent_id, verdict_digest)`` pair, else ``None``. Drives idempotency:
        the same verdict for the same actor is never double-issued.
        """
        digest = (
            verdict_digest[2:]
            if verdict_digest[:2].lower() == "0x"
            else verdict_digest
        ).lower()
        issued: dict[str, dict[str, Any]] = {}   # request_hash -> issued row
        revoked: set[str] = set()
        for r in self.load():
            rh = r.get("request_hash")
            if not rh:
                continue
            if r.get("event") == "issued":
                rd = str(r.get("verdict_digest") or "")
                rd = (rd[2:] if rd[:2].lower() == "0x" else rd).lower()
                if r.get("agent_id") == agent_id and rd == digest:
                    issued[rh] = r
            elif r.get("event") == "revoked":
                revoked.add(rh)
        for rh, row in issued.items():
            if rh not in revoked:
                return row
        return None

    def request_hashes(self) -> list[str]:
        """Ordered issued request hashes (64-hex, no 0x), for the Merkle root."""
        out: list[str] = []
        for r in self.load():
            if r.get("event") != "issued":
                continue
            rh = r.get("request_hash")
            if rh:
                out.append(str(rh)[2:] if str(rh).startswith("0x") else str(rh))
        return out

    def root(self) -> str | None:
        """RFC-6962 Merkle root over issued request hashes - one anchorable
        fingerprint of the whole badge-issuance history. ``None`` when empty.
        Reuses the journal Merkle helper (same domain separation as the journal anchor).
        """
        from core.journal.canonical import merkle_root as _merkle_root

        leaves = self.request_hashes()
        return _merkle_root(leaves) if leaves else None
