"""IdentityStore - the actor -> agentId mapping (the ERC-8004 "passport" book).

The verifier is entity-agnostic and never reads identity; identity lives only
here and on-chain. One JSONL row per registered actor:

    {actor, actor_kind, agent_id, owner_addr, metadata_uri, register_tx, ts}

Lookups are by the opaque ``actor`` string. Registration is idempotent: a
second register for the same actor is a no-op that returns the existing row.
"""

from __future__ import annotations

import json
import os
import threading
from typing import Any

from core.attest.client import AttestClient


class IdentityStore:
    """Append-only JSONL map: actor -> agentId. Thread-safe append."""

    def __init__(self, path: str) -> None:
        self.path = str(path)
        parent = os.path.dirname(self.path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        self._lock = threading.Lock()

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
                    continue
        return out

    def lookup(self, actor: str) -> dict[str, Any] | None:
        """Most recent mapping row for ``actor``, or ``None``."""
        found: dict[str, Any] | None = None
        for r in self.load():
            if r.get("actor") == actor and r.get("agent_id") is not None:
                found = r
        return found

    def record(self, row: dict[str, Any]) -> None:
        line = json.dumps(row, separators=(",", ":"), ensure_ascii=False)
        with self._lock:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
                fh.flush()


async def register_actor(
    client: AttestClient,
    store: IdentityStore,
    *,
    actor: str,
    actor_kind: str,
    metadata_uri: str,
    ts: str,
) -> dict[str, Any]:
    """Idempotently register an actor's identity NFT and persist the mapping.

    If ``actor`` already has an ``agent_id`` in the store, returns that row
    unchanged (no on-chain call). Otherwise calls ``Identity.register`` via the
    OWNER wallet, parses the minted ``agent_id`` (live), and appends the row.
    """
    existing = store.lookup(actor)
    if existing is not None:
        return existing

    agent_id, tx = await client.register_identity(
        metadata_uri, decision_id=f"attest-register-{actor}"
    )
    row = {
        "actor": actor,
        "actor_kind": actor_kind,
        "agent_id": agent_id,
        "owner_addr": client.config.owner_address,
        "metadata_uri": metadata_uri,
        "register_tx": tx.tx_id,
        "register_tx_hash": tx.tx_hash,
        "dry_run": tx.state == "DRY_RUN",
        "ts": ts,
    }
    store.record(row)
    return row
