"""build_badge_fn - the synchronous cashier hook that issues a badge on PASS.

The Trust Toll cashier (``core/x402/server.py``) calls a sync ``badge_fn(result,
digest)`` right after the verdict is known, mirroring the existing best-effort
``anchor_fn`` block. Unlike ``anchor_fn`` (which anchors both PASS and FAIL), a
badge is issued ONLY on PASS. Issuance is idempotent and never blocks or fails
the paid verdict (any error -> return None).

Sync <-> async bridge: the cashier handler runs inside an aiohttp event loop, so
we cannot ``asyncio.run`` inline. The async issuance is run to completion in a
dedicated worker thread with its own loop (and fresh Circle clients), which is
safe across loops and matches the existing blocking-hook pattern.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from core.attest.client import AttestClient, compute_request_hash
from core.attest.identity import IdentityStore
from core.attest.registry import AttestRegistry

logger = logging.getLogger(__name__)


def _run_sync(coro: Any) -> Any:
    """Run ``coro`` to completion in a fresh loop on a worker thread.

    Safe to call from inside a running event loop (the cashier handler) - the
    coroutine gets its own loop in another thread, avoiding 'loop already
    running'. Blocks the caller until done (badges are rare; acceptable, and
    consistent with the cashier's existing synchronous hooks).
    """
    box: dict[str, Any] = {}

    def runner() -> None:
        try:
            box["value"] = asyncio.run(coro)
        except BaseException as exc:  # noqa: BLE001 - surfaced to caller below
            box["error"] = exc

    t = threading.Thread(target=runner, daemon=True)
    t.start()
    t.join()
    if "error" in box:
        raise box["error"]
    return box.get("value")


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def build_badge_fn(
    *,
    client_factory: Callable[[], AttestClient],
    identity_store: IdentityStore,
    registry: AttestRegistry,
    evidence_uri: str = "",
    now_fn: Callable[[], str] = _utc_now_iso,
    enabled: bool = True,
) -> Callable[[dict[str, Any], str], dict[str, Any] | None]:
    """Return the sync ``badge_fn(result, digest)`` hook for the cashier.

    Parameters
    ----------
    client_factory : builds a fresh ``AttestClient`` (with its own Circle
        wallets) per invocation - fresh HTTP clients avoid cross-loop reuse.
    identity_store : actor -> agentId map (subject must be pre-registered).
    registry : badge issuance log (idempotency + record of issue).
    evidence_uri : public pointer stamped into request/response/feedback URIs.
    now_fn : timestamp source (injectable for tests).
    enabled : master off-switch (no-op when False).
    """

    def badge_fn(result: dict[str, Any], digest: str) -> dict[str, Any] | None:
        if not enabled:
            return None
        if bool(result.get("ok")) is not True:
            return None  # PASS-gated: never issue on FAIL

        subject = str(result.get("track_ref") or "")
        idrow = identity_store.lookup(subject)
        if idrow is None or idrow.get("agent_id") is None:
            logger.info(
                "[attest] no registered agentId for subject=%r; skipping badge",
                subject,
            )
            return None
        agent_id = int(idrow["agent_id"])

        # Idempotency: same verdict for same actor -> return the existing badge.
        active = registry.find_active(agent_id, digest)
        if active is not None:
            return {
                "agent_id": agent_id,
                "request_hash": active.get("request_hash"),
                "verdict_digest": digest,
                "response_tx": active.get("response_tx"),
                "feedback_tx": active.get("feedback_tx"),
                "feedback_index": active.get("feedback_index"),
                "idempotent": True,
            }

        ts = now_fn()
        request_hash = compute_request_hash(agent_id, digest, ts)

        async def _do() -> dict[str, Any]:
            client = client_factory()
            try:
                return await client.issue(
                    agent_id=agent_id,
                    verdict_digest=digest,
                    request_hash=request_hash,
                    request_uri=evidence_uri,
                    response_uri=evidence_uri,
                    feedback_uri=evidence_uri,
                )
            finally:
                await client.aclose()

        badge_ref = _run_sync(_do())
        registry.record_issue(
            subject=subject,
            actor_kind=str(idrow.get("actor_kind") or ""),
            badge_ref=badge_ref,
            ts=ts,
        )
        return badge_ref

    return badge_fn
