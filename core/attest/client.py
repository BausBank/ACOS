"""AttestClient - drives the ERC-8004 badge calls through Circle DCW wallets.

Two wallets, by ERC-8004's role split (owner != validator, anti-self-dealing):
  * OWNER     - registers the identity, opens validation requests.
  * VALIDATOR - answers validation, gives/revokes reputation feedback.

Both are Circle Developer-Controlled wallets (``core.circle.wallet``),
injected by the caller. In ``dry_run`` every call is logged and returns
``state="DRY_RUN"`` without touching the chain, so the whole pipeline is
exercised offline.

On-chain *reads* (badge read-back) and receipt log-parsing (agentId from the
register Transfer event, feedbackIndex from giveFeedback) are delegated to an
injectable ``chain_reader`` so this module stays unit-testable with no network.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Protocol

from core.attest import erc8004
from core.circle.wallet import CircleWallet, TxRequest, TxResult


@dataclass
class AttestConfig:
    """Static config for the attestation client."""

    dry_run: bool = True
    owner_address: str = ""        # OWNER wallet EOA address (for requests)
    validator_address: str = ""    # VALIDATOR wallet EOA address (the issuer)
    endpoint_url: str = ""         # our public /verify URL (Reputation endpoint)
    default_tag: str = "vtr-open-verify"
    fee_level: str = "MEDIUM"


class ChainReader(Protocol):
    """Read-only chain access used for receipt parsing + badge read-back.

    A live implementation wraps web3 against the Arc RPC; tests inject a fake.
    All methods may return ``None`` when the datum is unavailable.
    """

    def agent_id_from_tx(self, tx_hash: str) -> int | None: ...
    def feedback_index_from_tx(self, tx_hash: str) -> int | None: ...
    def get_validation_status(self, request_hash_hex: str) -> tuple[Any, ...] | None: ...


def compute_request_hash(agent_id: int, verdict_digest: str, ts: str) -> str:
    """Stable per-issuance key (64-hex, no prefix) binding agentId + verdict + time.

    Used as the ERC-8004 ``requestHash`` (the validation request/response key).
    Deterministic so the same issuance never produces two different keys.
    """
    digest = verdict_digest[2:] if verdict_digest[:2].lower() == "0x" else verdict_digest
    payload = json.dumps(
        {"agentId": int(agent_id), "verdict_digest": digest.lower(), "ts": ts},
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass
class AttestClient:
    owner: CircleWallet
    validator: CircleWallet
    config: AttestConfig = field(default_factory=AttestConfig)
    chain_reader: ChainReader | None = None

    async def aclose(self) -> None:
        """Close both wallets' HTTP clients."""
        await self.owner.aclose()
        if self.validator is not self.owner:
            await self.validator.aclose()

    _TERMINAL_STATES = frozenset(
        {"DRY_RUN", "COMPLETE", "CONFIRMED", "FAILED", "DENIED", "CANCELLED"}
    )

    async def _send(
        self, wallet: CircleWallet, call: erc8004.Call, decision_id: str
    ) -> TxResult:
        req = TxRequest(
            contract_address=call.contract,
            abi_function_signature=call.signature,
            abi_parameters=call.params,
            decision_id=decision_id,
            fee_level=self.config.fee_level,
        )
        result = await wallet.send_contract_execution(req)
        # Live: wait for confirmation so the on-chain tx_hash (+ receipt) is
        # available and dependent calls are ordered (response after request).
        if result.state not in self._TERMINAL_STATES:
            result = await wallet.wait_for_tx(result.tx_id)
        return result

    # --- one-time identity registration ----------------------------------

    async def register_identity(
        self, metadata_uri: str, *, decision_id: str | None = None
    ) -> tuple[int | None, TxResult]:
        """Mint the actor's passport NFT; returns ``(agent_id, tx)``.

        ``agent_id`` is parsed from the register receipt's Transfer event via the
        chain reader (live); ``None`` in dry-run or when no reader is wired.
        """
        call = erc8004.register_call(metadata_uri)
        tx = await self._send(self.owner, call, decision_id or "attest-register")
        agent_id: int | None = None
        if tx.tx_hash and self.chain_reader is not None:
            agent_id = self.chain_reader.agent_id_from_tx(tx.tx_hash)
        return agent_id, tx

    async def set_agent_uri(
        self, agent_id: int, metadata_uri: str, *, decision_id: str | None = None
    ) -> TxResult:
        """Update a passport's tokenURI in place (owner wallet). No re-mint."""
        call = erc8004.set_agent_uri_call(agent_id, metadata_uri)
        return await self._send(
            self.owner, call, decision_id or f"attest-seturi-{agent_id}"
        )

    # --- badge issuance (PASS) -------------------------------------------

    async def issue(
        self,
        *,
        agent_id: int,
        verdict_digest: str,
        request_hash: str,
        request_uri: str = "",
        response_uri: str = "",
        feedback_uri: str = "",
        tag: str | None = None,
    ) -> dict[str, Any]:
        """Issue the full "Verified" badge: validationRequest + validationResponse(100)
        + giveFeedback. Returns a compact ``badge_ref`` dict.
        """
        tag = tag or self.config.default_tag

        req_call = erc8004.validation_request_call(
            self.config.validator_address, agent_id, request_uri, request_hash
        )
        req_tx = await self._send(self.owner, req_call, f"attest-req-{request_hash}")

        resp_call = erc8004.validation_response_call(
            request_hash, erc8004.RESPONSE_PASSED, response_uri, verdict_digest, tag
        )
        resp_tx = await self._send(
            self.validator, resp_call, f"attest-resp-{request_hash}"
        )

        fb_call = erc8004.give_feedback_call(
            agent_id=agent_id,
            value=erc8004.RESPONSE_PASSED,
            value_decimals=0,
            tag1="verified",
            tag2=tag,
            endpoint=self.config.endpoint_url,
            feedback_uri=feedback_uri,
            feedback_hash_hex=verdict_digest,
        )
        fb_tx = await self._send(self.validator, fb_call, f"attest-fb-{request_hash}")

        feedback_index: int | None = None
        if fb_tx.tx_hash and self.chain_reader is not None:
            feedback_index = self.chain_reader.feedback_index_from_tx(fb_tx.tx_hash)

        return {
            "agent_id": agent_id,
            "request_hash": request_hash,
            "verdict_digest": verdict_digest,
            "request_tx": req_tx.tx_id,
            "request_tx_hash": req_tx.tx_hash,
            "response_tx": resp_tx.tx_id,
            "response_tx_hash": resp_tx.tx_hash,
            "feedback_tx": fb_tx.tx_id,
            "feedback_tx_hash": fb_tx.tx_hash,
            "feedback_index": feedback_index,
            "dry_run": resp_tx.state == "DRY_RUN",
        }

    # --- revoke -----------------------------------------------------------

    async def revoke(
        self,
        *,
        agent_id: int,
        request_hash: str,
        feedback_index: int | None,
        response_uri: str = "",
        response_hash: str = erc8004.ZERO_BYTES32,
        tag: str | None = None,
    ) -> dict[str, Any]:
        """Revoke a badge two ways: native ``revokeFeedback`` + downgrade the
        validation response to 0 (failed). Either alone is a valid revoke; both
        is belt-and-suspenders.
        """
        tag = tag or self.config.default_tag
        out: dict[str, Any] = {"agent_id": agent_id, "request_hash": request_hash}

        if feedback_index is not None:
            rv_call = erc8004.revoke_feedback_call(agent_id, feedback_index)
            rv_tx = await self._send(
                self.validator, rv_call, f"attest-revoke-{request_hash}"
            )
            out["revoke_feedback_tx"] = rv_tx.tx_id
            out["dry_run"] = rv_tx.state == "DRY_RUN"

        down_call = erc8004.validation_response_call(
            request_hash, erc8004.RESPONSE_FAILED, response_uri, response_hash, tag
        )
        down_tx = await self._send(
            self.validator, down_call, f"attest-downgrade-{request_hash}"
        )
        out["downgrade_tx"] = down_tx.tx_id
        out.setdefault("dry_run", down_tx.state == "DRY_RUN")
        return out

    # --- read-back --------------------------------------------------------

    def read_status(self, request_hash: str) -> dict[str, Any] | None:
        """Read a badge back from the Validation registry (view call).

        Returns the parsed status, or ``None`` when no chain reader is wired
        (e.g. dry-run / offline tests).
        """
        if self.chain_reader is None:
            return None
        raw = self.chain_reader.get_validation_status(request_hash)
        if raw is None:
            return None
        validator, agent_id, response, response_hash, tag, last_update = raw
        if isinstance(response_hash, (bytes, bytearray)):
            response_hash = "0x" + bytes(response_hash).hex()
        return {
            "validator": validator,
            "agent_id": int(agent_id),
            "response": int(response),
            "response_hash": str(response_hash),
            "tag": tag,
            "last_update": int(last_update),
            "passed": int(response) == erc8004.RESPONSE_PASSED,
        }
