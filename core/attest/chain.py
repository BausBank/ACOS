"""Web3ChainReader - read-only Arc access for attestation receipts + badge read-back.

Writes go through Circle DCW (``AttestClient``); *reads* (parsing the minted
agentId from the register Transfer event, the feedbackIndex from the NewFeedback
event, and reading a badge back via getValidationStatus) need plain JSON-RPC.
This wraps web3 against the Arc RPC - no signing, no gas. Tests inject a fake
``ChainReader`` instead, so this module is only exercised on the live path.

ABIs verified against the ERC-8004 spec (erc-8004/erc-8004-contracts ERC8004SPEC.md)
and Arc's "Register your first AI agent" quickstart.
"""

from __future__ import annotations

from typing import Any

from core.attest import erc8004

# --- minimal ABI fragments (only what we read) ----------------------------

_TRANSFER_EVENT = {
    "anonymous": False,
    "name": "Transfer",
    "type": "event",
    "inputs": [
        {"indexed": True, "name": "from", "type": "address"},
        {"indexed": True, "name": "to", "type": "address"},
        {"indexed": True, "name": "tokenId", "type": "uint256"},
    ],
}

_NEW_FEEDBACK_EVENT = {
    "anonymous": False,
    "name": "NewFeedback",
    "type": "event",
    "inputs": [
        {"indexed": True, "name": "agentId", "type": "uint256"},
        {"indexed": True, "name": "clientAddress", "type": "address"},
        {"indexed": False, "name": "feedbackIndex", "type": "uint64"},
        {"indexed": False, "name": "value", "type": "int128"},
        {"indexed": False, "name": "valueDecimals", "type": "uint8"},
        {"indexed": True, "name": "indexedTag1", "type": "string"},
        {"indexed": False, "name": "tag1", "type": "string"},
        {"indexed": False, "name": "tag2", "type": "string"},
        {"indexed": False, "name": "endpoint", "type": "string"},
        {"indexed": False, "name": "feedbackURI", "type": "string"},
        {"indexed": False, "name": "feedbackHash", "type": "bytes32"},
    ],
}

_TOKEN_URI = {
    "name": "tokenURI",
    "type": "function",
    "stateMutability": "view",
    "inputs": [{"name": "tokenId", "type": "uint256"}],
    "outputs": [{"name": "", "type": "string"}],
}

_GET_VALIDATION_STATUS = {
    "name": "getValidationStatus",
    "type": "function",
    "stateMutability": "view",
    "inputs": [{"name": "requestHash", "type": "bytes32"}],
    "outputs": [
        {"name": "validatorAddress", "type": "address"},
        {"name": "agentId", "type": "uint256"},
        {"name": "response", "type": "uint8"},
        {"name": "responseHash", "type": "bytes32"},
        {"name": "tag", "type": "string"},
        {"name": "lastUpdate", "type": "uint256"},
    ],
}


class Web3ChainReader:
    """Live read-only reader over the Arc RPC (no signing)."""

    def __init__(self, rpc_url: str | None = None, owner_address: str | None = None) -> None:
        from web3 import Web3

        self._Web3 = Web3
        self.w3 = Web3(Web3.HTTPProvider(rpc_url or erc8004.ARC_TESTNET_RPC_URL))
        self.owner_address = (owner_address or "").lower()

    def _bytes32(self, hex_str: str) -> bytes:
        h = hex_str[2:] if hex_str[:2].lower() == "0x" else hex_str
        return bytes.fromhex(h)

    def agent_id_from_tx(self, tx_hash: str) -> int | None:
        """Parse the minted agentId (tokenId) from the register receipt's
        Transfer event - the mint (from == zero address)."""
        from web3.logs import DISCARD

        receipt = self.w3.eth.get_transaction_receipt(tx_hash)
        c = self.w3.eth.contract(
            address=self._Web3.to_checksum_address(erc8004.IDENTITY_REGISTRY),
            abi=[_TRANSFER_EVENT],
        )
        events = c.events.Transfer().process_receipt(receipt, errors=DISCARD)
        mint = None
        for ev in events:
            args = ev["args"]
            if int(args["from"], 16) == 0:          # mint
                mint = int(args["tokenId"])
            elif self.owner_address and str(args["to"]).lower() == self.owner_address:
                mint = mint if mint is not None else int(args["tokenId"])
        return mint

    def feedback_index_from_tx(self, tx_hash: str) -> int | None:
        """Parse feedbackIndex from the giveFeedback receipt's NewFeedback event."""
        from web3.logs import DISCARD

        receipt = self.w3.eth.get_transaction_receipt(tx_hash)
        c = self.w3.eth.contract(
            address=self._Web3.to_checksum_address(erc8004.REPUTATION_REGISTRY),
            abi=[_NEW_FEEDBACK_EVENT],
        )
        events = c.events.NewFeedback().process_receipt(receipt, errors=DISCARD)
        if not events:
            return None
        return int(events[-1]["args"]["feedbackIndex"])

    def token_uri(self, agent_id: int) -> str:
        """Read a passport's current tokenURI (metadata description)."""
        c = self.w3.eth.contract(
            address=self._Web3.to_checksum_address(erc8004.IDENTITY_REGISTRY),
            abi=[_TOKEN_URI],
        )
        return c.functions.tokenURI(int(agent_id)).call()

    def get_validation_status(self, request_hash_hex: str) -> tuple[Any, ...] | None:
        """Read a badge back: getValidationStatus(requestHash) view call."""
        c = self.w3.eth.contract(
            address=self._Web3.to_checksum_address(erc8004.VALIDATION_REGISTRY),
            abi=[_GET_VALIDATION_STATUS],
        )
        result = c.functions.getValidationStatus(
            self._bytes32(request_hash_hex)
        ).call()
        return tuple(result)
