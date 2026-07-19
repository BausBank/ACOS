"""ERC-8004 ("Trustless Agents") on Arc Testnet - pure constants + call specs.

This module is I/O-free: it only describes *what* to call on the three live
ERC-8004 registries (Identity / Reputation / Validation), never *how*. The
actual broadcast goes through ``CircleWallet.send_contract_execution`` in
``core/circle/wallet.py`` (arbitrary contract CALL via Circle DCW;
gas paid in USDC). Keeping the encoding here makes it trivially testable.

Addresses + ABI signatures are taken verbatim from Arc's own quickstart
"Register your first AI agent":
https://docs.arc.network/arc/tutorials/register-your-first-ai-agent

Circle's ``abiParameters`` wants every argument as a JSON-friendly scalar:
integers as decimal strings, addresses and ``bytes32`` as ``0x``-hex, plain
strings as-is. The builder functions below enforce exactly that shape.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# --- Network (Arc Testnet) ------------------------------------------------
ARC_TESTNET_CHAIN_ID = 5042002
ARC_TESTNET_RPC_URL = "https://rpc.testnet.arc.network"
ARC_TESTNET_EXPLORER = "https://testnet.arcscan.app"

# --- Live ERC-8004 registry addresses on Arc Testnet ----------------------
IDENTITY_REGISTRY = "0x8004A818BFB912233c491871b3d84c89A494BD9e"
REPUTATION_REGISTRY = "0x8004B663056A597Dffe9eCcC1965A193B7388713"
VALIDATION_REGISTRY = "0x8004Cb1BF31DAf7788923b405b754f57acEB4272"

# --- Validation response codes (uint8) ------------------------------------
RESPONSE_PASSED = 100
RESPONSE_FAILED = 0

# --- Canonical ABI function signatures (no spaces; types only) ------------
SIG_REGISTER = "register(string)"
SIG_SET_AGENT_URI = "setAgentURI(uint256,string)"
SIG_OWNER_OF = "ownerOf(uint256)"
SIG_TOKEN_URI = "tokenURI(uint256)"
SIG_GIVE_FEEDBACK = (
    "giveFeedback(uint256,int128,uint8,string,string,string,string,bytes32)"
)
SIG_REVOKE_FEEDBACK = "revokeFeedback(uint256,uint64)"
SIG_VALIDATION_REQUEST = "validationRequest(address,uint256,string,bytes32)"
SIG_VALIDATION_RESPONSE = "validationResponse(bytes32,uint8,string,bytes32,string)"
SIG_GET_VALIDATION_STATUS = "getValidationStatus(bytes32)"

# Event emitted by Identity.register() - the minted agentId is its tokenId.
EVENT_TRANSFER = "Transfer(address,address,uint256)"

ZERO_BYTES32 = "0x" + "0" * 64


def to_bytes32_hex(digest_hex: str) -> str:
    """Normalise a 32-byte digest to a ``0x``-prefixed lowercase bytes32 string.

    Our verdict digests / Merkle leaves are stored as 64-hex without a ``0x``
    prefix (``core/x402/ledger.py``); ERC-8004 ``requestHash`` / ``responseHash``
    / ``feedbackHash`` parameters are ``bytes32`` and Circle expects them
    ``0x``-prefixed. Raises on anything that is not 32 bytes of hex.
    """
    h = digest_hex[2:] if digest_hex[:2].lower() == "0x" else digest_hex
    if len(h) != 64:
        raise ValueError(f"expected 32-byte (64-hex) digest, got {len(h)} hex chars")
    int(h, 16)  # validates it is hex; raises ValueError otherwise
    return "0x" + h.lower()


@dataclass(frozen=True)
class Call:
    """A fully-specified contract CALL: the target, the ABI signature and the
    ordered Circle ``abiParameters`` list. Pure data - the client turns it into
    a ``TxRequest``; tests assert these fields directly.
    """

    contract: str
    signature: str
    params: list[Any]


# --- Identity registry ----------------------------------------------------

def register_call(metadata_uri: str) -> Call:
    """Mint the one-time ERC-721 "passport" for an actor; agentId = its tokenId
    (read from the Transfer event on the receipt)."""
    return Call(IDENTITY_REGISTRY, SIG_REGISTER, [metadata_uri])


def set_agent_uri_call(agent_id: int, metadata_uri: str) -> Call:
    """Update an existing passport's tokenURI in place (owner-only). No re-mint."""
    return Call(IDENTITY_REGISTRY, SIG_SET_AGENT_URI, [str(agent_id), metadata_uri])


# --- Validation registry --------------------------------------------------

def validation_request_call(
    validator: str, agent_id: int, request_uri: str, request_hash_hex: str
) -> Call:
    """OWNER wallet opens a validation request addressed to our validator."""
    return Call(
        VALIDATION_REGISTRY,
        SIG_VALIDATION_REQUEST,
        [validator, str(agent_id), request_uri, to_bytes32_hex(request_hash_hex)],
    )


def validation_response_call(
    request_hash_hex: str,
    response: int,
    response_uri: str,
    response_hash_hex: str,
    tag: str,
) -> Call:
    """VALIDATOR wallet answers a request: response=100 passed, 0 failed.

    ``response_hash`` carries our verdict digest so a skeptic can match the
    on-chain badge against the public verdict receipt without trusting us.
    """
    return Call(
        VALIDATION_REGISTRY,
        SIG_VALIDATION_RESPONSE,
        [
            to_bytes32_hex(request_hash_hex),
            str(int(response)),
            response_uri,
            to_bytes32_hex(response_hash_hex),
            tag,
        ],
    )


def get_validation_status_call(request_hash_hex: str) -> Call:
    """Read-back (view): -> (validator, agentId, response, responseHash, tag, lastUpdate)."""
    return Call(
        VALIDATION_REGISTRY,
        SIG_GET_VALIDATION_STATUS,
        [to_bytes32_hex(request_hash_hex)],
    )


# --- Reputation registry --------------------------------------------------

def give_feedback_call(
    agent_id: int,
    value: int,
    value_decimals: int,
    tag1: str,
    tag2: str,
    endpoint: str,
    feedback_uri: str,
    feedback_hash_hex: str,
) -> Call:
    """VALIDATOR wallet records revocable feedback (anti-self-dealing: the
    owner cannot give feedback to its own agent)."""
    return Call(
        REPUTATION_REGISTRY,
        SIG_GIVE_FEEDBACK,
        [
            str(agent_id),
            str(int(value)),
            str(int(value_decimals)),
            tag1,
            tag2,
            endpoint,
            feedback_uri,
            to_bytes32_hex(feedback_hash_hex),
        ],
    )


def revoke_feedback_call(agent_id: int, feedback_index: int) -> Call:
    """VALIDATOR wallet revokes a prior feedback entry - the native, clean
    revoke path."""
    return Call(
        REPUTATION_REGISTRY,
        SIG_REVOKE_FEEDBACK,
        [str(agent_id), str(int(feedback_index))],
    )
