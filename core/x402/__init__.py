"""x402 Trust Toll - pay-per-call verification over HTTP 402 (Stage 17).

Wraps the Stage-16 open verifier (:func:`core.verify.open_verify`) in an HTTP
endpoint that charges a sub-cent USDC toll per verification, using the **x402**
protocol (HTTP ``402 Payment Required`` revived as a machine-to-machine payment
handshake) settled through **Circle Gateway Nanopayments** on Arc-testnet.

Why Gateway (not a self-rolled facilitator): Gateway batches thousands of
gasless EIP-3009 authorizations into one on-chain settlement, so a $0.001 toll
is economical - a direct per-payment USDC transfer would cost more in gas than
it earns. Gateway also handles verification + settlement, so the cashier needs
no Circle API key and no chain code of its own.

What stays OURS (the trust core): the *verdict* is still anchored independently
(:mod:`core.anchor`) so a skeptic re-checks the PASS/FAIL from the public chain
without trusting Circle. Circle moves the money; it does not vouch for the result.

Layers:
  * :mod:`core.x402.protocol`  - pure x402 helpers (requirements, header codec).
  * :mod:`core.x402.gateway`   - Circle Gateway x402 REST client (settle/supported).
  * :mod:`core.x402.ledger`    - append-only JSONL receipt ledger (persistence).
  * :mod:`core.x402.ratelimit` - in-memory token-bucket rate limiter.
  * :mod:`core.x402.server`    - the aiohttp Trust Toll endpoint.

Entity-agnostic: the endpoint verifies whatever track is submitted (address +
journal + fills) and knows nothing about *what* the actor is.
"""

from core.x402.client import BuyerError, GatewayBuyer
from core.x402.gateway import (
    GatewayError,
    GatewayFacilitator,
    MAINNET_BASE_URL,
    TESTNET_BASE_URL,
)
from core.x402.protocol import (
    ARC_TESTNET_NETWORK,
    DEFAULT_SCHEME,
    HEADER_PAYMENT_REQUIRED,
    HEADER_PAYMENT_RESPONSE,
    HEADER_PAYMENT_SIGNATURE,
    X402_VERSION,
    PaymentRequirements,
    build_payment_required,
    build_payment_response,
    decode_header,
    encode_header,
    requirements_from_supported_kind,
    usd_to_atomic,
)

__all__ = [
    "GatewayBuyer",
    "BuyerError",
    "GatewayError",
    "GatewayFacilitator",
    "TESTNET_BASE_URL",
    "MAINNET_BASE_URL",
    "ARC_TESTNET_NETWORK",
    "DEFAULT_SCHEME",
    "X402_VERSION",
    "HEADER_PAYMENT_REQUIRED",
    "HEADER_PAYMENT_SIGNATURE",
    "HEADER_PAYMENT_RESPONSE",
    "PaymentRequirements",
    "build_payment_required",
    "build_payment_response",
    "decode_header",
    "encode_header",
    "requirements_from_supported_kind",
    "usd_to_atomic",
]
