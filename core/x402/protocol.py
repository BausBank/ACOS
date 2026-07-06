"""x402 protocol primitives for the Trust Toll cashier (Stage 17).

Pure, network-free helpers that implement the **seller** side of Circle's x402
variant (the one Circle Gateway Nanopayments speaks). No blockchain code lives
here - settlement is delegated to Circle Gateway (see :mod:`core.x402.gateway`);
this module only builds/parses the HTTP-level payment negotiation.

The negotiation (Circle x402 header names, verified live against
``gateway-api-testnet.circle.com``):

    client --POST /verify------------------>  seller
           <--402 + PAYMENT-REQUIRED--------  (here is the price + how to pay)
           --POST /verify + PAYMENT-SIGNATURE->(buyer's gasless EIP-3009 payload)
           <--200 + verdict + PAYMENT-RESPONSE (settled via Gateway, here's PASS/FAIL)

``PAYMENT-REQUIRED`` / ``PAYMENT-SIGNATURE`` / ``PAYMENT-RESPONSE`` carry
base64-encoded JSON. The ``accepts`` entry (``PaymentRequirements``) and the
buyer's ``PaymentPayload`` match the Circle Gateway OpenAPI schemas exactly so a
buyer using ``@circle-fin/x402-batching`` / ``circle services pay`` interoperates
with us unchanged.

Grounded constants (Arc-testnet, from ``GET /v1/x402/supported``):
  * network   ``eip155:5042002``        (CAIP-2 id for Arc Testnet)
  * scheme    ``exact``
  * asset     ``0x3600...0000``         (USDC, 6 decimals)
  * extra     ``{name: GatewayWalletBatched, version: 1, verifyingContract: 0x0077...}``
  * minValiditySeconds ``604800``       (buyer authorization must be valid >= 7 days)

We do NOT hardcode the verifying contract / asset: they are read from
``/v1/x402/supported`` at runtime and threaded in here, so a Circle redeploy
can't silently break us.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from typing import Any

# x402 HTTP header names (Circle Gateway variant - NOT Coinbase's `X-PAYMENT`).
HEADER_PAYMENT_REQUIRED = "PAYMENT-REQUIRED"   # server -> client (402 body, base64)
HEADER_PAYMENT_SIGNATURE = "PAYMENT-SIGNATURE"  # client -> server (the signed payload)
HEADER_PAYMENT_RESPONSE = "PAYMENT-RESPONSE"   # server -> client (settlement receipt)

X402_VERSION = 2          # x402Version reported by Circle Gateway on Arc-testnet
DEFAULT_SCHEME = "exact"
ARC_TESTNET_NETWORK = "eip155:5042002"
# Fallback validity floor if /supported omits it; Gateway rejects shorter ones
# with `authorization_validity_too_short`.
DEFAULT_MIN_VALIDITY_SECONDS = 604_800  # 7 days


def usd_to_atomic(usd: float, decimals: int) -> int:
    """Convert a USD price to atomic token units (e.g. $0.001 USDC -> 1000).

    Rounds to the nearest atomic unit. ``decimals`` comes from the asset entry
    in ``/v1/x402/supported`` (6 for USDC), never assumed.
    """
    return int(round(usd * (10 ** decimals)))


@dataclass
class PaymentRequirements:
    """One acceptable way to pay, matching Circle's ``PaymentRequirements``.

    Built from a ``/v1/x402/supported`` *kind* (which supplies ``asset``,
    ``network`` and ``extra``) plus our price + receiving address.
    """

    scheme: str
    network: str
    asset: str
    amount: str            # atomic units, as a string ("1000" = $0.001 USDC)
    pay_to: str
    max_timeout_seconds: int
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scheme": self.scheme,
            "network": self.network,
            "asset": self.asset,
            "amount": self.amount,
            "payTo": self.pay_to,
            "maxTimeoutSeconds": self.max_timeout_seconds,
            "extra": self.extra,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "PaymentRequirements":
        return cls(
            scheme=d["scheme"],
            network=d["network"],
            asset=d["asset"],
            amount=str(d["amount"]),
            pay_to=d.get("payTo") or d.get("pay_to", ""),
            max_timeout_seconds=int(d.get("maxTimeoutSeconds", DEFAULT_MIN_VALIDITY_SECONDS)),
            extra=d.get("extra", {}),
        )


def requirements_from_supported_kind(
    kind: dict[str, Any],
    *,
    price_usd: float,
    pay_to: str,
    asset_symbol: str = "USDC",
    max_timeout_seconds: int | None = None,
) -> PaymentRequirements:
    """Turn a ``/v1/x402/supported`` *kind* into our ``PaymentRequirements``.

    Picks the ``asset`` whose symbol matches ``asset_symbol`` from the kind's
    ``extra.assets``, converts ``price_usd`` to that asset's atomic units, and
    copies ``extra`` (name / version / verifyingContract) verbatim so the
    buyer's EIP-712 signature targets the right domain. ``maxTimeoutSeconds``
    defaults to the kind's ``minValiditySeconds`` (+1 day buffer) so a buyer's
    7-day authorization is never rejected as too short.
    """
    extra = dict(kind.get("extra", {}))
    assets = extra.get("assets", [])
    match = next(
        (a for a in assets if str(a.get("symbol", "")).upper() == asset_symbol.upper()),
        None,
    )
    if match is None:
        raise ValueError(
            f"asset {asset_symbol!r} not offered by Gateway for network "
            f"{kind.get('network')!r}; available: {[a.get('symbol') for a in assets]}"
        )
    decimals = int(match["decimals"])
    amount = usd_to_atomic(price_usd, decimals)
    if amount <= 0:
        raise ValueError(f"price ${price_usd} rounds to 0 atomic units at {decimals} dp")
    min_validity = int(extra.get("minValiditySeconds", DEFAULT_MIN_VALIDITY_SECONDS))
    timeout = max_timeout_seconds if max_timeout_seconds is not None else min_validity + 86_400
    return PaymentRequirements(
        scheme=str(kind.get("scheme", DEFAULT_SCHEME)),
        network=str(kind["network"]),
        asset=str(match["address"]),
        amount=str(amount),
        pay_to=pay_to,
        max_timeout_seconds=timeout,
        extra=extra,
    )


def build_payment_required(
    accepts: list[PaymentRequirements],
    *,
    resource_url: str,
    description: str,
    mime_type: str = "application/json",
) -> dict[str, Any]:
    """Build the JSON body advertised in the ``PAYMENT-REQUIRED`` 402 header."""
    return {
        "x402Version": X402_VERSION,
        "resource": {
            "url": resource_url,
            "description": description,
            "mimeType": mime_type,
        },
        "accepts": [r.to_dict() for r in accepts],
    }


def encode_header(obj: dict[str, Any]) -> str:
    """base64(JSON) - the wire form for all three x402 headers."""
    raw = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


def decode_header(value: str) -> dict[str, Any]:
    """Inverse of :func:`encode_header`. Raises ``ValueError`` on bad input."""
    try:
        raw = base64.b64decode(value, validate=True)
        return json.loads(raw.decode("utf-8"))
    except Exception as exc:  # malformed header is a client error, surfaced as 402
        raise ValueError(f"malformed x402 header: {exc}") from exc


def build_payment_response(settle_result: dict[str, Any]) -> dict[str, Any]:
    """Build the ``PAYMENT-RESPONSE`` body from Gateway's settle result.

    Carries the settlement transaction UUID + payer + network so the client can
    independently look the transfer up via ``GET /v1/x402/transfers/{id}``.
    """
    return {
        "success": bool(settle_result.get("success")),
        "transaction": settle_result.get("transaction", ""),
        "payer": settle_result.get("payer"),
        "network": settle_result.get("network"),
    }
