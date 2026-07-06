"""Circle Gateway x402 facilitator client (Stage 17).

A thin async wrapper over Circle Gateway's **public** x402 REST endpoints - the
settlement layer behind the Trust Toll cashier. Verified live against
``https://gateway-api-testnet.circle.com`` (Arc-testnet, chainId 5042002):

  * ``GET  /v1/x402/supported`` - payment kinds per network, incl. the
    ``GatewayWalletBatched`` ``verifyingContract`` + USDC asset address. We read
    addresses from here instead of hardcoding them.
  * ``POST /v1/x402/settle``    - submit the buyer's EIP-3009 authorization;
    Gateway verifies it, locks balance, and queues it for batch settlement.
  * ``POST /v1/x402/verify``    - dry verification (no balance/nonce lock).
  * ``POST /v1/balances``       - a depositor's unified Gateway USDC balance.
  * ``GET  /v1/x402/transfers/{id}`` - settlement status.

These endpoints carry NO ``security`` block in the Gateway OpenAPI spec - they
are unauthenticated. The buyer's signature is the authorization; the seller just
relays it, so the cashier needs **no Circle API key** to take payment.

**Network robustness.** Circle's testnet endpoint is reached flakily from this
host (intermittent proxy-TLS / DNS ``getaddrinfo`` failures), exactly the issue
the live bot handles with proxy/direct auto-probing. So every call here retries
across both transports (env-proxy then direct) with backoff before giving up -
a single blip never fails a settlement.
"""

from __future__ import annotations

import asyncio
import os
from typing import Any

import httpx

from core.x402.protocol import ARC_TESTNET_NETWORK

# Public Gateway REST base URLs (no API key required for the x402 endpoints).
TESTNET_BASE_URL = "https://gateway-api-testnet.circle.com"
MAINNET_BASE_URL = "https://gateway-api.circle.com"


class GatewayError(RuntimeError):
    """A Gateway REST call failed at the transport / HTTP layer."""


class GatewayFacilitator:
    """Async client for Circle Gateway's x402 settlement endpoints.

    Parameters
    ----------
    base_url:
        Gateway REST root. Defaults to ``X402_GATEWAY_BASE_URL`` env or the
        public testnet endpoint.
    network:
        CAIP-2 network we operate on (default Arc-testnet ``eip155:5042002``).
    max_attempts:
        Transport retries per call, alternating env-proxy / direct.
    """

    def __init__(
        self,
        base_url: str | None = None,
        *,
        network: str = ARC_TESTNET_NETWORK,
        timeout_seconds: float = 30.0,
        max_attempts: int = 4,
    ) -> None:
        self.base_url = (
            base_url or os.getenv("X402_GATEWAY_BASE_URL") or TESTNET_BASE_URL
        ).rstrip("/")
        self.network = network
        self._timeout = timeout_seconds
        self._max_attempts = max(1, max_attempts)
        self._supported_cache: dict[str, Any] | None = None

    async def aclose(self) -> None:
        """No persistent client to close (one client per call for proxy probing)."""
        return None

    async def _request(
        self, method: str, path: str, *, json: dict[str, Any] | None = None
    ) -> httpx.Response:
        """One REST call, auto-probing env-proxy then direct, with backoff.

        Circle's testnet host fails intermittently on one transport but not the
        other; alternating + retrying makes a single blip non-fatal. Raises
        :class:`GatewayError` only if every attempt fails.
        """
        last: Exception | None = None
        for attempt in range(self._max_attempts):
            trust_env = attempt % 2 == 0  # even: honour HTTP(S)_PROXY; odd: direct
            try:
                async with httpx.AsyncClient(
                    base_url=self.base_url,
                    timeout=self._timeout,
                    trust_env=trust_env,
                    headers={"Accept": "application/json", "Content-Type": "application/json"},
                ) as c:
                    return await c.request(method, path, json=json)
            except httpx.HTTPError as exc:
                last = exc
                if attempt < self._max_attempts - 1:
                    await asyncio.sleep(1.0 + attempt)
        raise GatewayError(
            f"{method} {path} failed after {self._max_attempts} attempts "
            f"(proxy+direct): {last}"
        )

    # ------------------------------------------------------------------
    # /v1/x402/supported
    # ------------------------------------------------------------------

    async def get_supported(self, *, refresh: bool = False) -> dict[str, Any]:
        """Return the full ``/v1/x402/supported`` document (cached)."""
        if self._supported_cache is not None and not refresh:
            return self._supported_cache
        resp = await self._request("GET", "/v1/x402/supported")
        if resp.status_code >= 400:
            raise GatewayError(
                f"GET /v1/x402/supported -> {resp.status_code}: {resp.text[:200]}"
            )
        self._supported_cache = resp.json()
        return self._supported_cache

    async def supported_kind(
        self, *, network: str | None = None, refresh: bool = False
    ) -> dict[str, Any]:
        """Return the payment *kind* for ``network`` (default our network)."""
        net = network or self.network
        doc = await self.get_supported(refresh=refresh)
        for kind in doc.get("kinds", []):
            if str(kind.get("network")) == net:
                return kind
        raise GatewayError(
            f"Gateway does not list x402 support for network {net!r} "
            f"(available: {[k.get('network') for k in doc.get('kinds', [])]})"
        )

    # ------------------------------------------------------------------
    # /v1/balances
    # ------------------------------------------------------------------

    async def get_balances(self, depositor: str, *, domain: int = 26) -> dict[str, Any]:
        """Return ``depositor``'s unified Gateway USDC balance doc (domain 26 = Arc)."""
        resp = await self._request(
            "POST", "/v1/balances",
            json={"token": "USDC", "sources": [{"domain": domain, "depositor": depositor}]},
        )
        if resp.status_code >= 400:
            raise GatewayError(f"POST /v1/balances -> {resp.status_code}: {resp.text[:200]}")
        return resp.json()

    async def available_atomic(self, depositor: str, *, domain: int = 26) -> int:
        """Convenience: the depositor's available balance in atomic USDC units.

        Gateway returns the balance in HUMAN units ("1.000000" = 1 USDC), not
        atomic, so convert to 6-dp atomic units here.
        """
        doc = await self.get_balances(depositor, domain=domain)
        bals = doc.get("balances", [])
        if not bals:
            return 0
        return int(round(float(str(bals[0].get("balance", "0"))) * 1_000_000))

    # ------------------------------------------------------------------
    # /v1/x402/settle  &  /v1/x402/verify
    # ------------------------------------------------------------------

    async def settle(
        self,
        payment_payload: dict[str, Any],
        payment_requirements: dict[str, Any],
    ) -> dict[str, Any]:
        """Settle a payment. Returns Gateway's result dict.

        A *business* failure (``insufficient_balance``, ``nonce_already_used``,
        ``authorization_expired`` …) comes back as HTTP 200/400 with
        ``success=false`` + ``errorReason`` - returned as-is so the caller can
        answer the client precisely. Only 5xx / exhausted-transport raise.
        Retrying a connect-failed settle is safe: the authorization nonce makes
        Gateway idempotent (a re-send is ``nonce_already_used``, not a double
        charge).
        """
        resp = await self._request(
            "POST", "/v1/x402/settle",
            json={"paymentPayload": payment_payload, "paymentRequirements": payment_requirements},
        )
        if resp.status_code >= 500:
            raise GatewayError(f"Gateway settle 5xx: {resp.status_code} {resp.text[:200]}")
        try:
            return resp.json()
        except Exception as exc:  # noqa: BLE001
            raise GatewayError(f"Gateway settle returned non-JSON: {exc}") from exc

    async def verify(
        self,
        payment_payload: dict[str, Any],
        payment_requirements: dict[str, Any],
    ) -> dict[str, Any]:
        """Dry-verify a payload without locking balance (best-effort precheck)."""
        resp = await self._request(
            "POST", "/v1/x402/verify",
            json={"paymentPayload": payment_payload, "paymentRequirements": payment_requirements},
        )
        return resp.json()

    # ------------------------------------------------------------------
    # /v1/x402/transfers/{id}
    # ------------------------------------------------------------------

    async def get_transfer(self, transfer_id: str) -> dict[str, Any]:
        """Look up a settled transfer's status by its UUID."""
        resp = await self._request("GET", f"/v1/x402/transfers/{transfer_id}")
        if resp.status_code >= 400:
            raise GatewayError(
                f"GET /v1/x402/transfers/{transfer_id} -> {resp.status_code}"
            )
        return resp.json()
