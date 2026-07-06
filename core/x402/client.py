"""x402 buyer over Circle Gateway Nanopayments (Stage 17).

The **buyer** side of the Trust Toll: an entity that pays our cashier (or any
x402 / Gateway-batching seller) a sub-cent USDC toll, gasless. Reusable as the
paying agent in the Stage-19 agent-to-agent demo.

Flow (the buyer talks to the SELLER, never to Gateway settle - the seller
relays):

    1. request seller URL                 -> 402 + PAYMENT-REQUIRED (the price)
    2. sign an EIP-3009 TransferWithAuthorization against the GatewayWalletBatched
       domain (offchain, zero gas), build the x402 PaymentPayload
    3. retry with PAYMENT-SIGNATURE        -> 200 + resource + PAYMENT-RESPONSE

Setup (one-time, on-chain): the buyer deposits USDC into the Gateway Wallet
contract (``0x0077...``); after that, payments are gasless (Gateway batches them
and pays gas once per batch). The signing domain, asset and amount all come from
the seller's 402 ``accepts`` (which the seller built from ``/v1/x402/supported``)
- nothing is hardcoded except the deposit contract, which Circle pins the same on
all EVM testnets.

Grounding (verified): x402 "exact" payload shape from the coinbase/x402 spec;
EIP-3009 ``TransferWithAuthorization`` struct; ``GatewayWalletBatched`` domain
from ``/v1/x402/supported``; deposit ``approve``+``deposit(address,uint256)`` from
Circle's own ``gateway-sdk.ts`` sample.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import time
from typing import Any

import httpx

from core.x402.gateway import TESTNET_BASE_URL
from core.x402.protocol import (
    DEFAULT_MIN_VALIDITY_SECONDS,
    HEADER_PAYMENT_REQUIRED,
    HEADER_PAYMENT_RESPONSE,
    HEADER_PAYMENT_SIGNATURE,
    X402_VERSION,
    decode_header,
    encode_header,
)

# Circle pins the Gateway Wallet (deposit target + x402 verifying contract) at the
# same address on ALL EVM testnets. Still, signing uses the verifyingContract from
# the seller's 402 - this constant is only the deposit destination.
GATEWAY_WALLET_ADDRESS = "0x0077777d7EBA4688BDeF3E311b846F25870A19B9"
ARC_TESTNET_USDC = "0x3600000000000000000000000000000000000000"

# CAIP-2 network -> Circle Gateway domain id (for the /v1/balances query).
_DOMAIN_BY_NETWORK = {
    "eip155:5042002": 26,   # Arc Testnet
    "eip155:84532": 6,      # Base Sepolia
    "eip155:11155111": 0,   # Ethereum Sepolia
    "eip155:421614": 3,     # Arbitrum Sepolia
}

# EIP-3009 TransferWithAuthorization struct (standard; the x402 "exact" scheme).
_TWA_TYPES = {
    "TransferWithAuthorization": [
        {"name": "from", "type": "address"},
        {"name": "to", "type": "address"},
        {"name": "value", "type": "uint256"},
        {"name": "validAfter", "type": "uint256"},
        {"name": "validBefore", "type": "uint256"},
        {"name": "nonce", "type": "bytes32"},
    ]
}


class BuyerError(RuntimeError):
    """The x402 buyer could not complete a payment."""


class GatewayBuyer:
    """Pays x402 tolls from a Gateway USDC balance, gasless.

    Parameters
    ----------
    private_key:
        EOA private key (hex). SCA wallets are NOT supported - Gateway verifies
        the authorization with ``ecrecover`` offchain, which is EOA-only.
    network:
        CAIP-2 id of the chain whose Gateway balance funds payments
        (default Arc-testnet ``eip155:5042002``).
    gateway_url / rpc_url:
        Gateway REST root + EVM RPC (defaults to testnet / Arc env).
    """

    def __init__(
        self,
        private_key: str,
        *,
        network: str = "eip155:5042002",
        gateway_url: str | None = None,
        rpc_url: str | None = None,
        timeout_seconds: float = 30.0,
    ) -> None:
        from eth_account import Account

        self._acct = Account.from_key(private_key)
        self.address = self._acct.address
        self.network = network
        try:
            self.chain_id = int(network.split(":", 1)[1])
        except (IndexError, ValueError) as exc:
            raise BuyerError(f"bad CAIP-2 network {network!r}") from exc
        self.gateway_url = (
            gateway_url or os.getenv("X402_GATEWAY_BASE_URL") or TESTNET_BASE_URL
        ).rstrip("/")
        self.rpc_url = rpc_url or os.getenv("ARC_RPC_URL", "https://rpc.testnet.arc.network")
        self._timeout = timeout_seconds

    # ------------------------------------------------------------------
    # Signing (pure, offline, zero gas)
    # ------------------------------------------------------------------

    def build_payment(
        self, requirements: dict[str, Any], *, resource: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Build a signed x402 ``PaymentPayload`` for the seller's requirements.

        ``requirements`` is one ``accepts[]`` entry from the 402 ``PAYMENT-REQUIRED``
        header. The signing domain (name / version / verifyingContract) comes from
        its ``extra``; the amount / payTo / asset from the entry itself.

        ``resource`` is the resource info from the 402 body. Circle's live Gateway
        REQUIRES ``paymentPayload.resource`` (its OpenAPI marks it optional, but
        ``/v1/x402/verify`` and ``/settle`` reject a payload without it), so we
        always include one - the seller's if given, else a minimal placeholder.
        """
        extra = requirements.get("extra", {})
        if not extra.get("verifyingContract"):
            raise BuyerError("requirements.extra.verifyingContract missing - cannot sign")
        now = int(time.time())
        valid_after = now - 60  # small backdate to tolerate clock skew
        min_validity = int(extra.get("minValiditySeconds", DEFAULT_MIN_VALIDITY_SECONDS))
        valid_before = now + min_validity + 86_400  # clear the 7-day floor + buffer
        nonce = secrets.token_bytes(32)
        pay_to = requirements.get("payTo") or requirements.get("pay_to")
        value = int(requirements["amount"])

        signature = self._sign(
            from_addr=self.address, to_addr=pay_to, value=value,
            valid_after=valid_after, valid_before=valid_before, nonce=nonce,
            name=extra.get("name", "GatewayWalletBatched"),
            version=str(extra.get("version", "1")),
            verifying_contract=extra["verifyingContract"],
        )
        # The on-wire authorization uses STRING values (per the x402 exact spec).
        authorization = {
            "from": self.address,
            "to": pay_to,
            "value": str(value),
            "validAfter": str(valid_after),
            "validBefore": str(valid_before),
            "nonce": "0x" + nonce.hex(),
        }
        if resource is None:
            resource = {
                "url": "/", "description": "x402 payment", "mimeType": "application/json",
            }
        return {
            "x402Version": X402_VERSION,
            "resource": resource,
            "accepted": requirements,
            "payload": {"signature": signature, "authorization": authorization},
        }

    def _signable(
        self, *, from_addr, to_addr, value, valid_after, valid_before, nonce,
        name, version, verifying_contract,
    ):
        from eth_account.messages import encode_typed_data

        # 3-arg form: domain is built from domain_data, so we must NOT list
        # EIP712Domain in the types (eth-account adds it). Avoids a common footgun.
        return encode_typed_data(
            domain_data={
                "name": name,
                "version": version,
                "chainId": self.chain_id,
                "verifyingContract": verifying_contract,
            },
            message_types=_TWA_TYPES,
            message_data={
                "from": from_addr,
                "to": to_addr,
                "value": value,
                "validAfter": valid_after,
                "validBefore": valid_before,
                "nonce": nonce,
            },
        )

    def _sign(self, **kw) -> str:
        from eth_account import Account

        signable = self._signable(**kw)
        signed = Account.sign_message(signable, private_key=self._acct.key)
        # HexBytes.hex() is "0x"-prefixed on some versions, bare on others - normalise.
        sig = signed.signature.hex()
        return sig if sig.startswith("0x") else "0x" + sig

    # ------------------------------------------------------------------
    # Pay (talks to the SELLER)
    # ------------------------------------------------------------------

    def pay(
        self,
        seller_url: str,
        *,
        body: dict[str, Any] | None = None,
        method: str = "POST",
    ) -> dict[str, Any]:
        """Run the full x402 flow against ``seller_url`` and return the result.

        Returns ``{status, data, payment_response?}``. If the first request is not
        a 402 (resource is free or errored), returns it as-is without paying.
        """
        with httpx.Client(timeout=self._timeout) as c:
            r0 = c.request(method, seller_url, json=body)
            if r0.status_code != 402:
                return {"status": r0.status_code, "data": _safe_json(r0), "paid": False}
            pr = r0.headers.get(HEADER_PAYMENT_REQUIRED)
            if not pr:
                raise BuyerError("seller returned 402 without a PAYMENT-REQUIRED header")
            offer = decode_header(pr)
            req = _pick_requirements(offer.get("accepts", []), self.network)
            payment = self.build_payment(req, resource=offer.get("resource"))
            headers = {HEADER_PAYMENT_SIGNATURE: encode_header(payment)}
            r1 = c.request(method, seller_url, json=body, headers=headers)
            out: dict[str, Any] = {
                "status": r1.status_code, "data": _safe_json(r1),
                "paid": r1.status_code == 200,
            }
            pres = r1.headers.get(HEADER_PAYMENT_RESPONSE)
            if pres:
                out["payment_response"] = decode_header(pres)
            return out

    def precheck(self, requirements: dict[str, Any]) -> dict[str, Any]:
        """Validate our signature via Gateway ``/v1/x402/verify`` WITHOUT paying.

        Gateway checks signature/format here (balance + nonce are only checked at
        settle), so this confirms the signing domain is right for ~free before we
        deposit or spend. Returns Gateway's verify result.
        """
        payment = self.build_payment(requirements)
        with httpx.Client(timeout=self._timeout) as c:
            r = c.post(
                self.gateway_url + "/v1/x402/verify",
                json={"paymentPayload": payment, "paymentRequirements": requirements},
            )
            return _safe_json(r)

    # ------------------------------------------------------------------
    # One-time setup: deposit + balance
    # ------------------------------------------------------------------

    def gateway_balance(self) -> dict[str, Any]:
        """Query this buyer's unified Gateway USDC balance (``POST /v1/balances``)."""
        domain = _DOMAIN_BY_NETWORK.get(self.network)
        if domain is None:
            raise BuyerError(f"no Gateway domain id known for network {self.network!r}")
        with httpx.Client(timeout=self._timeout) as c:
            r = c.post(
                self.gateway_url + "/v1/balances",
                json={"token": "USDC", "sources": [{"domain": domain, "depositor": self.address}]},
            )
            r.raise_for_status()
            return r.json()

    def deposit(self, amount_atomic: int, *, usdc_address: str = ARC_TESTNET_USDC) -> dict[str, Any]:
        """One-time on-chain deposit of USDC into the Gateway Wallet.

        ``approve(GatewayWallet, amount)`` then ``deposit(usdc, amount)``. Gas is
        paid by this EOA (in USDC on Arc), so the key needs faucet USDC for both
        the deposit amount and gas. Returns the two tx hashes.
        """
        from web3 import Web3

        w3 = Web3(Web3.HTTPProvider(self.rpc_url, request_kwargs={"timeout": 30}))
        erc20 = w3.eth.contract(
            address=Web3.to_checksum_address(usdc_address),
            abi=[{"name": "approve", "type": "function", "stateMutability": "nonpayable",
                  "inputs": [{"name": "spender", "type": "address"}, {"name": "amount", "type": "uint256"}],
                  "outputs": [{"name": "", "type": "bool"}]}],
        )
        gateway = w3.eth.contract(
            address=Web3.to_checksum_address(GATEWAY_WALLET_ADDRESS),
            abi=[{"name": "deposit", "type": "function", "stateMutability": "nonpayable",
                  "inputs": [{"name": "token", "type": "address"}, {"name": "amount", "type": "uint256"}],
                  "outputs": []}],
        )
        approve_tx = self._send(w3, erc20.functions.approve(
            Web3.to_checksum_address(GATEWAY_WALLET_ADDRESS), amount_atomic))
        deposit_tx = self._send(w3, gateway.functions.deposit(
            Web3.to_checksum_address(usdc_address), amount_atomic))
        return {"approve_tx": approve_tx, "deposit_tx": deposit_tx}

    def _send(self, w3: Any, fn: Any) -> str:
        from_addr = self.address
        tx = fn.build_transaction({
            "from": from_addr,
            "nonce": w3.eth.get_transaction_count(from_addr),
            "chainId": self.chain_id,
            "gasPrice": w3.eth.gas_price,
        })
        try:
            tx["gas"] = int(w3.eth.estimate_gas(tx) * 1.25)
        except Exception:
            tx["gas"] = 200_000
        signed = self._acct.sign_transaction(tx)
        raw = getattr(signed, "raw_transaction", None) or getattr(signed, "rawTransaction")
        h = w3.eth.send_raw_transaction(raw)
        w3.eth.wait_for_transaction_receipt(h, timeout=180)
        return "0x" + bytes(h).hex().removeprefix("0x")


def _safe_json(resp: httpx.Response) -> Any:
    try:
        return resp.json()
    except Exception:
        return {"raw": resp.text[:500]}


def _pick_requirements(accepts: list[dict[str, Any]], network: str) -> dict[str, Any]:
    """Pick the accepts[] entry for our network (else the first offered)."""
    if not accepts:
        raise BuyerError("seller's 402 listed no payment options")
    for a in accepts:
        if str(a.get("network")) == network:
            return a
    return accepts[0]


def main() -> None:
    from core.anchor.anchorer import load_env_file

    load_env_file()
    ap = argparse.ArgumentParser(description="x402 buyer (Circle Gateway Nanopayments)")
    ap.add_argument("cmd", choices=["pay", "balance", "deposit"], help="action")
    ap.add_argument("--url", help="seller URL (for pay)")
    ap.add_argument("--amount-usdc", type=float, default=1.0, help="USDC to deposit")
    ap.add_argument("--key", default=os.getenv("X402_PAYER_PRIVATE_KEY"),
                    help="buyer EOA private key (or X402_PAYER_PRIVATE_KEY)")
    ap.add_argument("--network", default=os.getenv("X402_NETWORK", "eip155:5042002"))
    a = ap.parse_args()
    if not a.key:
        raise SystemExit("set --key or X402_PAYER_PRIVATE_KEY (a funded EOA private key)")
    buyer = GatewayBuyer(a.key, network=a.network)
    print(f"[buyer] address={buyer.address} network={buyer.network}", flush=True)
    if a.cmd == "balance":
        print(json.dumps(buyer.gateway_balance(), indent=2))
    elif a.cmd == "deposit":
        units = int(round(a.amount_usdc * 1_000_000))
        print(f"[buyer] depositing {a.amount_usdc} USDC ({units} units) into Gateway...", flush=True)
        print(json.dumps(buyer.deposit(units), indent=2))
    elif a.cmd == "pay":
        if not a.url:
            raise SystemExit("pay needs --url <seller endpoint>")
        print(json.dumps(buyer.pay(a.url), indent=2))


if __name__ == "__main__":
    main()
