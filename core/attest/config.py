"""Wiring: build the AttestClient (two Circle DCW wallets) from environment.

Env vars (all in .env, gitignored):
    CIRCLE_API_KEY, CIRCLE_ENTITY_SECRET        - shared Circle credentials
    ATTEST_OWNER_WALLET_ID / _ADDRESS           - OWNER wallet (registers, requests)
    ATTEST_VALIDATOR_WALLET_ID / _ADDRESS       - VALIDATOR wallet (responds, feedback)
    ATTEST_ENDPOINT_URL                         - our public /verify URL (optional)
    ATTEST_EVIDENCE_URI                         - public evidence pointer (optional)

Default state is DRY-RUN; the live path is opt-in (``dry_run=False``).
"""

from __future__ import annotations

import os
import pathlib

from core.attest.client import AttestClient, AttestConfig
from core.circle.wallet import CircleWallet, CircleWalletConfig


def load_dotenv(path: str = ".env") -> None:
    """Populate os.environ from .env for any key not already set (idempotent,
    no external dependency). Existing environment values win."""
    p = pathlib.Path(path)
    if not p.exists():
        return
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        key = key.strip()
        if key and key not in os.environ:
            os.environ[key] = val.strip().strip('"').strip("'")


def default_identity_map_path() -> str:
    return os.getenv("ATTEST_IDENTITY_MAP", "data/attest_identity.jsonl")


def default_registry_path() -> str:
    return os.getenv("ATTEST_REGISTRY", "data/attest_registry.jsonl")


def _wallet(wallet_id: str, dry_run: bool) -> CircleWallet:
    return CircleWallet(
        CircleWalletConfig(
            api_key=os.getenv("CIRCLE_API_KEY", ""),
            wallet_id=wallet_id,
            entity_secret=os.getenv("CIRCLE_ENTITY_SECRET"),
        ),
        dry_run=dry_run,
    )


def build_attest_client(*, dry_run: bool = True, with_reader: bool = False) -> AttestClient:
    """Construct an AttestClient from env. ``with_reader`` attaches a live
    Web3ChainReader (used on the live path for receipt parsing + read-back)."""
    load_dotenv()
    owner_id = os.getenv("ATTEST_OWNER_WALLET_ID", "")
    validator_id = os.getenv("ATTEST_VALIDATOR_WALLET_ID", "")
    cfg = AttestConfig(
        dry_run=dry_run,
        owner_address=os.getenv("ATTEST_OWNER_ADDRESS", ""),
        validator_address=os.getenv("ATTEST_VALIDATOR_ADDRESS", ""),
        endpoint_url=os.getenv("ATTEST_ENDPOINT_URL", ""),
    )
    reader = None
    if with_reader:
        from core.attest.chain import Web3ChainReader

        reader = Web3ChainReader(owner_address=cfg.owner_address)
    return AttestClient(
        owner=_wallet(owner_id, dry_run),
        validator=_wallet(validator_id, dry_run),
        config=cfg,
        chain_reader=reader,
    )


def evidence_uri() -> str:
    """Public evidence pointer stamped into the badge URIs (points at our
    anchored evidence / verify endpoint)."""
    return os.getenv("ATTEST_EVIDENCE_URI") or os.getenv("ATTEST_ENDPOINT_URL", "")
