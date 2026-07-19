"""core.attest - ERC-8004 "Verified" attestations on Arc.

Entity-agnostic attestation layer: when the open verifier (core.verify)
returns a PASS verdict, publish a tamper-evident "Verified" badge into the
live ERC-8004 registries on Arc Testnet - a Validation response (validator
posts response=100, carrying our verdict digest) plus a Reputation feedback
entry (so the badge can be cleanly revoked via revokeFeedback).

The badge is NOT a token: the ERC-8004 Identity NFT (agentId) is a one-time
"passport" for the actor; the badge itself is a Validation/Reputation record
keyed to that agentId and authored only by our validator wallet, so it is
non-transferable by construction.

On-chain writes go through Circle DCW (core.circle.wallet); all writes are
performed by a dedicated validator wallet. This layer is isolated from the
trading agent; the anchor key is never used here.
"""

from __future__ import annotations

from core.attest import erc8004  # noqa: F401

__all__ = ["erc8004"]
