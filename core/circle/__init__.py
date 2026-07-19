"""Circle Developer-Controlled Wallets client (the on-chain write path).

Thin async client for Circle's DCW REST API: wallet balances, USDC
transfers and arbitrary contract-execution transactions, with per-request
RSA-OAEP-SHA256 entity-secret encryption. Zero strategy logic: this module
only signs and submits what callers hand it.
"""

from core.circle.wallet import (  # noqa: F401
    CircleWallet,
    CircleWalletConfig,
    TxRequest,
    TxResult,
)
