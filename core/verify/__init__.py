"""Open verifier - recompute any track from public data, "don't trust, verify" (Stage 16).

The economic + on-chain layer on top of the journal (Stage 12) and anchor
(Stage 13) integrity checks. Given a journal, its anchor manifest, the venue's
public fills and the anchor address, it returns a single PASS/FAIL:

  * :func:`recompute_from_fills` - P&L / Sharpe / drawdown recomputed
    independently from public venue fills.
  * :func:`crosscheck` - the journal's claimed P&L vs that recompute (catches an
    anchored, internally-consistent journal with inflated *outcomes*).
  * :func:`verify_anchor_history` - enumerate every anchor tx from the anchor
    address on-chain; flag any the manifest omits (closes the re-mint boundary).
  * :func:`open_verify` - the orchestrator that composes all of the above with
    the Stage-12 / Stage-13 verifiers into one verdict.

Entity-agnostic: reads plain journal + fill dicts, knows nothing about trading.
"""

from core.verify.anchor_history import (
    AnchorHistoryReport,
    AnchorTxProvider,
    BlockscoutProvider,
    OnchainAnchorTx,
    verify_anchor_history,
)
from core.verify.crosscheck import (
    ClaimedTrade,
    CrosscheckReport,
    TradeMatch,
    crosscheck,
    extract_claimed_trades,
)
from core.verify.fills_pnl import (
    RecomputedTrade,
    RecomputeReport,
    recompute_from_fills,
    reconstruct_trades,
)
from core.verify.verify import OpenVerifyReport, open_verify

__all__ = [
    "recompute_from_fills",
    "reconstruct_trades",
    "RecomputeReport",
    "RecomputedTrade",
    "crosscheck",
    "extract_claimed_trades",
    "CrosscheckReport",
    "ClaimedTrade",
    "TradeMatch",
    "verify_anchor_history",
    "AnchorHistoryReport",
    "AnchorTxProvider",
    "BlockscoutProvider",
    "OnchainAnchorTx",
    "open_verify",
    "OpenVerifyReport",
]
