"""VTR anchoring - bind the journal to public, unforgeable time (Stage 13).

Closes the Stage-12 *offline ceiling*: a journal can be re-chained from genesis
to hide a loss and still pass the integrity check. Anchoring publishes one
32-byte fingerprint of the chain to public ledgers at a real block timestamp, so
a re-mint cannot reproduce a value already recorded in a past block.

  * :class:`AnchorRecord` / :func:`build_anchor` - the pure, offline fingerprint
    (binds ``journal_head`` + ``batch_root`` + ``prev_anchor``).
  * :class:`ArcRawTxBackend` / :class:`OpenTimestampsBackend` - the two public
    rails (Arc-testnet raw tx + Bitcoin via OpenTimestamps).
  * :class:`Anchorer` - drives a round and writes the sidecar anchor manifest.
  * :func:`verify_anchors` - recompute the fingerprint from the journal and
    confirm it matches the manifest (and, live, the chains).

Entity-agnostic: anchors plain journal entries, knows nothing about trades.
"""

from core.anchor.anchorer import Anchorer, default_manifest_path, load_manifest
from core.anchor.bitcoin_verify import explorer_bitcoin_verify, upgrade_via_calendar
from core.anchor.backends import (
    AnchorBackend,
    AnchorReceipt,
    ArcRawTxBackend,
    OpenTimestampsBackend,
)
from core.anchor.record import (
    ANCHOR_MAGIC,
    ANCHOR_SCHEMA,
    AnchorRecord,
    anchor_calldata,
    build_anchor,
    parse_anchor_calldata,
)
from core.anchor.verify import AnchorVerifyReport, verify_anchors

__all__ = [
    "AnchorRecord",
    "ANCHOR_SCHEMA",
    "ANCHOR_MAGIC",
    "anchor_calldata",
    "parse_anchor_calldata",
    "build_anchor",
    "AnchorBackend",
    "AnchorReceipt",
    "ArcRawTxBackend",
    "OpenTimestampsBackend",
    "Anchorer",
    "default_manifest_path",
    "load_manifest",
    "verify_anchors",
    "AnchorVerifyReport",
    "explorer_bitcoin_verify",
    "upgrade_via_calendar",
]
