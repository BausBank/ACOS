"""Redaction layer for the public snapshot (whitelist + defense-in-depth).

The snapshot emitter (:mod:`core.site.emitter`) NEVER passes a raw private
record (journal entry, telemetry event, fill) through to the public JSON - it
rebuilds every public object field-by-field from an explicit whitelist. This
module is the second line of defense behind that whitelist:

  * :data:`FORBIDDEN_KEY_SUBSTRINGS` - substrings that must not occur in ANY
    JSON key of the finished snapshot (commit salts, pending secrets, and the
    strategy's internal signal vocabulary: confidence / gate scores / sizing
    factors). :func:`assert_public` walks the built snapshot and raises if one
    slips through, so a future emitter bug fails CLOSED (no file written)
    instead of leaking.
  * Free-text sanitisation - raw "why" strings from telemetry carry internal
    scores like ``"confluence 3/4"``. Public text is NEVER taken from a raw
    string: skip and exit reasons are mapped through the fixed tables below to
    generic plain-English phrases, and :func:`assert_public` additionally
    rejects any output text matching a ``N/M`` score pattern.

Entity-agnostic and stdlib-only: it walks plain JSON values and knows nothing
about trading.
"""

from __future__ import annotations

import re
from typing import Any

# Substrings that must never occur in a JSON key of the public snapshot.
# Covers commit secrets ("salt", "pending") and the strategy's internal signal
# vocabulary (entry gates, conviction scores, sizing inputs).
FORBIDDEN_KEY_SUBSTRINGS = frozenset({
    "salt",
    "pending",
    "confidence",
    "direction_strength",
    "volatility_pct",
    "size_factor",
    "entry_check",
    "block_reason",
    "htf_align",
    "pullback",
    "structure",
    "adx",
    "score",
    "threshold",
    "ev_",
    "kelly",
    "atr",
})

# "3/4"-style internal gate scores must never appear in public text.
SCORE_PATTERN = re.compile(r"\d+\s*/\s*\d+")

# Fixed table: private skip/block reason code -> generic public phrase. The
# raw code (and the raw free-text "why") stays private; anything unknown maps
# to the most generic phrase rather than passing through.
_SKIP_PHRASE = {
    "confluence": "signal not strong enough",
    "no_signal": "signal not strong enough",
    "regime_chaos": "market too wild",
    "range_standdown": "stood down",
    "short_regime_gate": "stood down",
    "range_meanrev": "stood down",
    "no_atr": "stood down",
    "risk_off": "stood down",
}
_SKIP_DEFAULT = "stood down"

# Fixed table: exit reason code -> plain-English public phrase.
_EXIT_PHRASE = {
    "stop_loss": "hit safety exit",
    "trailing_stop": "trailing exit",
    "take_profit": "hit profit target",
    "partial_take_profit": "banked part of the trade",
    "time_exit": "time limit",
    "side_flip": "trend reversed",
    "daily_dd_guard": "daily loss limit",
    "risk_off": "engine risk-off",
    "vol_spike_close": "volatility spike",
    "re_evaluation": "conviction collapsed",
    "native_stop": "venue-side exit",
}
_EXIT_DEFAULT = "closed"


# Exact output keys ALLOWED despite containing a forbidden substring.
# ``anchors_*_pending`` count public anchor RECEIPT STATUSES from the manifest
# (e.g. an OpenTimestamps proof still awaiting its Bitcoin block) - nothing to
# do with the ``.pending.jsonl`` commit-secret sidecar that the "pending"
# substring guards against. EXACT match only: any other key containing
# "pending" still fails closed.
ALLOWED_EXACT_KEYS = frozenset({
    "anchors_arc_pending",
    "anchors_btc_pending",
})


class RedactionError(ValueError):
    """A private key / score pattern reached (or would reach) the public JSON."""


def sanitize_skip_reason(reason: str | None) -> str:
    """Map a private skip/block reason code to a generic public phrase.

    Unknown or missing codes map to the default phrase - never passed through.
    """
    return _SKIP_PHRASE.get(reason or "", _SKIP_DEFAULT)


def sanitize_exit_reason(reason: str | None) -> str:
    """Map a private exit reason code to a plain-English public phrase."""
    return _EXIT_PHRASE.get(reason or "", _EXIT_DEFAULT)


def _walk(obj: Any, path: str) -> None:
    if isinstance(obj, dict):
        for key, value in obj.items():
            key_l = str(key).lower()
            if key_l not in ALLOWED_EXACT_KEYS:
                for bad in FORBIDDEN_KEY_SUBSTRINGS:
                    if bad in key_l:
                        raise RedactionError(
                            f"forbidden key substring {bad!r} in key {key!r} at {path}"
                        )
            _walk(value, f"{path}.{key}")
    elif isinstance(obj, (list, tuple)):
        for i, value in enumerate(obj):
            _walk(value, f"{path}[{i}]")
    elif isinstance(obj, str):
        if SCORE_PATTERN.search(obj):
            raise RedactionError(
                f"score-like pattern (N/M) in public text at {path}: {obj!r}"
            )


def assert_public(obj: Any) -> None:
    """Assert ``obj`` (a built snapshot or a passthrough section) is publishable.

    Walks every nested dict/list and raises :class:`RedactionError` when any
    JSON key contains a forbidden substring, or any string value contains an
    ``N/M`` score-like pattern. Called on the finished snapshot AND on any
    operator-supplied passthrough (actors) before it is accepted.
    """
    _walk(obj, "$")


__all__ = [
    "FORBIDDEN_KEY_SUBSTRINGS",
    "ALLOWED_EXACT_KEYS",
    "SCORE_PATTERN",
    "RedactionError",
    "assert_public",
    "sanitize_skip_reason",
    "sanitize_exit_reason",
]
