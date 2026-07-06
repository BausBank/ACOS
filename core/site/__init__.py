"""Public snapshot emitter - private live artifacts in, one whitelisted JSON out.

The bridge between the private runtime artifacts (VTR journal, anchor manifest,
fills archive, telemetry events) and the static public site: it emits a single
``snapshot.json`` whose every field is rebuilt from an explicit whitelist.

  * :func:`build_snapshot` / :func:`emit_snapshot` - build + atomically write
    the snapshot (chain integrity is a real ``verify_journal`` call).
  * :mod:`core.site.redact` - the redaction layer: forbidden-key-substring +
    score-pattern assertions (fail closed) and the fixed reason-phrase tables.

Read-only over the inputs, stdlib-only, entity-agnostic. CLI::

    python -m core.site --journal J.jsonl [--anchors A.jsonl] [--fills F.jsonl]
        [--fills-cursor C.json] [--events E.jsonl] [--actors X.json]
        [--candles K.json] --out snapshot.json
"""

from core.site.emitter import (
    FEED_MAX_ITEMS,
    SNAPSHOT_SCHEMA,
    build_snapshot,
    emit_snapshot,
    load_jsonl,
)
from core.site.redact import (
    FORBIDDEN_KEY_SUBSTRINGS,
    RedactionError,
    assert_public,
    sanitize_exit_reason,
    sanitize_skip_reason,
)

__all__ = [
    "SNAPSHOT_SCHEMA",
    "FEED_MAX_ITEMS",
    "build_snapshot",
    "emit_snapshot",
    "load_jsonl",
    "FORBIDDEN_KEY_SUBSTRINGS",
    "RedactionError",
    "assert_public",
    "sanitize_skip_reason",
    "sanitize_exit_reason",
]
