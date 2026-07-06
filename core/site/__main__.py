"""CLI: emit the public site snapshot from private live artifacts.

    python -m core.site --journal path/to/journal.jsonl \
        [--anchors path/to/journal.anchors.jsonl] \
        [--fills path/to/fills.jsonl] [--fills-cursor path/to/cursor.json] \
        [--events path/to/events.jsonl] [--actors actors.json] \
        [--candles candles.json] --out snapshot.json

Only ``--journal`` and ``--out`` are required; a missing optional input leaves
its snapshot section ``null`` (never fake data). When ``--fills`` is given
without ``--fills-cursor``, the capture module's default sidecar
(``<fills>.cursor.json``) is used if present.
"""

from __future__ import annotations

import argparse
import json
from typing import Any

from core.site.emitter import build_snapshot, emit_snapshot, load_jsonl


def _load_json(path: str) -> Any:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(
        prog="python -m core.site",
        description="Emit the public site snapshot.json (whitelist-redacted)",
    )
    ap.add_argument("--journal", required=True, help="VTR journal .jsonl path")
    ap.add_argument("--anchors", default=None, help="anchor manifest .jsonl path")
    ap.add_argument("--fills", default=None, help="fills archive .jsonl path")
    ap.add_argument("--fills-cursor", default=None,
                    help="fills cursor .json path (default: <fills>.cursor.json)")
    ap.add_argument("--events", default=None, help="telemetry events .jsonl path")
    ap.add_argument("--actors", default=None,
                    help="static actors .json to pass through (validated)")
    ap.add_argument("--candles", default=None,
                    help="candles .json: list of [ts,o,h,l,c] rows (validated)")
    ap.add_argument("--started-usd", type=float, default=None,
                    help="starting capital for agent.started_usd (and the APR base)")
    ap.add_argument("--metrics-from-fills", action="store_true",
                    help="recompute agent.metrics {apr,sharpe,dd} from the fills "
                         "archive (Stage-16 recompute; unlocks at >=3 trades)")
    ap.add_argument("--out", required=True, help="output snapshot.json path")
    a = ap.parse_args(argv)

    import os

    cursor_path = a.fills_cursor
    if cursor_path is None and a.fills is not None:
        candidate = a.fills + ".cursor.json"
        cursor_path = candidate if os.path.exists(candidate) else None

    snapshot = build_snapshot(
        journal_entries=load_jsonl(a.journal),
        anchor_records=load_jsonl(a.anchors) if a.anchors else None,
        fills=load_jsonl(a.fills) if a.fills else None,
        fills_cursor=_load_json(cursor_path) if cursor_path else None,
        events=load_jsonl(a.events) if a.events else None,
        actors=_load_json(a.actors) if a.actors else None,
        candles=_load_json(a.candles) if a.candles else None,
        started_usd=a.started_usd,
        metrics_from_fills=a.metrics_from_fills,
    )
    emit_snapshot(snapshot, a.out)

    tb, jr = snapshot["trust_band"], snapshot["journal"]
    feed = snapshot["feed"]
    print("=" * 72)
    print(f"  PUBLIC SNAPSHOT  chain={tb['chain_integrity']}  "
          f"entries={jr['entries']}  open_seals={jr['open_seals']}")
    print(f"  anchors arc={tb['anchors_arc']} btc={tb['anchors_btc']}  "
          f"decisions={tb['decisions']}  trades={tb['trades']}  "
          f"fills={tb['fills']}")
    print(f"  feed={'-' if feed is None else len(feed)} items  -> {a.out}")
    print("=" * 72, flush=True)


if __name__ == "__main__":
    main()
