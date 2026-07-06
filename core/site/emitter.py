"""Public snapshot emitter - one whitelisted ``snapshot.json`` from private artifacts.

Reads the private live artifacts (VTR journal JSONL, anchor manifest JSONL,
fills archive JSONL + cursor, telemetry events JSONL) and builds ONE public
JSON document for the static site. Trust-first design:

  * every number in the trust band is derived from a REAL check - chain
    integrity is a live :func:`core.journal.verify.verify_journal` call, anchor
    counts come from the manifest receipts, never hardcoded;
  * every public object is rebuilt field-by-field from an explicit whitelist -
    a raw journal entry / telemetry event dict is never passed through;
  * the finished snapshot is walked by :func:`core.site.redact.assert_public`
    (forbidden key substrings, ``N/M`` score patterns) so an emitter bug fails
    CLOSED instead of leaking a commit salt or an internal signal score;
  * a missing optional input yields ``null`` for its section - never fake data.

Entity-agnostic and stdlib-only: reads plain JSON records, knows the journal's
commit/reveal envelope but nothing about how decisions are made.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any

from core.journal.verify import verify_journal
from core.site.redact import (
    RedactionError,
    assert_public,
    sanitize_exit_reason,
    sanitize_skip_reason,
)

SNAPSHOT_SCHEMA = 1

# Feed cap: the public feed carries only the most recent slice.
FEED_MAX_ITEMS = 50

# Anchor backends -> receipt statuses that count as a published anchor.
# "arc-rawtx" reports ``submitted`` WITH a block once the tx landed on-chain
# (``confirmed`` after an explicit re-check); OpenTimestamps is ``pending``
# until a real Bitcoin block attests it, so only ``confirmed`` counts.
_ARC_BACKEND = "arc-rawtx"
_BTC_BACKEND = "opentimestamps"
_CONFIRMED_STATUSES = {
    _ARC_BACKEND: frozenset({"submitted", "confirmed"}),
    _BTC_BACKEND: frozenset({"confirmed"}),
}

_FEED_KINDS = frozenset({
    "CYCLE", "NOTARIZED", "SEALED", "REVEALED", "OPENED",
    "CLOSED", "SKIPPED", "DAY_CLOSE", "SAFETY_EXIT",
})


# --------------------------------------------------------------------------- #
# small helpers                                                                #
# --------------------------------------------------------------------------- #
def _iso(dt: datetime) -> str:
    """ISO-8601 UTC, second precision, trailing Z (the repo-wide convention)."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(ts: str) -> datetime | None:
    try:
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


def _money(x: Any) -> str:
    """Whole-dollar amount with thousands separators: ``$1,240``."""
    return f"${float(x):,.0f}"


def _pnl(x: Any) -> str:
    """Signed P&L with cents: ``+$27.01`` / ``-$18.40``."""
    v = float(x)
    sign = "+" if v >= 0 else "-"
    return f"{sign}${abs(v):,.2f}"


def load_jsonl(path: str) -> list[dict[str, Any]]:
    """Read a JSONL file tolerantly (skip blank / torn lines).

    A torn FINAL line (power loss mid-write) is dropped exactly like the
    journal's own resume path does; a torn line in the MIDDLE of a journal
    surfaces honestly as a broken chain in ``verify_journal``.
    """
    out: list[dict[str, Any]] = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(rec, dict):
                out.append(rec)
    return out


# --------------------------------------------------------------------------- #
# section builders (each returns whitelisted public data only)                 #
# --------------------------------------------------------------------------- #
def _count_anchor_receipts(records: list[dict[str, Any]], backend: str) -> int:
    """Count receipts of ``backend`` whose status means "actually published"."""
    ok_statuses = _CONFIRMED_STATUSES.get(backend, frozenset())
    n = 0
    for rec in records:
        for receipt in rec.get("receipts") or []:
            if receipt.get("backend") != backend:
                continue
            if receipt.get("status") not in ok_statuses:
                continue
            if backend == _ARC_BACKEND and receipt.get("block") is None:
                continue  # submitted but no block yet -> not on-chain
            n += 1
    return n


def _count_pending_receipts(records: list[dict[str, Any]], backend: str) -> int:
    """Count receipts of ``backend`` that are published but not yet confirmed:
    status ``pending`` (e.g. an OTS proof awaiting its Bitcoin block), or - for
    Arc - ``submitted`` without a block number. Surfaced so the site can
    honestly show "BTC: N PENDING" instead of a bare confirmed count of 0."""
    n = 0
    for rec in records:
        for receipt in rec.get("receipts") or []:
            if receipt.get("backend") != backend:
                continue
            status = receipt.get("status")
            if status == "pending" or (
                backend == _ARC_BACKEND and status == "submitted"
                and receipt.get("block") is None
            ):
                n += 1
    return n


def _arc_tx_ref(rec: dict[str, Any]) -> Any:
    """The Arc receipt's tx hash (``ref``) of one anchor record, or None."""
    for receipt in rec.get("receipts") or []:
        if receipt.get("backend") == _ARC_BACKEND and receipt.get("ref"):
            return receipt["ref"]
    return None


def _extract_anchor_address(records: list[dict[str, Any]]) -> Any:
    """The anchoring EOA address, taken ONLY from the manifest receipts'
    ``detail`` dicts (public by design: Stage 16 enumerates this address's txs
    on-chain). Newest occurrence wins; None when no receipt carries it."""
    addr = None
    for rec in records:
        for receipt in rec.get("receipts") or []:
            if receipt.get("backend") != _ARC_BACKEND:
                continue
            detail = receipt.get("detail") or {}
            for key in ("from", "sender", "address"):
                if detail.get(key):
                    addr = detail[key]
                    break
    return addr


def _build_trust_band(
    entries: list[dict[str, Any]],
    report: Any,
    anchor_records: list[dict[str, Any]] | None,
    fills: list[dict[str, Any]] | None,
    fills_cursor: dict[str, Any] | None,
    now: datetime,
) -> dict[str, Any]:
    genesis_ts = entries[0].get("ts") if entries else None
    track_age_days = None
    genesis_dt = _parse_iso(genesis_ts) if genesis_ts else None
    if genesis_dt is not None:
        track_age_days = max(0, int((now - genesis_dt).total_seconds() // 86400))

    decision_ts: list[str] = [
        e["ts"] for e in entries
        if e.get("kind") == "commit"
        or (e.get("kind") == "event" and e.get("ref") == "skip")
    ]

    fills_count: int | None = None
    if fills_cursor is not None and fills_cursor.get("n_total") is not None:
        fills_count = int(fills_cursor["n_total"])
    elif fills is not None:
        fills_count = len(fills)

    anchors_arc: int | None = None
    anchors_btc: int | None = None
    anchors_arc_pending: int | None = None
    anchors_btc_pending: int | None = None
    last_anchor_ts: str | None = None
    last_anchor_tx: Any = None
    anchor_address: Any = None
    if anchor_records is not None:
        anchors_arc = _count_anchor_receipts(anchor_records, _ARC_BACKEND)
        anchors_btc = _count_anchor_receipts(anchor_records, _BTC_BACKEND)
        anchors_arc_pending = _count_pending_receipts(anchor_records, _ARC_BACKEND)
        anchors_btc_pending = _count_pending_receipts(anchor_records, _BTC_BACKEND)
        anchor_address = _extract_anchor_address(anchor_records)
        if anchor_records:
            last_anchor_ts = anchor_records[-1].get("ts")
            last_anchor_tx = _arc_tx_ref(anchor_records[-1])

    return {
        "chain_integrity": "PASS" if report.ok else "FAIL",
        "genesis_ts": genesis_ts,
        "track_age_days": track_age_days,
        "anchors_arc": anchors_arc,
        "anchors_btc": anchors_btc,
        "anchors_arc_pending": anchors_arc_pending,
        "anchors_btc_pending": anchors_btc_pending,
        "last_anchor_ts": last_anchor_ts,
        "last_anchor_tx": last_anchor_tx,
        "anchor_address": anchor_address,
        "decisions": report.n_commits + sum(
            1 for e in entries
            if e.get("kind") == "event" and e.get("ref") == "skip"
        ),
        "trades": report.n_reveals,
        "fills": fills_count,
        "last_decision_ts": decision_ts[-1] if decision_ts else None,
    }


def _build_journal_section(
    entries: list[dict[str, Any]], report: Any
) -> dict[str, Any]:
    commit_ts = [e["ts"] for e in entries if e.get("kind") == "commit"]
    return {
        "entries": report.n_entries,
        "head_hash_prefix": (report.head or "")[:8],
        "open_seals": report.open_commits,
        "last_seal_ts": commit_ts[-1] if commit_ts else None,
    }


def _fingerprint_prefix(raw: Any) -> str:
    """Public fingerprint prefix: strip a leading ``cfg-`` tag, then first 8
    chars - so ``cfg-9cad40e9`` shows as ``9cad40e9`` (the hex, not the tag)."""
    s = str(raw or "")
    if s.startswith("cfg-"):
        s = s[4:]
    return s[:8]


def _build_metrics_from_fills(
    fills: list[dict[str, Any]] | None,
    started_usd: float | None,
) -> dict[str, Any]:
    """Recompute {apr, sharpe, dd} from the fills archive via the Stage-16
    verifier (:func:`core.verify.fills_pnl.recompute_from_fills` - reused, not
    reimplemented). Site rule: metrics unlock at >= 3 closed round-trips; below
    that (or with no fills / no capital base for the ratio metrics) the fields
    stay null - never fake data.
    """
    metrics: dict[str, Any] = {"apr": None, "sharpe": None, "dd": None}
    if not fills:
        return metrics
    from core.verify.fills_pnl import recompute_from_fills

    rep = recompute_from_fills(fills, equity_start=started_usd)
    if rep.n_trades < 3:
        return metrics
    if rep.sharpe is not None:
        metrics["sharpe"] = round(rep.sharpe, 2)
    if rep.max_drawdown_pct is not None:
        metrics["dd"] = round(rep.max_drawdown_pct, 1)
    # APR: net realised P&L annualised over the archive's time span, measured
    # against the starting capital. Needs both a capital base and a non-zero
    # span; otherwise it stays null (a ratio with no base is not a number).
    if started_usd is not None and started_usd > 0 and rep.window:
        start_dt, end_dt = _parse_iso(rep.window[0]), _parse_iso(rep.window[1])
        if start_dt is not None and end_dt is not None:
            span_days = (end_dt - start_dt).total_seconds() / 86400.0
            if span_days > 0:
                metrics["apr"] = round(
                    rep.net_pnl / started_usd * (365.0 / span_days) * 100.0, 1
                )
    return metrics


def _build_agent_section(
    entries: list[dict[str, Any]],
    *,
    started_usd: float | None,
    metrics: dict[str, Any],
) -> dict[str, Any]:
    manifest: dict[str, Any] | None = None
    for e in entries:
        if e.get("kind") == "manifest":
            body = e.get("body") or {}
            manifest = {
                "actor": body.get("actor"),
                "strategy": body.get("strategy"),
                "strategy_version": body.get("strategy_version"),
                "config_fingerprint": _fingerprint_prefix(body.get("config_fingerprint")),
                "mode": body.get("mode"),
            }
            break
    return {
        "started_usd": started_usd,
        "manifest": manifest,
        "metrics": metrics,
    }


def _reveal_final(outcome: dict[str, Any]) -> tuple[dict[str, Any], Any]:
    """The terminal leg + total P&L of a reveal outcome (handles the
    partial-take-profit shape ``{final, partials, net_profit_usd_total}``)."""
    final = outcome.get("final") if isinstance(outcome.get("final"), dict) else None
    if final is not None:
        return final, outcome.get("net_profit_usd_total", final.get("net_profit_usd"))
    return outcome, outcome.get("net_profit_usd")


def _coin(symbol: Any) -> Any:
    """``BTC-PERP`` -> ``BTC`` (public display name)."""
    if isinstance(symbol, str) and "-" in symbol:
        return symbol.split("-", 1)[0]
    return symbol


def _build_last_trade(entries: list[dict[str, Any]]) -> dict[str, Any] | None:
    reveal = None
    for e in entries:
        if e.get("kind") == "reveal":
            reveal = e
    if reveal is None:
        return None
    body = reveal.get("body") or {}
    payload = body.get("payload") or {}
    outcome = body.get("outcome") or {}
    final, pnl = _reveal_final(outcome)
    commit_hash = None
    for e in entries:
        if e.get("kind") == "commit" and e.get("ref") == reveal.get("ref"):
            commit_hash = (e.get("body") or {}).get("commit_hash")
            break
    return {
        "ts": reveal.get("ts"),
        "coin": _coin(payload.get("symbol")),
        "side": payload.get("side"),
        "size_usd": payload.get("size_usd"),
        "held_hours": final.get("held_hours"),
        "exit_reason": sanitize_exit_reason(final.get("exit_reason")),
        "pnl_usd": pnl,
        "peak_pnl_usd": None,
        "decision_id": reveal.get("ref"),
        "commit_hash_prefix": (commit_hash or "")[:8] or None,
        "seq": reveal.get("seq"),
    }


# -- feed ------------------------------------------------------------------- #
def _feed_item(
    ts: Any, kind: str, text: str, *,
    symbol: Any = None, decision_id: Any = None, refs: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Assemble one feed item from WHITELISTED values only (never a raw dict)."""
    item: dict[str, Any] = {"ts": ts, "kind": kind}
    if symbol is not None:
        item["symbol"] = symbol
    item["text"] = text
    if decision_id is not None:
        item["decision_id"] = decision_id
    if refs:
        item["refs"] = refs
    return item


def _feed_from_event(ev: dict[str, Any]) -> dict[str, Any] | None:
    """Rebuild ONE public feed item from a private telemetry event, or None
    for event types that stay private (run bookkeeping, errors, raw intents)."""
    etype = ev.get("event")
    ts = ev.get("time")
    if etype == "cycle":
        kind = "DAY_CLOSE" if str(ts).endswith("T00:00:00Z") else "CYCLE"
        text = (
            f"account {_money(ev.get('equity_usd', 0.0))} · "
            f"{int(ev.get('open_positions', 0))} open · "
            f"{int(ev.get('n_trades', 0))} trades"
        )
        return _feed_item(ts, kind, text)
    if etype == "decision" and ev.get("action") in ("block", "risk_off"):
        reason = ev.get("block_reason") if ev.get("action") == "block" else "risk_off"
        return _feed_item(
            ts, "SKIPPED", sanitize_skip_reason(reason), symbol=ev.get("symbol")
        )
    if etype == "open":
        text = f"opened {ev.get('side')} · {_money(ev.get('size_usd', 0.0))}"
        return _feed_item(
            ts, "OPENED", text,
            symbol=ev.get("symbol"), decision_id=ev.get("decision_id"),
        )
    if etype == "close":
        kind = "SAFETY_EXIT" if ev.get("exit_reason") == "stop_loss" else "CLOSED"
        text = (
            f"closed {ev.get('side')} · "
            f"{sanitize_exit_reason(ev.get('exit_reason'))} · "
            f"{_pnl(ev.get('net_profit_usd', 0.0))}"
        )
        return _feed_item(
            ts, kind, text,
            symbol=ev.get("symbol"), decision_id=ev.get("decision_id"),
        )
    return None


def _anchor_refs(rec: dict[str, Any]) -> dict[str, Any]:
    refs: dict[str, Any] = {}
    for receipt in rec.get("receipts") or []:
        backend, block = receipt.get("backend"), receipt.get("block")
        if backend == _ARC_BACKEND and receipt.get("ref") and "arc_tx" not in refs:
            refs["arc_tx"] = receipt["ref"]   # explorer-linkable tx hash
        if block is None:
            continue
        if backend == _ARC_BACKEND and "arc_block" not in refs:
            refs["arc_block"] = block
        elif backend == _BTC_BACKEND and "btc_block" not in refs:
            refs["btc_block"] = block
    return refs


def _build_feed(
    events: list[dict[str, Any]],
    entries: list[dict[str, Any]],
    anchor_records: list[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    """Merge telemetry events + journal seals/reveals + anchor notarisations
    into one chronological feed, newest first, capped at FEED_MAX_ITEMS."""
    staged: list[tuple[str, int, int, dict[str, Any]]] = []

    for i, ev in enumerate(events):
        item = _feed_from_event(ev)
        if item is not None:
            staged.append((str(item["ts"]), 0, i, item))

    for i, e in enumerate(entries):
        kind, ts, ref = e.get("kind"), e.get("ts"), e.get("ref")
        if kind == "commit":
            prefix = ((e.get("body") or {}).get("commit_hash") or "")[:8]
            item = _feed_item(
                ts, "SEALED", f"decision sealed pre-outcome · {prefix}",
                decision_id=ref,
            )
            staged.append((str(ts), 1, i, item))
        elif kind == "reveal":
            body = e.get("body") or {}
            final, pnl = _reveal_final(body.get("outcome") or {})
            text = "outcome revealed"
            if pnl is not None:
                text += f" · {_pnl(pnl)}"
            item = _feed_item(
                ts, "REVEALED", text,
                symbol=(body.get("payload") or {}).get("symbol"), decision_id=ref,
            )
            staged.append((str(ts), 1, i, item))

    for i, rec in enumerate(anchor_records or []):
        ts = rec.get("ts")
        item = _feed_item(
            ts, "NOTARIZED",
            f"anchor #{rec.get('anchor_no')} notarized on-chain",
            refs=_anchor_refs(rec),
        )
        staged.append((str(ts), 2, i, item))

    # ISO-8601 UTC strings sort chronologically as plain strings; the
    # (priority, index) tiebreak keeps the merge deterministic.
    staged.sort(key=lambda t: (t[0], t[1], t[2]))
    newest_first = [item for _, _, _, item in staged][-FEED_MAX_ITEMS:]
    newest_first.reverse()
    return newest_first


def _build_market_mood(events: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Public market read from the LATEST cycle event's per-bar reason counts -
    the same counts the human feed line already summarises ("2 TRENDING ·
    7 SIDEWAYS"). No strategy internals: only the plain-English regime label.

    Majority of the three public buckets wins (trending = tradeable-regime
    passes: confluence + short_regime_gate + range_meanrev; sideways =
    range_standdown; wild = regime_chaos); a tie reads SIDEWAYS. No cycle
    event, or no regime counts at all -> None (never invented).
    """
    latest = None
    for ev in events:
        if ev.get("event") == "cycle":
            latest = ev
    if latest is None:
        return None
    counts = latest.get("blocked") or {}
    trending = (counts.get("confluence", 0) + counts.get("short_regime_gate", 0)
                + counts.get("range_meanrev", 0))
    sideways = counts.get("range_standdown", 0)
    wild = counts.get("regime_chaos", 0)
    if trending == sideways == wild == 0:
        return None  # the latest cycle carries no regime information
    best = max(trending, sideways, wild)
    winners = [label for label, n in (("TRENDING", trending),
                                      ("SIDEWAYS", sideways),
                                      ("WILD", wild)) if n == best]
    return {
        "regime": winners[0] if len(winners) == 1 else "SIDEWAYS",
        "as_of": latest.get("time"),
    }


def _validate_candles(raw: Any) -> list[list[Any]]:
    """Validate + rebuild an operator-supplied candle list ``[ts,o,h,l,c]``.

    Rebuilt element-by-element (never passed through) so extra columns or
    non-numeric junk can never ride along into the public file.
    """
    if not isinstance(raw, list):
        raise RedactionError("candles must be a JSON list of [ts,o,h,l,c] rows")
    out: list[list[Any]] = []
    for i, row in enumerate(raw):
        if not isinstance(row, (list, tuple)) or len(row) < 5:
            raise RedactionError(f"candle row {i} is not a [ts,o,h,l,c] list")
        ts = row[0]
        if not isinstance(ts, (int, float, str)):
            raise RedactionError(f"candle row {i}: bad timestamp {ts!r}")
        try:
            o, h, l, c = (float(v) for v in row[1:5])
        except (TypeError, ValueError) as exc:
            raise RedactionError(f"candle row {i}: non-numeric OHLC") from exc
        out.append([ts, o, h, l, c])
    return out


# --------------------------------------------------------------------------- #
# top-level build + emit                                                       #
# --------------------------------------------------------------------------- #
def build_snapshot(
    *,
    journal_entries: list[dict[str, Any]],
    anchor_records: list[dict[str, Any]] | None = None,
    fills: list[dict[str, Any]] | None = None,
    fills_cursor: dict[str, Any] | None = None,
    events: list[dict[str, Any]] | None = None,
    actors: Any = None,
    candles: Any = None,
    started_usd: float | None = None,
    metrics_from_fills: bool = False,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Build the public snapshot dict from pre-loaded private artifacts.

    Only ``journal_entries`` is required; every ``None`` optional input yields
    ``null`` for its section (never fake data). ``started_usd`` fills
    ``agent.started_usd``; ``metrics_from_fills=True`` (with a fills archive)
    recomputes ``agent.metrics`` via the Stage-16 verifier. The finished
    snapshot is checked by :func:`core.site.redact.assert_public` and the call
    raises :class:`core.site.redact.RedactionError` instead of returning a
    leaky dict.
    """
    now = now or datetime.now(timezone.utc)
    report = verify_journal(journal_entries)

    if actors is not None:
        assert_public(actors)  # passthrough allowed only if provably clean

    metrics = (
        _build_metrics_from_fills(fills, started_usd)
        if metrics_from_fills else {"apr": None, "sharpe": None, "dd": None}
    )

    snapshot: dict[str, Any] = {
        "meta": {"schema": SNAPSHOT_SCHEMA, "generated_at": _iso(now)},
        "trust_band": _build_trust_band(
            journal_entries, report, anchor_records, fills, fills_cursor, now
        ),
        "journal": _build_journal_section(journal_entries, report),
        "agent": _build_agent_section(
            journal_entries, started_usd=started_usd, metrics=metrics
        ),
        "last_trade": _build_last_trade(journal_entries),
        "market_mood": (
            _build_market_mood(events) if events is not None else None
        ),
        "feed": (
            _build_feed(events, journal_entries, anchor_records)
            if events is not None else None
        ),
        "actors": actors,
        "candles": _validate_candles(candles) if candles is not None else None,
    }

    # real current capital: newest cycle event's equity (public in feed text
    # already; here as a number for the site's capital display)
    equity: float | None = None
    for ev in reversed(events or []):
        if ev.get("event") == "cycle" and ev.get("equity_usd") is not None:
            equity = round(float(ev["equity_usd"]), 2)
            break
    snapshot["agent"]["equity_usd"] = equity

    assert_public(snapshot)  # defense-in-depth: fail closed, never leak
    return snapshot


def emit_snapshot(snapshot: dict[str, Any], out_path: str) -> None:
    """Write the snapshot atomically (tmp + replace) as pretty-printed JSON."""
    out_dir = os.path.dirname(out_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    tmp = out_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(snapshot, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    os.replace(tmp, out_path)


__all__ = [
    "SNAPSHOT_SCHEMA",
    "FEED_MAX_ITEMS",
    "build_snapshot",
    "emit_snapshot",
    "load_jsonl",
]
