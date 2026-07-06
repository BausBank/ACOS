"""Cross-check the journal's CLAIMED P&L against the fills RECOMPUTE (Stage 16).

This is the economic tamper-catch that closes Stage-12's offline ceiling. The
chain verifier proves a journal is *un-edited*; the anchor verifier proves it was
*not re-minted*. But a reveal's ``outcome`` (the realised P&L) is added at reveal
time and is NOT sealed by the commit hash - so an actor who controls the whole
pipeline could re-chain AND re-anchor a journal whose decisions are honest but
whose *outcomes* are inflated, and pass both prior checks. The only thing that
catches that is recomputing the outcome from the venue's own public fills and
confirming the journal's claim matches. That is this module.

It compares two independently-derived views of the same track:

  * **Claimed** - parsed from the journal's ``reveal`` entries (one per closed
    decision). Net P&L = ``outcome.net_profit_usd`` (or, for a position closed in
    several legs, ``outcome.net_profit_usd_total``).
  * **Recomputed** - the round-trip trades + aggregate from
    :func:`core.verify.fills_pnl.recompute_from_fills` (public fills only).

Checks: an AGGREGATE total match within tolerance, plus a PER-TRADE match
(greedy by ``coin`` + ``direction`` + nearest open time) flagging any claimed
trade with no fills counterpart, any fills trade the journal omits, and any
per-trade P&L that disagrees beyond tolerance.

Tolerance is deliberately non-zero: the recompute excludes funding (a separate
venue ledger, out of ``userFills``) and both sides round, so a small residual is
expected and is NOT a tamper signal. A large, directional gap is. Defaults:
``abs_tol=$1.00`` + ``rel_tol=2%`` of the claimed magnitude, per trade and on the
aggregate. Entity-agnostic: it reads plain journal dicts and recomputed trades.

Pairing prerequisite (honest boundary): a meaningful cross-check needs the
journal and the fills to be the SAME track. A replay/backtest journal has no
public fills to match; running this against unrelated fills will (correctly)
diverge - that is "these do not pair", not "the track is verified". The verifier
reports ``applicable=False`` when either side is empty so a 0-trade live journal
passes trivially (and starts matching for real once trades land).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Sequence

from core.verify.fills_pnl import RecomputedTrade


def _coin_of(symbol: str) -> str:
    """'BTC-PERP' -> 'BTC' (the venue's fill ``coin``). Idempotent for bare coins."""
    return symbol.split("-", 1)[0] if symbol else symbol


@dataclass
class ClaimedTrade:
    """One closed decision as the journal claims it (parsed from a reveal)."""

    decision_id: str
    coin: str
    direction: str          # "long" | "short"
    open_ts: str | None     # commit timestamp (decision sealed), if found
    close_ts: str | None    # reveal timestamp (outcome known)
    net_pnl: float
    gross_pnl: float | None
    fee: float | None
    exit_reason: str | None


@dataclass
class TradeMatch:
    coin: str
    direction: str
    claimed_net: float
    recomputed_net: float
    diff: float
    within_tol: bool
    claim_id: str | None = None
    open_ts: str | None = None


@dataclass
class CrosscheckReport:
    ok: bool = True
    applicable: bool = True       # False when one side is empty (nothing to pair)
    n_claimed: int = 0
    n_recomputed: int = 0
    claimed_total: float = 0.0
    recomputed_total: float = 0.0
    aggregate_diff: float = 0.0
    aggregate_ok: bool = True
    matches: list[TradeMatch] = field(default_factory=list)
    unmatched_claimed: list[ClaimedTrade] = field(default_factory=list)
    unmatched_recomputed: list[RecomputedTrade] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)

    def summary(self) -> str:
        if not self.applicable:
            return (
                "  CROSS-CHECK (journal claim vs fills recompute) : N/A\n"
                f"    nothing to pair (claimed={self.n_claimed}, "
                f"recomputed={self.n_recomputed})"
            )
        verdict = "PASS" if self.ok else "FAIL"
        per_ok = sum(1 for m in self.matches if m.within_tol)
        lines = [
            f"  CROSS-CHECK (journal claim vs fills recompute) : {verdict}",
            f"  claimed total=${self.claimed_total:,.2f}  "
            f"recomputed total=${self.recomputed_total:,.2f}  "
            f"diff=${self.aggregate_diff:,.2f} ({'ok' if self.aggregate_ok else 'OVER TOL'})",
            f"  per-trade: {per_ok}/{len(self.matches)} within tol  "
            f"unmatched: claimed={len(self.unmatched_claimed)} "
            f"recomputed={len(self.unmatched_recomputed)}",
        ]
        if self.issues:
            lines.append(f"  issues ({len(self.issues)}):")
            lines.extend(f"    - {m}" for m in self.issues[:15])
        return "\n".join(lines)


def extract_claimed_trades(entries: Sequence[dict[str, Any]]) -> list[ClaimedTrade]:
    """Parse the journal's ``reveal`` entries into per-decision claimed P&L.

    Uses the matching ``commit`` entry's timestamp (same ``ref``) as the open
    time when present. Handles both a flat outcome and the partial-legs outcome
    ``{final, partials, net_profit_usd_total}`` written by the telemetry emitter.
    """
    commit_ts: dict[str, str] = {}
    for e in entries:
        if e.get("kind") == "commit":
            commit_ts[e.get("ref")] = e.get("ts")

    out: list[ClaimedTrade] = []
    for e in entries:
        if e.get("kind") != "reveal":
            continue
        body = e.get("body") or {}
        payload = body.get("payload") or {}
        outcome = body.get("outcome") or {}
        # Partial-legs vs flat outcome.
        if "net_profit_usd_total" in outcome:
            net = float(outcome.get("net_profit_usd_total"))
            final = outcome.get("final") or {}
            gross = final.get("profit_usd")
            fee = final.get("fee_usd")
            exit_reason = final.get("exit_reason")
        else:
            net = float(outcome.get("net_profit_usd", 0.0))
            gross = outcome.get("profit_usd")
            fee = outcome.get("fee_usd")
            exit_reason = outcome.get("exit_reason")
        ref = e.get("ref")
        symbol = payload.get("symbol") or outcome.get("symbol") or ""
        side = (payload.get("side") or outcome.get("side") or "").lower()
        out.append(ClaimedTrade(
            decision_id=ref,
            coin=_coin_of(symbol),
            direction="long" if side == "long" else "short",
            open_ts=commit_ts.get(ref),
            close_ts=e.get("ts"),
            net_pnl=net,
            gross_pnl=float(gross) if gross is not None else None,
            fee=float(fee) if fee is not None else None,
            exit_reason=exit_reason,
        ))
    return out


def _close(claimed_v: float, recomp_v: float, abs_tol: float, rel_tol: float) -> bool:
    """|claimed-recomputed| within ``max(abs_tol, rel_tol*|recomputed|)``.

    The tolerance scales to the INDEPENDENTLY-recomputed value (the trusted side),
    NOT ``max(|a|,|b|)`` - otherwise a forged claim could inflate its own
    tolerance (claim a huge number and the rel-tol grows to swallow the gap)."""
    return abs(claimed_v - recomp_v) <= max(abs_tol, rel_tol * abs(recomp_v))


def crosscheck(
    claimed: Sequence[ClaimedTrade],
    recomputed: Sequence[RecomputedTrade],
    *,
    abs_tol: float = 1.0,
    rel_tol: float = 0.02,
) -> CrosscheckReport:
    """Match claimed trades to recomputed trades and verify P&L agreement.

    ``recomputed`` should be the CLOSED round-trips (open episodes carry no
    realised result to match). Matching is greedy: for each claimed trade, take
    the unused recomputed trade with the same ``coin`` + ``direction`` whose open
    time is nearest.

    Applicability is driven by the CLAIMED side: a journal with no closed trades
    is genuinely "nothing to verify" (N/A). But if the journal DOES claim trades,
    the check runs even against EMPTY fills - so handing in no/empty fills cannot
    silently dodge it (every claim then lands as ``unmatched_claimed`` -> FAIL).
    """
    rep = CrosscheckReport(n_claimed=len(claimed), n_recomputed=len(recomputed))
    rep.claimed_total = round(sum(c.net_pnl for c in claimed), 6)
    rep.recomputed_total = round(sum(r.net_pnl for r in recomputed), 6)
    rep.aggregate_diff = round(rep.claimed_total - rep.recomputed_total, 6)

    # N/A only when there is nothing CLAIMED to verify (a 0-trade journal).
    if not claimed:
        rep.applicable = False
        return rep
    rep.applicable = True

    # Greedy per-trade matching by coin+direction, nearest open time.
    def _ms(ts: str | None) -> int:
        if not ts:
            return 0
        from datetime import datetime, timezone
        try:
            return int(datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")
                       .replace(tzinfo=timezone.utc).timestamp() * 1000)
        except ValueError:
            return 0

    pool = list(recomputed)
    for c in sorted(claimed, key=lambda c: _ms(c.open_ts)):
        cands = [r for r in pool if r.coin == c.coin and r.direction == c.direction]
        if not cands:
            rep.unmatched_claimed.append(c)
            rep.issues.append(
                f"claimed {c.coin} {c.direction} (${c.net_pnl:,.2f}) has no fills match"
            )
            continue
        c_ms = _ms(c.open_ts)
        best = min(cands, key=lambda r: abs(r.open_time_ms - c_ms))
        pool.remove(best)
        diff = round(c.net_pnl - best.net_pnl, 6)
        ok = _close(c.net_pnl, best.net_pnl, abs_tol, rel_tol)
        rep.matches.append(TradeMatch(
            coin=c.coin, direction=c.direction,
            claimed_net=round(c.net_pnl, 6), recomputed_net=round(best.net_pnl, 6),
            diff=diff, within_tol=ok, claim_id=c.decision_id, open_ts=c.open_ts,
        ))
        if not ok:
            rep.issues.append(
                f"per-trade mismatch {c.coin} {c.direction} @ {c.open_ts}: "
                f"claimed ${c.net_pnl:,.2f} vs recomputed ${best.net_pnl:,.2f}"
            )

    for r in pool:
        rep.unmatched_recomputed.append(r)
        rep.issues.append(
            f"fills show a {r.coin} {r.direction} trade (${r.net_pnl:,.2f}) the "
            "journal does not claim (omitted trade?)"
        )

    # Aggregate gate: TWO checks, so the per-trade floor cannot stack into free
    # fabrication and opposite-sign per-trade skims cannot cancel in the net.
    #   (a) net total within tol of the recomputed total;
    #   (b) the SUM OF ABSOLUTE per-trade discrepancies (incl. every unmatched
    #       trade at full magnitude) within tol of the recomputed gross activity.
    gross_recomp = sum(abs(r.net_pnl) for r in recomputed)
    total_abs_diff = (
        sum(abs(m.diff) for m in rep.matches)
        + sum(abs(c.net_pnl) for c in rep.unmatched_claimed)
        + sum(abs(r.net_pnl) for r in rep.unmatched_recomputed)
    )
    net_ok = abs(rep.aggregate_diff) <= max(abs_tol, rel_tol * abs(rep.recomputed_total))
    sum_ok = total_abs_diff <= max(abs_tol, rel_tol * gross_recomp)
    rep.aggregate_ok = net_ok and sum_ok
    if not net_ok:
        rep.issues.append(
            f"aggregate P&L mismatch: journal claims ${rep.claimed_total:,.2f} but "
            f"fills recompute to ${rep.recomputed_total:,.2f} "
            f"(net diff ${rep.aggregate_diff:,.2f} exceeds tolerance)"
        )
    if net_ok and not sum_ok:
        rep.issues.append(
            f"per-trade discrepancies sum to ${total_abs_diff:,.2f} (exceeds "
            f"tolerance of recomputed activity ${gross_recomp:,.2f}) even though the "
            "net totals match - opposite-sign misreporting"
        )

    rep.ok = (
        rep.aggregate_ok
        and all(m.within_tol for m in rep.matches)
        and not rep.unmatched_claimed
        and not rep.unmatched_recomputed
    )
    return rep


__all__ = ["ClaimedTrade", "TradeMatch", "CrosscheckReport",
           "extract_claimed_trades", "crosscheck"]
