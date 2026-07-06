"""Recompute performance from raw venue fills - the heart of "don't trust, verify" (Stage 16).

The journal records what an actor *claims* happened; this module recomputes the
truth INDEPENDENTLY from the venue's own public fill record, so a skeptic holding
only ``(address, fills)`` reproduces P&L / Sharpe / drawdown without trusting us.

Input: a list of Hyperliquid ``userFills`` dicts (public, re-queryable from the
venue by address). Each fill carries::

    {"coin": "BTC", "px": "63758.0", "sz": "0.00018", "side": "B"|"A",
     "time": 1781981804642, "dir": "Open Long"|"Close Short"|..., "startPosition":
     "0.0", "closedPnl": "0.0", "fee": "0.004957", "tid": ..., "oid": ...}

Two independent recomputations are produced and should agree:

  * **Aggregate** - ``net_pnl = Σ closedPnl - Σ fee`` over every fill. The venue
    credits realised P&L on the closing portion of each fill (``closedPnl``) and
    charges ``fee`` per fill; this sum is the realised trading result, robust to
    how trades are grouped.
  * **Per round-trip trade** - fills are walked per coin in time order, tracking
    the signed position (``+sz`` on a buy, ``-sz`` on a sell, seeded by the
    fill's ``startPosition``). A *trade episode* spans from a zero -> non-zero
    crossing to the next return to zero; its net P&L is the ``closedPnl - fee``
    accumulated inside it. This list is what the Stage-16 cross-check matches
    against the journal's per-decision reveals.

Metrics (rf=0, daily basis, x sqrt(365) annualisation - the convention used by
``core.backtest.overfit`` so a verifier's Sharpe is comparable to the harness
headline):

  * realised equity curve = ``equity_start`` + cumulative realised net P&L,
    stepped at each closing fill's time;
  * Sharpe = ``mean / std`` of DAILY returns (population std) x sqrt(365);
  * max drawdown = deepest peak-to-trough fraction of the daily equity curve.

Scope (honest boundary): this recomputes REALISED TRADING P&L. Funding payments
are a separate venue ledger not present in ``userFills`` (isolated in Stage 10's
parity work too) - so a tiny funding-sized residual between this and the journal
is expected and tolerated by the cross-check, not a tamper signal. Unrealised
P&L of a still-open position is reported but never folded into the realised
result. Pure stdlib (no numpy) so an outside party can re-implement it anywhere.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Sequence

# A position whose absolute size is below this (in coin units) is treated as
# flat. Venues can leave a sub-dust residue after a "close"; without an epsilon
# a 1e-12 remainder would wrongly keep a trade episode open forever.
_FLAT_EPS = 1e-9

# Annualisation for a daily return series (crypto trades 24/7 -> 365 days).
# Matches core.backtest.overfit.PER_DAY_ANN so the numbers are comparable.
_PER_DAY_ANN = math.sqrt(365.0)


def _f(x: Any) -> float:
    """Parse a venue numeric field (often a string) to float; '' / None -> 0.0."""
    if x is None or x == "":
        return 0.0
    return float(x)


def _iso(ms: int) -> str:
    """Epoch-ms -> ISO-8601 UTC seconds with trailing Z (the feed convention)."""
    return datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def _day(ms: int) -> str:
    """Epoch-ms -> UTC calendar day 'YYYY-MM-DD' (the daily-return bucket)."""
    return datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc).strftime("%Y-%m-%d")


@dataclass
class RecomputedTrade:
    """One reconstructed round-trip position, recomputed from fills alone."""

    coin: str
    direction: str          # "long" | "short"
    open_time: str          # ISO-8601 UTC of the first (opening) fill
    close_time: str         # ISO-8601 UTC of the last (closing) fill
    open_time_ms: int
    close_time_ms: int
    gross_pnl: float        # Σ closedPnl inside the episode (venue realised P&L)
    fees: float             # Σ fee inside the episode
    net_pnl: float          # gross_pnl - fees
    n_fills: int
    max_abs_size: float     # peak |position| during the episode (coin units)
    open: bool = False      # True if the episode never returned to flat (still open)

    def to_dict(self) -> dict[str, Any]:
        return {
            "coin": self.coin,
            "direction": self.direction,
            "open_time": self.open_time,
            "close_time": self.close_time,
            "gross_pnl": round(self.gross_pnl, 6),
            "fees": round(self.fees, 6),
            "net_pnl": round(self.net_pnl, 6),
            "n_fills": self.n_fills,
            "open": self.open,
        }


@dataclass
class RecomputeReport:
    """Independent performance recompute from public fills."""

    n_fills: int = 0
    n_trades: int = 0          # closed round-trips
    n_open: int = 0            # episodes still open at the end of the window
    gross_pnl: float = 0.0     # Σ closedPnl over all fills
    fees: float = 0.0          # Σ fee over all fills
    net_pnl: float = 0.0       # gross_pnl - fees (realised)
    equity_start: float | None = None
    equity_end: float | None = None
    return_pct: float | None = None     # net_pnl / equity_start * 100
    sharpe: float | None = None         # daily basis, rf=0, x sqrt(365)
    max_drawdown_pct: float | None = None
    n_days: int = 0
    coins: list[str] = field(default_factory=list)
    window: tuple[str, str] | None = None
    trades: list[RecomputedTrade] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)

    def summary(self) -> str:
        sh = "n/a" if self.sharpe is None else f"{self.sharpe:+.2f}"
        dd = "n/a" if self.max_drawdown_pct is None else f"{self.max_drawdown_pct:.2f}%"
        rp = "n/a" if self.return_pct is None else f"{self.return_pct:+.2f}%"
        lines = [
            "  FILLS RECOMPUTE (independent, from public venue fills)",
            f"  fills={self.n_fills}  trades={self.n_trades}  open={self.n_open}  "
            f"coins={','.join(self.coins) or '-'}",
            f"  net P&L=${self.net_pnl:,.2f}  (gross ${self.gross_pnl:,.2f} - "
            f"fees ${self.fees:,.2f})",
            f"  return={rp}  sharpe={sh}  maxDD={dd}  days={self.n_days}",
        ]
        if self.window:
            lines.append(f"  window: {self.window[0]} -> {self.window[1]}")
        if self.issues:
            lines.append(f"  notes ({len(self.issues)}):")
            lines.extend(f"    - {m}" for m in self.issues[:10])
        return "\n".join(lines)


def _signed_size(fill: dict[str, Any]) -> float:
    """Signed fill size: + on a buy ('B'), - on a sell ('A')."""
    sz = _f(fill.get("sz"))
    return sz if fill.get("side") == "B" else -sz


def reconstruct_trades(fills: Sequence[dict[str, Any]]) -> list[RecomputedTrade]:
    """Group fills into round-trip trade episodes, per coin, in time order.

    A position is tracked as a signed running size seeded by each fill's
    ``startPosition``; an episode spans flat -> non-flat -> flat. A single fill
    that flips the sign (e.g. ``Long > Short``) closes the current episode and
    opens a new one at the same fill (its ``closedPnl`` realises the closed leg).
    """
    by_coin: dict[str, list[dict[str, Any]]] = {}
    for f in fills:
        by_coin.setdefault(str(f.get("coin")), []).append(f)

    trades: list[RecomputedTrade] = []
    for coin, coin_fills in by_coin.items():
        coin_fills = sorted(coin_fills, key=lambda f: (int(f.get("time", 0)),
                                                       str(f.get("tid", ""))))
        cur: dict[str, Any] | None = None  # the open episode accumulator

        def _flush(end_ms: int) -> None:
            nonlocal cur
            if cur is None:
                return
            net = cur["gross"] - cur["fees"]
            trades.append(RecomputedTrade(
                coin=coin,
                direction="long" if cur["dir_sign"] > 0 else "short",
                open_time=_iso(cur["open_ms"]), close_time=_iso(end_ms),
                open_time_ms=cur["open_ms"], close_time_ms=end_ms,
                gross_pnl=cur["gross"], fees=cur["fees"], net_pnl=net,
                n_fills=cur["n"], max_abs_size=cur["max_abs"], open=cur["still_open"],
            ))
            cur = None

        for f in coin_fills:
            start_pos = _f(f.get("startPosition"))
            after = start_pos + _signed_size(f)
            t = int(f.get("time", 0))
            pnl = _f(f.get("closedPnl"))
            fee = _f(f.get("fee"))

            # Open a new episode if we were flat going in.
            if cur is None and abs(start_pos) <= _FLAT_EPS:
                cur = {"open_ms": t, "dir_sign": 1 if after > 0 else -1,
                       "gross": 0.0, "fees": 0.0, "n": 0, "max_abs": 0.0,
                       "still_open": True}

            if cur is not None:
                cur["gross"] += pnl
                cur["fees"] += fee
                cur["n"] += 1
                cur["max_abs"] = max(cur["max_abs"], abs(after))

            # Returned to flat -> close the episode here.
            if cur is not None and abs(after) <= _FLAT_EPS:
                cur["still_open"] = False
                _flush(t)
            # Sign flip in a single fill: close the old leg, open the new one.
            elif cur is not None and after * cur["dir_sign"] < 0:
                cur["still_open"] = False
                _flush(t)
                cur = {"open_ms": t, "dir_sign": 1 if after > 0 else -1,
                       "gross": 0.0, "fees": 0.0, "n": 1, "max_abs": abs(after),
                       "still_open": True}

        # Anything left non-flat is a still-open position at window end.
        if cur is not None:
            _flush(cur["open_ms"] if cur["n"] == 0 else
                   int(coin_fills[-1].get("time", cur["open_ms"])))

    trades.sort(key=lambda tr: (tr.open_time_ms, tr.coin))
    return trades


def _sharpe_daily(daily_returns: list[float]) -> float | None:
    """Sharpe of a DAILY return series: mean/std (population) x sqrt(365), rf=0.

    Population std (divide by n) AND the ``n>=3`` minimum both match
    ``core.backtest.overfit._moments`` / ``sample_sharpe`` - so a Sharpe reported
    here equals the harness convention byte-for-byte, and a 2-point series (which
    has no statistical meaning) is left undefined (None) rather than shown."""
    n = len(daily_returns)
    if n < 3:
        return None
    mu = sum(daily_returns) / n
    var = sum((r - mu) ** 2 for r in daily_returns) / n
    sd = math.sqrt(var)
    if sd <= 0:
        return None
    return mu / sd * _PER_DAY_ANN


def _daily_pnl_series(closes: list[tuple[int, float]]) -> list[tuple[str, float]]:
    """``(day, realised_pnl)`` for EVERY UTC calendar day from the first close to
    the last (quiet days = 0.0), so a flat day contributes a genuine 0% return
    rather than being skipped. Includes the FIRST active day (its P&L is a real
    return measured against the capital base, not erased)."""
    if not closes:
        return []
    by_day: dict[str, float] = {}
    for ms, pnl in sorted(closes):
        d = _day(ms)
        by_day[d] = by_day.get(d, 0.0) + pnl
    first = datetime.strptime(min(by_day), "%Y-%m-%d").replace(tzinfo=timezone.utc)
    last = datetime.strptime(max(by_day), "%Y-%m-%d").replace(tzinfo=timezone.utc)
    out: list[tuple[str, float]] = []
    t = int(first.timestamp())
    end_t = int(last.timestamp())
    while t <= end_t:   # fixed 86400s steps on UTC (no DST) never skip/dup a day
        day = datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%d")
        out.append((day, by_day.get(day, 0.0)))
        t += 86400
    return out


def recompute_from_fills(
    fills: Sequence[dict[str, Any]],
    *,
    equity_start: float | None = None,
) -> RecomputeReport:
    """Recompute realised P&L (+ Sharpe / drawdown when ``equity_start`` given).

    ``equity_start`` is the capital base the % return / Sharpe / drawdown are
    measured against (the live track runs $350). Without it, absolute P&L and the
    per-trade list are still produced; ratio metrics are left ``None`` (you cannot
    form a return series with no capital base)."""
    rep = RecomputeReport(n_fills=len(fills))
    if not fills:
        rep.equity_start = equity_start
        rep.equity_end = equity_start
        return rep

    rep.gross_pnl = sum(_f(f.get("closedPnl")) for f in fills)
    rep.fees = sum(_f(f.get("fee")) for f in fills)
    rep.net_pnl = rep.gross_pnl - rep.fees
    rep.coins = sorted({str(f.get("coin")) for f in fills})
    times = [int(f.get("time", 0)) for f in fills]
    rep.window = (_iso(min(times)), _iso(max(times)))

    trades = reconstruct_trades(fills)
    rep.trades = trades
    rep.n_trades = sum(1 for t in trades if not t.open)
    rep.n_open = sum(1 for t in trades if t.open)
    if rep.n_open:
        rep.issues.append(
            f"{rep.n_open} position(s) still open at window end "
            "(unrealised P&L excluded from the realised result)"
        )

    # A consistency note (not a failure): the per-trade nets should sum to the
    # aggregate within float noise. A real gap means the fills couldn't be cleanly
    # grouped (flips/dust) and the AGGREGATE is the figure to trust.
    trade_net = sum(t.net_pnl for t in trades)
    if abs(trade_net - rep.net_pnl) > 1e-6:
        rep.issues.append(
            f"per-trade net ${trade_net:,.2f} != aggregate ${rep.net_pnl:,.2f} "
            "(grouping residue; aggregate is authoritative)"
        )

    if equity_start is not None and equity_start > 0:
        rep.equity_start = equity_start
        rep.equity_end = equity_start + rep.net_pnl
        rep.return_pct = rep.net_pnl / equity_start * 100.0
        # FIXED-BASE daily returns: each day's realised P&L measured against the
        # SAME capital base. The track is non-compounding fixed-notional (the live
        # $350 sizes 1:1), so return-on-initial-capital is the honest basis - and
        # it stays well-defined even if cumulative equity goes <=0 (a prior-equity
        # denominator would silently drop the catastrophic days). Includes day 0.
        closes = [(t.close_time_ms, t.net_pnl) for t in trades if not t.open]
        series = _daily_pnl_series(closes)
        rep.n_days = len(series)
        if series:
            daily_ret = [pnl / equity_start for _, pnl in series]
            rep.sharpe = _sharpe_daily(daily_ret)   # None when <2 days
            # Max drawdown: deepest peak-to-trough on the cumulative equity curve,
            # seeded at equity_start. The running peak starts at equity_start>0 and
            # only grows, so the fraction is always well-defined; a wipeout past
            # the base honestly reads >100% rather than collapsing to 0%.
            equity = equity_start
            peak = equity_start
            max_dd = 0.0
            for _, pnl in series:
                equity += pnl
                peak = max(peak, equity)
                max_dd = max(max_dd, (peak - equity) / peak)
            rep.max_drawdown_pct = max_dd * 100.0

    return rep


__all__ = ["RecomputedTrade", "RecomputeReport", "recompute_from_fills",
           "reconstruct_trades"]
