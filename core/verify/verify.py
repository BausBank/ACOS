"""Open verifier - one command, one verdict: "don't trust, verify" (Stage 16).

Given ``(journal, anchors, public fills, anchor address)`` this recomputes a
track from raw public data and returns a single PASS/FAIL, composing every layer
of the trust stack:

  1. **Journal integrity** (Stage 12) - chain + commit-reveal + manifest are
     internally sound (no edit / insert / reorder / hindsight outcome editing).
  2. **Anchor verification** (Stage 13) - the anchored fingerprints recompute
     from the journal and match the manifest (offline), and - ``--live`` - each
     is bound to a real Arc tx / Bitcoin block. A re-mint can't reproduce a value
     already in a past block.
  3. **Fills recompute** (Stage 16) - P&L / Sharpe / drawdown recomputed
     INDEPENDENTLY from the venue's public fills.
  4. **Cross-check** (Stage 16) - the journal's CLAIMED P&L matches the fills
     recompute. This is what catches a journal that is internally consistent AND
     anchored but whose *outcomes* were inflated (the one tamper the chain + the
     anchor cannot see, because the outcome is not sealed by the commit).
  5. **Anchor history** (Stage 16, best-effort) - enumerate every anchor tx from
     the anchor address on-chain and confirm the manifest omits none (closes the
     re-mint-and-re-anchor residual boundary Stage 13 documented).

Entity-agnostic throughout: it reads plain journal dicts + venue fill dicts and
knows nothing about *what* the actor is.

    python -m core.verify <journal.jsonl> [--fills fills.jsonl] [--manifest m.jsonl]
        [--capital 350] [--live] [--anchor-address 0x..] [--explorer-url URL]

Run it against the LIVE track's files and it self-verifies: with 0 trades the
cross-check is N/A (trivially PASS) and starts matching for real once trades land.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Sequence

from core.anchor.verify import AnchorVerifyReport, verify_anchors
from core.journal.verify import VerifyReport, verify_journal
from core.verify.anchor_history import (
    AnchorHistoryReport,
    OnchainAnchorTx,
    verify_anchor_history,
)
from core.verify.crosscheck import CrosscheckReport, crosscheck, extract_claimed_trades
from core.verify.fills_pnl import RecomputeReport, recompute_from_fills


@dataclass
class OpenVerifyReport:
    ok: bool = True
    journal: VerifyReport | None = None
    anchors: AnchorVerifyReport | None = None
    recompute: RecomputeReport | None = None
    crosscheck: CrosscheckReport | None = None
    anchor_history: AnchorHistoryReport | None = None
    checks: dict[str, str] = field(default_factory=dict)   # name -> PASS/FAIL/SKIP/N/A
    notes: list[str] = field(default_factory=list)

    def summary(self) -> str:
        bar = "=" * 72
        head = "PASS" if self.ok else "FAIL"
        lines = [bar, f"  OPEN VERIFIER  ::  OVERALL {head}", bar]
        for name, status in self.checks.items():
            lines.append(f"  [{status:^5}] {name}")
        if self.notes:
            lines.append("  " + "-" * 68)
            lines.extend(f"  ! {n}" for n in self.notes)
        lines.append(bar)
        if self.journal:
            lines.append(self.journal.summary())
        if self.anchors:
            lines.append("")
            lines.append(self.anchors.summary())
        if self.recompute:
            lines.append("")
            lines.append(self.recompute.summary())
        if self.crosscheck:
            lines.append("")
            lines.append(self.crosscheck.summary())
        if self.anchor_history:
            lines.append("")
            lines.append(self.anchor_history.summary())
        lines.append(bar)
        return "\n".join(lines)


def open_verify(
    journal_entries: Sequence[dict[str, Any]],
    *,
    manifest_records: Sequence[dict[str, Any]] | None = None,
    fills: Sequence[dict[str, Any]] | None = None,
    equity_start: float | None = None,
    abs_tol: float = 1.0,
    rel_tol: float = 0.02,
    check_anchors: bool = True,
    anchor_backends: Sequence[Any] | None = None,
    live: bool = False,
    onchain_txs: Sequence[OnchainAnchorTx] | None = None,
    expected_address: str | None = None,
    require_manifest_onchain: bool = False,
) -> OpenVerifyReport:
    """Run the full open-verification and return a single PASS/FAIL report.

    A check that is not requested (no fills -> no recompute; ``check_anchors=False``
    -> no anchor stage; ``onchain_txs=None`` -> anchor history SKIP) is recorded
    as ``SKIP``/``N/A`` and does not affect the verdict. The verdict is the AND of
    every check that actually ran with a pass/fail meaning.
    """
    rep = OpenVerifyReport()

    # 1. Journal integrity (always).
    jrep = verify_journal(list(journal_entries))
    rep.journal = jrep
    rep.checks["journal integrity (chain + commit-reveal + manifest)"] = (
        "PASS" if jrep.ok else "FAIL"
    )

    # 2. Anchor verification (recompute vs manifest; + on-chain when live).
    if check_anchors and manifest_records is not None:
        arep = verify_anchors(
            list(journal_entries), list(manifest_records),
            backends=anchor_backends, live=live, check_journal=False,
        )
        rep.anchors = arep
        rep.checks["anchor verification (recompute"
                   + (" + on-chain)" if live else ")")] = "PASS" if arep.ok else "FAIL"
    else:
        rep.checks["anchor verification"] = "SKIP"

    # 3. Fills recompute (measurement; feeds the cross-check).
    if fills is not None:
        rrep = recompute_from_fills(fills, equity_start=equity_start)
        rep.recompute = rrep
        rep.checks["fills recompute (P&L / Sharpe / drawdown)"] = "DONE"

        # 4. Cross-check claimed vs recomputed.
        claimed = extract_claimed_trades(list(journal_entries))
        closed = [t for t in rrep.trades if not t.open]
        crep = crosscheck(claimed, closed, abs_tol=abs_tol, rel_tol=rel_tol)
        rep.crosscheck = crep
        rep.checks["cross-check (journal claim vs fills recompute)"] = (
            "N/A" if not crep.applicable else ("PASS" if crep.ok else "FAIL")
        )
    else:
        # No fills handed in. If the journal CLAIMS trades, the economic layer was
        # not exercised at all - surface that loudly so an integrity-only PASS is
        # never mistaken for "P&L verified from the venue".
        n_reveals = sum(1 for e in journal_entries if e.get("kind") == "reveal")
        if n_reveals:
            rep.checks["fills recompute / cross-check"] = "SKIP"
            rep.notes.append(
                f"economic cross-check NOT run: journal claims {n_reveals} closed "
                "trade(s) but no fills were provided (pass --fills to verify P&L "
                "against the venue). Integrity + anchors only."
            )
        else:
            rep.checks["fills recompute / cross-check"] = "N/A"

    # 5. Anchor history (best-effort; never fails the verdict when not enumerated).
    if manifest_records is not None and (onchain_txs is not None or live):
        hrep = verify_anchor_history(
            list(manifest_records), onchain_txs,
            expected_address=expected_address,
            require_manifest_onchain=require_manifest_onchain,
        )
        rep.anchor_history = hrep
        rep.checks["anchor history (on-chain enumeration)"] = (
            "SKIP" if not hrep.enumerated else ("PASS" if hrep.ok else "FAIL")
        )

    # Overall verdict: AND of every check with pass/fail meaning.
    rep.ok = (
        jrep.ok
        and (rep.anchors.ok if rep.anchors is not None else True)
        and (rep.crosscheck.ok if (rep.crosscheck is not None
                                   and rep.crosscheck.applicable) else True)
        and (rep.anchor_history.ok if (rep.anchor_history is not None
                                       and rep.anchor_history.enumerated) else True)
    )
    return rep


def _load_jsonl(path: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def main() -> None:
    import argparse
    import os

    from core.anchor.anchorer import default_manifest_path, load_env_file, load_manifest

    load_env_file()
    ap = argparse.ArgumentParser(
        description="Open verifier: recompute a track from public data (Stage 16)"
    )
    ap.add_argument("journal", help="path to the journal .jsonl")
    ap.add_argument("--manifest", default=None,
                    help="anchor manifest (.anchors.jsonl); default = sidecar")
    ap.add_argument("--fills", default=None, help="captured public fills .jsonl")
    ap.add_argument("--capital", type=float, default=None,
                    help="equity base for return%% / Sharpe / drawdown (e.g. 350)")
    ap.add_argument("--abs-tol", type=float, default=1.0, help="cross-check $ tolerance")
    ap.add_argument("--rel-tol", type=float, default=0.02, help="cross-check rel tolerance")
    ap.add_argument("--no-anchors", action="store_true", help="skip anchor verification")
    ap.add_argument("--live", action="store_true",
                    help="also re-read anchors on-chain + enumerate anchor history")
    ap.add_argument("--anchor-address", default=os.getenv("ANCHOR_ADDRESS"),
                    help="anchor identity (Arc 'from') to PIN for live verify")
    ap.add_argument("--explorer-url", default=os.getenv("ARC_EXPLORER_URL"),
                    help="Blockscout-style API base for anchor-history enumeration")
    a = ap.parse_args()

    entries = _load_jsonl(a.journal)
    manifest_path = a.manifest or default_manifest_path(a.journal)
    manifest = None if a.no_anchors else load_manifest(manifest_path)
    fills = _load_jsonl(a.fills) if a.fills else None

    anchor_backends = None
    onchain_txs = None
    if a.live:
        from core.anchor.backends import ArcRawTxBackend, OpenTimestampsBackend
        chain_id = int(os.getenv("ARC_CHAIN_ID")) if os.getenv("ARC_CHAIN_ID") else None
        ots_dir = os.path.dirname(manifest_path) or "."
        anchor_backends = [
            ArcRawTxBackend(expected_address=a.anchor_address, chain_id=chain_id),
            OpenTimestampsBackend(out_dir=ots_dir),
        ]
        if a.explorer_url and a.anchor_address:
            from core.verify.anchor_history import BlockscoutProvider
            try:
                onchain_txs = BlockscoutProvider(a.explorer_url).list_anchor_txs(
                    a.anchor_address
                )
            except Exception as exc:  # best-effort: explorer down -> SKIP, not FAIL
                print(f"  (anchor-history enumeration unavailable: {exc!r})", flush=True)
                onchain_txs = None

    rep = open_verify(
        entries,
        manifest_records=manifest,
        fills=fills,
        equity_start=a.capital,
        abs_tol=a.abs_tol,
        rel_tol=a.rel_tol,
        check_anchors=not a.no_anchors,
        anchor_backends=anchor_backends,
        live=a.live,
        onchain_txs=onchain_txs,
        expected_address=a.anchor_address,
    )
    print(rep.summary(), flush=True)
    raise SystemExit(0 if rep.ok else 1)


if __name__ == "__main__":
    main()
