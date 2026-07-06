"""Integrity verifier for the VTR journal (Stage 12).

Walks a journal and checks it is internally sound - this is the "tamper breaks
the chain" guarantee, entity-agnostic and offline:

  1. **Chain** - every entry's recomputed hash matches its stored ``hash``
     (no content was altered), and its ``prev_hash`` equals the previous
     entry's ``hash`` (no entry was inserted, deleted or reordered). ``seq``
     runs 1, 2, 3, ... without gaps.
  2. **Commit-reveal** - every reveal has a prior commit with the same ``ref``,
     its disclosed ``payload`` + ``salt`` re-hash to that commit's
     ``commit_hash`` (no hindsight editing), and no commit is revealed twice.
  3. **Manifest** - exactly one manifest entry, and it is first.

Scope: this checks the journal is *un-forged*. Recomputing the actual P&L /
Sharpe / drawdown from public exchange fills is the Stage-16 open verifier - a
separate, economic check that consumes a journal this one has certified intact.

Offline ceiling (important): this proves INTERNAL CONSISTENCY, not authenticity
or completeness. An adversary who holds the whole file can re-chain it from
genesis (mint a fresh journal, or truncate the tail to hide a loss) and it will
still PASS - exactly the gap that Stage-13 on-chain anchoring of the chain head
/ ``batch_root`` closes (a re-mint cannot match the anchored root). "Tamper
breaks the chain" holds against partial edits; full re-chaining needs the
anchor. When Stage 13 lands, verification should additionally assert the head
and entry count match the anchored value.

    python -m core.journal.verify path/to/journal.jsonl
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from core.journal.canonical import GENESIS, commitment, hash_obj


@dataclass
class VerifyReport:
    ok: bool = True
    n_entries: int = 0
    n_manifest: int = 0
    n_commits: int = 0
    n_reveals: int = 0
    n_events: int = 0
    open_commits: int = 0          # committed but never revealed (open positions)
    head: str = GENESIS
    issues: list[str] = field(default_factory=list)

    def summary(self) -> str:
        verdict = "PASS" if self.ok else "FAIL"
        lines = [
            f"  JOURNAL INTEGRITY : {verdict}",
            f"  entries={self.n_entries}  manifest={self.n_manifest}  "
            f"commits={self.n_commits}  reveals={self.n_reveals}  "
            f"events={self.n_events}  open={self.open_commits}",
            f"  head={self.head}",
        ]
        if self.issues:
            lines.append(f"  issues ({len(self.issues)}):")
            lines.extend(f"    - {m}" for m in self.issues[:20])
            if len(self.issues) > 20:
                lines.append(f"    ... +{len(self.issues) - 20} more")
        return "\n".join(lines)


def verify_journal(entries: list[dict]) -> VerifyReport:
    """Verify chain + commit-reveal + manifest integrity of an entry list."""
    rep = VerifyReport(n_entries=len(entries))
    prev = GENESIS
    seq_expected = 1
    prev_ts: str | None = None
    commits: dict[str, str] = {}     # ref -> commit_hash
    commit_ts: dict[str, str] = {}   # ref -> commit timestamp
    revealed: set[str] = set()

    for e in entries:
        seq = e.get("seq")
        ts = e.get("ts")
        # 1. chain integrity. Advance the cursor on the RECOMPUTED hash (not the
        # entry's self-reported one) so the next link is checked against an
        # honest value, never an attacker-supplied stored hash.
        recomputed = hash_obj({k: v for k, v in e.items() if k != "hash"})
        if recomputed != e.get("hash"):
            rep.issues.append(f"seq {seq}: hash mismatch (entry content tampered)")
        if e.get("prev_hash") != prev:
            rep.issues.append(f"seq {seq}: broken chain link (prev_hash mismatch)")
        if seq != seq_expected:
            rep.issues.append(f"seq out of order: got {seq}, expected {seq_expected}")
        # ISO-8601 UTC strings (fixed width, trailing Z) compare chronologically
        # as plain strings - a back-dated entry breaks monotonicity.
        if prev_ts is not None and ts is not None and ts < prev_ts:
            rep.issues.append(f"seq {seq}: timestamp goes backwards ({ts} < {prev_ts})")
        prev = recomputed
        prev_ts = ts if ts is not None else prev_ts
        seq_expected += 1

        kind = e.get("kind")
        body = e.get("body") or {}
        if kind == "manifest":
            rep.n_manifest += 1
            if seq != 1:
                rep.issues.append(f"seq {seq}: manifest is not the first entry")
        elif kind == "commit":
            rep.n_commits += 1
            ref = e.get("ref")
            if ref in commits:
                rep.issues.append(f"ref {ref}: duplicate commit")
            commits[ref] = body.get("commit_hash")
            commit_ts[ref] = ts
        elif kind == "reveal":
            rep.n_reveals += 1
            ref = e.get("ref")
            if ref not in commits:
                rep.issues.append(f"ref {ref}: reveal with no prior commit")
            elif ref in revealed:
                rep.issues.append(f"ref {ref}: double reveal")
            else:
                got = commitment(body.get("payload"), body.get("salt"))
                if got != commits[ref]:
                    rep.issues.append(
                        f"ref {ref}: commitment mismatch (revealed payload/salt altered)"
                    )
                # DoD #4: a reveal must not predate its own commit (the outcome
                # cannot be known before the decision was sealed).
                cts = commit_ts.get(ref)
                if cts is not None and ts is not None and ts < cts:
                    rep.issues.append(
                        f"ref {ref}: reveal predates its commit ({ts} < {cts})"
                    )
            revealed.add(ref)
        elif kind == "event":
            rep.n_events += 1
        else:
            rep.issues.append(f"seq {seq}: unknown entry kind {kind!r}")

    if rep.n_manifest == 0:
        rep.issues.append("no manifest entry (stack passport missing)")
    elif rep.n_manifest > 1:
        rep.issues.append(f"multiple manifest entries ({rep.n_manifest})")

    rep.open_commits = len(set(commits) - revealed)
    rep.head = prev
    rep.ok = not rep.issues
    return rep


def load_journal(path: str) -> list[dict]:
    """Read a JSONL journal file into a list of entry dicts."""
    out: list[dict] = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def main() -> None:
    import argparse

    ap = argparse.ArgumentParser(description="Verify VTR journal integrity")
    ap.add_argument("path", help="path to a journal .jsonl file")
    a = ap.parse_args()
    rep = verify_journal(load_journal(a.path))
    print("=" * 72)
    print(rep.summary())
    print("=" * 72, flush=True)
    raise SystemExit(0 if rep.ok else 1)


if __name__ == "__main__":
    main()
