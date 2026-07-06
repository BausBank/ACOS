"""Anchorer - turn a journal batch into a published, verifiable anchor (Stage 13).

Orchestrates one anchoring round:

  1. load the (already integrity-checked) journal,
  2. compute the :class:`~core.anchor.record.AnchorRecord` over the next batch,
     chaining ``prev_anchor`` from the last anchor,
  3. submit the 32-byte digest to each backend (dry-run by default; a live
     broadcast is an explicit ``--live`` step),
  4. append a record to a sidecar **anchor manifest** (``<journal>.anchors.jsonl``).

Why a sidecar and not an in-chain ``anchor`` event: writing back into the
journal would require *resuming* an existing hash-chain (reload seq/head/pending
salts), which is the durable-live-journal work deferred to Stage 14. The sidecar
keeps Stage 13 self-contained: it references the journal by ``journal_head`` +
``end_seq``, so verification recomputes those from the journal and checks they
match what was anchored. When Stage 14 adds chain-resume, these records fold
into the live journal as ``anchor`` events with no format change.

The manifest is itself a small chain (each record's ``prev_anchor`` is the
previous record's ``anchor_hash``), so a published anchor cannot be quietly
dropped or reordered without detection.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Callable, Sequence

from core.anchor.backends import AnchorBackend, AnchorReceipt
from core.anchor.record import build_anchor
from core.journal.canonical import GENESIS
from core.journal.verify import load_journal

ANCHOR_MANIFEST_SCHEMA = 1


def default_manifest_path(journal_path: str) -> str:
    """``foo.jsonl`` -> ``foo.anchors.jsonl`` (sidecar next to the journal)."""
    base, ext = os.path.splitext(journal_path)
    return f"{base}.anchors.jsonl"


def load_manifest(path: str) -> list[dict[str, Any]]:
    """Read an anchor manifest (JSONL) into a list of records; [] if absent."""
    if not os.path.exists(path):
        return []
    out: list[dict[str, Any]] = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def _iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Anchorer:
    """Drives anchoring rounds against a journal + its sidecar manifest.

    Parameters
    ----------
    journal_path
        Path to the ``.jsonl`` journal to anchor.
    backends
        Ordered :class:`AnchorBackend` rails (e.g. Arc + OpenTimestamps).
    manifest_path
        Sidecar path; defaults to ``<journal>.anchors.jsonl``.
    clock
        Injectable ``() -> datetime`` for the record timestamp (tests pin it).
    """

    def __init__(
        self,
        journal_path: str,
        *,
        backends: Sequence[AnchorBackend] = (),
        manifest_path: str | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.journal_path = journal_path
        self.backends = list(backends)
        self.manifest_path = manifest_path or default_manifest_path(journal_path)
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def anchor_batch(
        self,
        *,
        start_seq: int | None = None,
        end_seq: int | None = None,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        """Anchor the batch ``[start_seq, end_seq]``. By default continues from
        the last anchored entry (``start_seq = last end_seq + 1``) up to the
        journal head, so repeated calls anchor only the new tail."""
        entries = load_journal(self.journal_path)
        if not entries:
            raise ValueError(f"empty/absent journal at {self.journal_path!r}")

        prior = load_manifest(self.manifest_path)
        prev_anchor = prior[-1]["anchor_hash"] if prior else GENESIS
        last_end = prior[-1]["payload"]["end_seq"] if prior else 0
        start = start_seq if start_seq is not None else last_end + 1

        max_seq = max(int(e["seq"]) for e in entries)
        end = max_seq if end_seq is None else int(end_seq)
        if start > end:
            raise ValueError(
                f"nothing new to anchor: start_seq {start} > end_seq {end} "
                f"(already anchored through {last_end})"
            )

        record = build_anchor(entries, start_seq=start, end_seq=end, prev_anchor=prev_anchor)
        receipts: list[AnchorReceipt] = [
            b.submit(record.anchor_hash, dry_run=dry_run) for b in self.backends
        ]

        anchor_no = (prior[-1]["anchor_no"] + 1) if prior else 1
        line = {
            "manifest_schema": ANCHOR_MANIFEST_SCHEMA,
            "anchor_no": anchor_no,
            "ts": _iso(self._clock()),
            "anchor_hash": record.anchor_hash,
            "dry_run": dry_run,
            "payload": record.payload,
            "receipts": [r.to_dict() for r in receipts],
        }
        with open(self.manifest_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(line, ensure_ascii=False) + "\n")

        return {
            "anchor_no": anchor_no,
            "anchor_hash": record.anchor_hash,
            "range": [start, end],
            "n_entries": record.n_entries,
            "journal_head": record.journal_head,
            "dry_run": dry_run,
            "receipts": [r.to_dict() for r in receipts],
            "manifest_path": self.manifest_path,
        }


def load_env_file(path: str = ".env") -> None:
    """Best-effort: load ``KEY=value`` lines from ``path`` into ``os.environ``
    (without overriding already-set vars). The anchorer/verify CLIs are live
    NETWORK tools that need ANCHOR_PRIVATE_KEY / ARC_* / ANCHOR_ADDRESS; the
    offline library classes stay env-agnostic (the key is passed explicitly)."""
    if not os.path.exists(path):
        return
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                os.environ.setdefault(k.strip(), v.strip().strip('"'))
    except OSError:
        pass


def _build_backends(args: Any, journal_path: str) -> list[AnchorBackend]:
    """CLI helper: assemble the requested rails from env + flags."""
    from core.anchor.backends import ArcRawTxBackend, OpenTimestampsBackend

    rails: list[AnchorBackend] = []
    if "arc" in args.rails:
        rails.append(
            ArcRawTxBackend(
                rpc_url=os.getenv("ARC_RPC_URL"),
                private_key=os.getenv("ANCHOR_PRIVATE_KEY") or None,
            )
        )
    if "btc" in args.rails:
        out_dir = args.ots_dir or os.path.join(os.path.dirname(journal_path) or ".", "ots")
        rails.append(OpenTimestampsBackend(out_dir))
    return rails


def main() -> None:
    import argparse

    ap = argparse.ArgumentParser(description="Anchor a VTR journal batch (Stage 13)")
    ap.add_argument("journal", help="path to a journal .jsonl file")
    ap.add_argument("--rails", default="arc,btc",
                    help="comma list of rails to publish to: arc, btc (default both)")
    ap.add_argument("--start", type=int, default=None, help="start seq (default: continue)")
    ap.add_argument("--end", type=int, default=None, help="end seq (default: head)")
    ap.add_argument("--ots-dir", default=None, help="dir for .ots proofs")
    ap.add_argument("--live", action="store_true",
                    help="REALLY broadcast (default is dry-run: build + sign, no send)")
    a = ap.parse_args()
    a.rails = [r.strip() for r in a.rails.split(",") if r.strip()]

    load_env_file()
    anchorer = Anchorer(a.journal, backends=_build_backends(a, a.journal))
    out = anchorer.anchor_batch(start_seq=a.start, end_seq=a.end, dry_run=not a.live)
    print("=" * 72)
    print(f"  ANCHOR #{out['anchor_no']}  {'(DRY-RUN)' if out['dry_run'] else '(LIVE)'}")
    print(f"  range seq [{out['range'][0]}, {out['range'][1]}]  n_entries={out['n_entries']}")
    print(f"  anchor_hash = {out['anchor_hash']}")
    print(f"  journal_head = {out['journal_head']}")
    for r in out["receipts"]:
        loc = r.get("ref") or "-"
        extra = f" block={r['block']}" if r.get("block") else ""
        print(f"  [{r['backend']:14}] {r['status']:9} {loc}{extra}")
    print(f"  manifest -> {out['manifest_path']}")
    print("=" * 72, flush=True)


if __name__ == "__main__":
    main()
