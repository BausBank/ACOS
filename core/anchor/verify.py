"""Anchor verifier - the check that closes Stage 12's offline ceiling (Stage 13).

:func:`core.journal.verify_journal` proves a journal is *internally consistent*,
but a re-mint (re-chain from genesis to hide a loss) still passes it. This layer
adds the missing assertion the Stage-12 verifier flagged: recompute the anchored
fingerprint(s) from the journal and confirm they match what was published.

Three checks per anchor, escalating in strength:

  1. **Recompute** - rebuild the :class:`~core.anchor.record.AnchorRecord` over
     the journal's ``[start_seq, end_seq]`` and confirm its ``anchor_hash``,
     ``journal_head`` and ``batch_root`` equal the manifest's. A re-minted
     journal yields a different ``journal_head`` -> mismatch -> FAIL.
  2. **Anchor chain** - each record's ``prev_anchor`` must equal the previous
     record's ``anchor_hash`` (anchors can't be dropped/reordered).
  3. **On-chain** (``live=True``) - ask each backend to re-read its receipt from
     Arc / OpenTimestamps and confirm the published digest equals the recomputed
     ``anchor_hash``. This is what makes the past un-rewritable: the digest is
     already in a block, at a block timestamp, before any tampering.

Offline (``live=False``) verifies 1 + 2 (recompute vs manifest) without network;
``live=True`` additionally does 3.

Residual ceiling (honest boundary): this verifies a (journal, manifest) PAIR. The
remaining gap is an actor who controls the anchor key and *re-publishes*: re-mint
the whole journal, recompute a fully-consistent manifest, and post fresh anchor
txs for the new digests. Because anchors are append-only ON-CHAIN at real block
times, the original anchors still exist on-chain and were timestamped earlier - so
this is caught only by enumerating ALL anchor-identity txs on-chain and confirming
the manifest omits none (and that block times are monotonic with seq). That
on-chain anchor-history enumeration is the Stage-16 open verifier; here we assume
the manifest presented is the complete published set.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Sequence

from core.anchor.backends import AnchorBackend, AnchorReceipt
from core.anchor.record import build_anchor
from core.journal.canonical import GENESIS
from core.journal.verify import verify_journal


@dataclass
class AnchorVerifyReport:
    ok: bool = True
    journal_ok: bool = True
    n_anchors: int = 0
    n_recompute_ok: int = 0
    n_chain_ok: int = 0           # on-chain confirmations (live only)
    covered_through: int = 0      # highest journal seq the anchors actually cover
    journal_max_seq: int = 0      # highest seq in the journal
    rails_confirmed: dict[str, int] = field(default_factory=dict)
    rails_pending: dict[str, int] = field(default_factory=dict)  # submitted, awaiting confirmation
    issues: list[str] = field(default_factory=list)

    def summary(self) -> str:
        verdict = "PASS" if self.ok else "FAIL"
        lines = [
            f"  ANCHOR VERIFICATION : {verdict}",
            f"  journal_integrity={'ok' if self.journal_ok else 'FAIL'}  "
            f"anchors={self.n_anchors}  recomputed_ok={self.n_recompute_ok}",
            f"  coverage: anchored through seq {self.covered_through} of {self.journal_max_seq}",
        ]
        if self.rails_confirmed:
            rails = "  ".join(f"{k}={v}" for k, v in sorted(self.rails_confirmed.items()))
            lines.append(f"  on-chain confirmed: {rails}")
        if self.rails_pending:
            rails = "  ".join(f"{k}={v}" for k, v in sorted(self.rails_pending.items()))
            lines.append(f"  submitted (pending confirmation): {rails}")
        if self.issues:
            lines.append(f"  issues ({len(self.issues)}):")
            lines.extend(f"    - {m}" for m in self.issues[:20])
            if len(self.issues) > 20:
                lines.append(f"    ... +{len(self.issues) - 20} more")
        return "\n".join(lines)


def verify_anchors(
    journal_entries: list[dict[str, Any]],
    manifest_records: list[dict[str, Any]],
    *,
    backends: Sequence[AnchorBackend] | None = None,
    live: bool = False,
    check_journal: bool = True,
) -> AnchorVerifyReport:
    """Verify a journal against its anchor manifest (and, if ``live``, the chains).

    ``backends`` maps a receipt's ``backend`` name to the rail used to re-read it
    (only needed when ``live=True``).
    """
    from core.journal.canonical import canonical_bytes, sha256_hex

    rep = AnchorVerifyReport(n_anchors=len(manifest_records))
    by_name = {b.name: b for b in (backends or [])}

    if check_journal:
        jrep = verify_journal(journal_entries)
        rep.journal_ok = jrep.ok
        if not jrep.ok:
            rep.issues.append(f"journal integrity FAILED ({len(jrep.issues)} issue(s))")

    rep.journal_max_seq = (
        max(int(e["seq"]) for e in journal_entries) if journal_entries else 0
    )

    prev_anchor = GENESIS
    expected_next_start = 1   # anchored ranges must tile [1..head] with no gap
    for rec in manifest_records:
        no = rec.get("anchor_no", "?")
        payload = rec.get("payload", {})
        manifest_hash = rec.get("anchor_hash")
        start = int(payload.get("start_seq", 0))
        end = int(payload.get("end_seq", 0))

        # 0. payload self-consistency: the stored payload MUST hash to the
        # published anchor_hash, and its declared range must be internally sound.
        # (Without this, a manifest record could carry fields - n_entries,
        # schema - that disagree with its own published hash and still pass.)
        if sha256_hex(canonical_bytes(payload)) != manifest_hash:
            rep.issues.append(
                f"anchor #{no}: payload does not hash to its anchor_hash (manifest altered)"
            )
        if payload.get("n_entries") != (end - start + 1):
            rep.issues.append(
                f"anchor #{no}: n_entries={payload.get('n_entries')} inconsistent with range [{start},{end}]"
            )

        # 1. recompute from the journal (re-mint / truncation detector)
        try:
            recomputed = build_anchor(
                journal_entries, start_seq=start, end_seq=end, prev_anchor=prev_anchor
            )
        except Exception as exc:
            rep.issues.append(f"anchor #{no}: cannot recompute over [{start},{end}]: {exc}")
            prev_anchor = manifest_hash or prev_anchor
            expected_next_start = end + 1
            rep.covered_through = max(rep.covered_through, end)
            continue

        if recomputed.anchor_hash != manifest_hash:
            rep.issues.append(
                f"anchor #{no}: anchor_hash mismatch (journal re-minted or manifest altered)"
            )
        elif recomputed.journal_head != payload.get("journal_head"):
            rep.issues.append(f"anchor #{no}: journal_head mismatch")
        elif recomputed.batch_root != payload.get("batch_root"):
            rep.issues.append(f"anchor #{no}: batch_root mismatch")
        else:
            rep.n_recompute_ok += 1

        # 2. anchor-chain link + contiguous coverage. The link advances on the
        # JOURNAL-bound recomputed hash (not the manifest's self-reported one).
        if payload.get("prev_anchor") != prev_anchor:
            rep.issues.append(f"anchor #{no}: prev_anchor broken (anchor dropped/reordered)")
        if start != expected_next_start:
            rep.issues.append(
                f"anchor #{no}: range starts at {start}, expected {expected_next_start} "
                "(gap or overlap in anchored coverage)"
            )
        prev_anchor = recomputed.anchor_hash
        expected_next_start = end + 1
        rep.covered_through = max(rep.covered_through, end)

        # 3. on-chain confirmation (live only). Live mode must produce POSITIVE
        # evidence: each anchor needs >=1 confirmed-or-pending receipt, else the
        # 'past in a real block' guarantee is not met and live collapses to the
        # offline ceiling. A dry-run receipt was never broadcast; a receipt for a
        # backend we were not given is not checkable - both are flagged, not
        # silently skipped, and neither counts as evidence.
        if live:
            anchor_confirmed = 0
            for rdict in rec.get("receipts", []):
                name = rdict.get("backend")
                backend = by_name.get(name)
                if backend is None:
                    rep.issues.append(
                        f"anchor #{no} [{name}]: receipt not checkable (no such backend supplied)"
                    )
                    continue
                if rdict.get("status") == "dry-run":
                    rep.issues.append(
                        f"anchor #{no} [{name}]: receipt is dry-run (never broadcast) - "
                        "no on-chain confirmation"
                    )
                    continue
                receipt = AnchorReceipt(**{
                    k: rdict.get(k) for k in (
                        "backend", "digest_hex", "status", "ref",
                        "block", "block_time", "chain_id", "detail",
                    )
                })
                ok, info = backend.verify(receipt, manifest_hash)
                if ok and info.get("confirmed"):
                    rep.n_chain_ok += 1
                    anchor_confirmed += 1
                    rep.rails_confirmed[name] = rep.rails_confirmed.get(name, 0) + 1
                elif ok and info.get("pending"):
                    # A pending proof is a calendar PROMISE, not a commitment to a
                    # real block - and a third party cannot tell a genuine pending
                    # proof from one fabricated offline (the URI is free text, no
                    # network round-trip authenticates it). So it is reported for
                    # context but does NOT satisfy live evidence; only an
                    # authoritatively-confirmed receipt (a mined Arc tx bound to
                    # the anchor identity, or an OTS Bitcoin attestation validated
                    # by the reference tool) does.
                    rep.rails_pending[name] = rep.rails_pending.get(name, 0) + 1
                else:
                    rep.issues.append(f"anchor #{no} [{name}]: on-chain verify failed ({info})")
            if anchor_confirmed == 0:
                rep.issues.append(
                    f"anchor #{no}: no CONFIRMED on-chain proof under live verify "
                    "(pending/unconfirmed receipts do not suffice) - not bound to a real block"
                )

    # Coverage: the anchored ranges must reach the journal head. Anything past
    # the newest anchor - INCLUDING a journal with NO anchors at all - is
    # unprotected and can be silently truncated (drop a losing tail). This is the
    # exact gap Stage-13 exists to close, so it must fire even when the manifest
    # is empty/absent (covered_through stays 0), not only for a partial anchor.
    if rep.journal_max_seq > 0 and rep.covered_through < rep.journal_max_seq:
        if not manifest_records:
            rep.issues.append(
                f"no anchors: journal reaches seq {rep.journal_max_seq} but nothing is "
                "anchored (entirely unprotected / truncation-exposed)"
            )
        else:
            rep.issues.append(
                f"unanchored tail: journal reaches seq {rep.journal_max_seq} but anchors "
                f"cover only through seq {rep.covered_through} (truncation-exposed)"
            )

    rep.ok = (not rep.issues) and (rep.journal_ok or not check_journal)
    return rep


def main() -> None:
    import argparse
    import os

    from core.anchor.anchorer import default_manifest_path, load_env_file, load_manifest
    from core.anchor.backends import ArcRawTxBackend, OpenTimestampsBackend
    from core.journal.verify import load_journal

    load_env_file()  # pick up ANCHOR_ADDRESS / ARC_CHAIN_ID for live verify
    ap = argparse.ArgumentParser(description="Verify a VTR journal against its anchors (Stage 13)")
    ap.add_argument("journal", help="path to the journal .jsonl")
    ap.add_argument("manifest", nargs="?", default=None, help="anchor manifest (.anchors.jsonl)")
    ap.add_argument("--live", action="store_true", help="also re-read each anchor from its chain")
    ap.add_argument(
        "--anchor-address", default=os.getenv("ANCHOR_ADDRESS"),
        help="the anchor identity (Arc 'from' address) to PIN for live verify. "
             "Without it, a live Arc check only proves 'some tx carries the digest', "
             "not 'the anchor key published it' - the digest is public.",
    )
    a = ap.parse_args()

    manifest_path = a.manifest or default_manifest_path(a.journal)
    entries = load_journal(a.journal)
    records = load_manifest(manifest_path)
    backends = None
    if a.live:
        chain_id = int(os.getenv("ARC_CHAIN_ID")) if os.getenv("ARC_CHAIN_ID") else None
        if not a.anchor_address:
            print("  WARNING: --anchor-address not set; Arc identity is UNPINNED "
                  "(a live Arc 'confirmed' then only proves the public digest is on "
                  "some tx, not that the anchor key published it).", flush=True)
        ots_dir = os.path.dirname(manifest_path) or "."
        backends = [
            ArcRawTxBackend(expected_address=a.anchor_address, chain_id=chain_id),
            OpenTimestampsBackend(out_dir=ots_dir),
        ]
    rep = verify_anchors(entries, records, backends=backends, live=a.live)
    print("=" * 72)
    print(rep.summary())
    print("=" * 72, flush=True)
    raise SystemExit(0 if rep.ok else 1)


if __name__ == "__main__":
    main()
