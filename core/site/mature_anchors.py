"""One-off LOCAL maturation of pending OpenTimestamps receipts (ops tool).

The live server's anchor manifest was pulled locally with every OTS receipt
still ``pending`` (no upgrade pass ever ran server-side). This runner matures
those receipts against the pulled ``.ots`` proofs WITHOUT touching the server
or the original manifest copy:

  1. for each anchor whose OTS receipt is pending, locate the LOCAL ``.ots``
     (the receipt's ``ref`` is a server path - remapped by basename, with a
     fallback match via the ``.digest`` sidecar's content);
  2. run the EXISTING Stage-13 pure-Python upgrade
     (:func:`core.anchor.bitcoin_verify.upgrade_via_calendar` - pulls the
     Bitcoin attestation from the public calendars into the local ``.ots``);
  3. re-verify AUTHORITATIVELY via the EXISTING backend verifier
     (:meth:`core.anchor.backends.OpenTimestampsBackend.verify` -> explorer
     merkle-root cross-check; ``confirmed`` only when a real Bitcoin block
     validates the attestation, never on the bare attestation object);
  4. write an UPGRADED manifest COPY (original file untouched) with the
     matured receipts (status/block/block_time updated, server ``ref`` kept).

No cryptography is implemented here - this module only wires the existing
upgrade + verify APIs together and adds bookkeeping (per-calendar/explorer
response stats, local path remapping, an early abort when the network is
plainly unreachable).

    python -m core.site.mature_anchors \
        --manifest backtest_data/live_server_pull/journal_poller_live.anchors.jsonl \
        --ots-dir backtest_data/live_server_pull/ots \
        --out backtest_data/live_server_pull/journal_poller_live.anchors.UPGRADED.jsonl
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any

from core.anchor.backends import AnchorReceipt, OpenTimestampsBackend
from core.anchor.bitcoin_verify import (
    DEFAULT_EXPLORERS,
    _fetch_block_header,
    _fetch_one,
    explorer_bitcoin_verify,
    upgrade_via_calendar,
)
from core.site.emitter import load_jsonl

_OTS_BACKEND = "opentimestamps"


def _iso(ts_unix: int) -> str:
    return datetime.fromtimestamp(int(ts_unix), tz=timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


class _NetStats:
    """Per-endpoint success/failure counters (calendars + explorers)."""

    def __init__(self) -> None:
        self.calendar_ok: dict[str, int] = {}
        self.calendar_err: dict[str, int] = {}
        self.explorer_ok: dict[str, int] = {}
        self.explorer_err: dict[str, int] = {}

    @property
    def any_success(self) -> bool:
        return bool(self.calendar_ok or self.explorer_ok)

    def summary_lines(self) -> list[str]:
        lines = []
        for uri in sorted(set(self.calendar_ok) | set(self.calendar_err)):
            lines.append(f"  calendar {uri}: ok={self.calendar_ok.get(uri, 0)} "
                         f"err={self.calendar_err.get(uri, 0)}")
        for uri in sorted(set(self.explorer_ok) | set(self.explorer_err)):
            lines.append(f"  explorer {uri}: ok={self.explorer_ok.get(uri, 0)} "
                         f"err={self.explorer_err.get(uri, 0)}")
        return lines


class _HeaderCache:
    """Cache of authoritatively fetched block headers (height -> header), with
    per-explorer response stats. Reuses the existing multi-explorer agreement
    fetch - this class only memoises and counts."""

    def __init__(self, stats: _NetStats, timeout: float) -> None:
        self._stats = stats
        self._timeout = timeout
        self.headers: dict[int, Any] = {}

    def _counting_fetch_one(self, base: str, height: int, timeout: float):
        out = _fetch_one(base, height, timeout)
        bucket = self._stats.explorer_ok if out is not None else self._stats.explorer_err
        bucket[base] = bucket.get(base, 0) + 1
        return out

    def fetch(self, height: int) -> Any:
        if height not in self.headers:
            self.headers[height] = _fetch_block_header(
                height, DEFAULT_EXPLORERS, self._timeout,
                fetch_one=self._counting_fetch_one,
            )
        return self.headers[height]


def _digest_map(ots_dir: str) -> dict[str, str]:
    """Fallback locator: digest hex (from each ``.digest`` sidecar's content)
    -> local ``.ots`` path."""
    out: dict[str, str] = {}
    for name in os.listdir(ots_dir):
        if not name.endswith(".digest"):
            continue
        path = os.path.join(ots_dir, name)
        try:
            with open(path, "rb") as fh:
                digest_hex = fh.read().hex()
        except OSError:
            continue
        ots_path = path[:-len(".digest")] + ".ots"
        if os.path.exists(ots_path):
            out[digest_hex] = ots_path
    return out


def _locate_ots(receipt: dict[str, Any], ots_dir: str,
                by_digest: dict[str, str]) -> str | None:
    """Local ``.ots`` for a receipt: server-path basename first, digest match
    as the fallback."""
    ref = str(receipt.get("ref") or "").replace("\\", "/")
    if ref:
        candidate = os.path.join(ots_dir, os.path.basename(ref))
        if os.path.exists(candidate):
            return candidate
    return by_digest.get(str(receipt.get("digest_hex") or ""))


def mature_manifest(
    manifest_path: str,
    ots_dir: str,
    out_path: str,
    *,
    timeout: float = 12.0,
    limit: int | None = None,
) -> dict[str, Any]:
    """Mature every pending OTS receipt of ``manifest_path`` against the local
    ``.ots`` proofs; write the upgraded manifest COPY to ``out_path``.

    Returns a summary dict (counts + per-endpoint stats + confirmed samples).
    Aborts early (with ``network_unreachable=True``) if the first few anchors
    show zero successful calendar AND explorer responses.
    """
    records = load_jsonl(manifest_path)
    stats = _NetStats()
    cache = _HeaderCache(stats, timeout)

    # Existing authoritative verifier, with the counting header fetch injected.
    backend = OpenTimestampsBackend(
        ots_dir,
        bitcoin_verify_fn=lambda path, digest: explorer_bitcoin_verify(
            path, digest, fetch_header=cache.fetch, timeout=timeout
        ),
        timeout=timeout,
    )

    def _counting_get(commitment: bytes, uri: str) -> Any:
        from opentimestamps.calendar import RemoteCalendar

        try:
            ts = RemoteCalendar(uri).get_timestamp(commitment, timeout=timeout)
        except Exception:
            stats.calendar_err[uri] = stats.calendar_err.get(uri, 0) + 1
            raise  # upgrade_via_calendar tolerates per-calendar failures
        stats.calendar_ok[uri] = stats.calendar_ok.get(uri, 0) + 1
        return ts

    by_digest = _digest_map(ots_dir)
    counts = {"total": len(records), "confirmed_new": 0, "already_confirmed": 0,
              "still_pending": 0, "unverified_explorer": 0, "no_local_ots": 0,
              "no_ots_receipt": 0}
    samples: list[dict[str, Any]] = []
    out_records: list[dict[str, Any]] = []
    network_unreachable = False
    processed = 0

    for rec in records:
        rec = dict(rec)
        receipts = list(rec.get("receipts") or [])
        idx = next((i for i, r in enumerate(receipts)
                    if r.get("backend") == _OTS_BACKEND), None)
        if idx is None:
            counts["no_ots_receipt"] += 1
            out_records.append(rec)
            continue
        receipt = receipts[idx]
        if receipt.get("status") == "confirmed":
            counts["already_confirmed"] += 1
            out_records.append(rec)
            continue
        if limit is not None and processed >= limit:
            out_records.append(rec)
            continue

        local_ots = _locate_ots(receipt, ots_dir, by_digest)
        if local_ots is None:
            counts["no_local_ots"] += 1
            out_records.append(rec)
            continue

        processed += 1
        # Work on a receipt whose ref points at the LOCAL proof.
        local_receipt = AnchorReceipt(**{**receipt, "ref": local_ots})

        # 1. upgrade: pull the Bitcoin attestation from the calendars (merges
        #    into the local .ots in place - the pulled proof becomes complete).
        try:
            upgrade_ran = upgrade_via_calendar(
                local_ots, get_timestamp_fn=_counting_get, timeout=timeout
            )
        except Exception:
            upgrade_ran = False

        # 2. authoritative verify: explorers must validate the merkle root.
        ok, info = backend.verify(local_receipt, local_receipt.digest_hex)

        new = AnchorReceipt(**{**receipt})  # server ref preserved in output
        new.detail = {**(receipt.get("detail") or {}),
                      "upgrade_ran": upgrade_ran, "verify": info}
        if ok and info.get("confirmed") and info.get("bitcoin_blocks"):
            height = int(info["bitcoin_blocks"][0])
            header = cache.headers.get(height)
            new.status = "confirmed"
            new.block = height
            new.block_time = _iso(header.nTime) if header is not None else None
            counts["confirmed_new"] += 1
            if len(samples) < 5:
                samples.append({"anchor_no": rec.get("anchor_no"),
                                "block": height, "block_time": new.block_time})
        elif info.get("claimed_bitcoin_blocks") and not info.get("bitcoin_blocks"):
            counts["unverified_explorer"] += 1  # attestation there, explorers not
        else:
            counts["still_pending"] += 1        # no Bitcoin attestation yet

        receipts[idx] = new.to_dict()
        rec["receipts"] = receipts
        out_records.append(rec)

        # Early abort: if the first anchors show a completely dead network,
        # report it instead of grinding through 74 timeouts.
        if processed == 3 and not stats.any_success:
            network_unreachable = True
            out_records.extend(records[len(out_records):])
            break

    tmp = out_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        for rec in out_records:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    os.replace(tmp, out_path)

    return {"counts": counts, "samples": samples, "stats": stats,
            "network_unreachable": network_unreachable, "out_path": out_path}


def main(argv: list[str] | None = None) -> None:
    import argparse

    ap = argparse.ArgumentParser(
        prog="python -m core.site.mature_anchors",
        description="Mature pending OTS receipts locally (upgrade + verify)",
    )
    ap.add_argument("--manifest", required=True, help="anchor manifest .jsonl (read-only)")
    ap.add_argument("--ots-dir", required=True, help="dir with the pulled .ots/.digest files")
    ap.add_argument("--out", required=True, help="UPGRADED manifest copy to write")
    ap.add_argument("--timeout", type=float, default=12.0, help="per-request timeout (s)")
    ap.add_argument("--limit", type=int, default=None, help="process at most N anchors")
    a = ap.parse_args(argv)

    res = mature_manifest(a.manifest, a.ots_dir, a.out,
                          timeout=a.timeout, limit=a.limit)
    c = res["counts"]
    print("=" * 72)
    print(f"  OTS MATURATION  total={c['total']}  confirmed_new={c['confirmed_new']}  "
          f"already={c['already_confirmed']}")
    print(f"  still_pending={c['still_pending']}  unverified_explorer="
          f"{c['unverified_explorer']}  no_local_ots={c['no_local_ots']}  "
          f"no_ots_receipt={c['no_ots_receipt']}")
    for line in res["stats"].summary_lines():
        print(line)
    for s in res["samples"]:
        print(f"  sample: anchor #{s['anchor_no']} -> btc block {s['block']} "
              f"@ {s['block_time']}")
    if res["network_unreachable"]:
        print("  !! NETWORK UNREACHABLE: no calendar or explorer responded - "
              "aborted early, manifest copied through unchanged")
    print(f"  -> {res['out_path']}")
    print("=" * 72, flush=True)


if __name__ == "__main__":
    main()
