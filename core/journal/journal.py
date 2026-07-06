"""Append-only, hash-chained VTR journal (Stage 12) - the trust primitive.

A :class:`Journal` is an ordered, tamper-evident log of an actor's events.
Each entry stores the hash of the previous entry (``prev_hash``), so editing,
deleting, inserting or reordering any past entry changes its hash and breaks
the chain link of every entry after it - the tampering becomes self-evident
(verified by :mod:`core.journal.verify`).

Two phases of disclosure (the commit-reveal envelope):

  * :meth:`commit` - at decision time, *before* the outcome is known, write
    ONLY a sealed hash of the payload (payload + random salt are kept private,
    NOT in the public journal). This proves the decision was fixed before the
    result.
  * :meth:`reveal` - after the outcome is known (the position closed), disclose
    the original payload + salt + outcome. A verifier re-hashes and confirms it
    matches the earlier commit, so the *committed decision* (side / size / entry
    / stop / target) cannot be changed with hindsight. The disclosed ``outcome``
    is necessarily added at reveal (it is unknowable at commit), so it is NOT
    sealed by the commitment - its integrity rests on the hash-chain plus the
    Stage-13 anchored head and the Stage-16 recompute from public exchange
    fills, not on the commit hash.

Plain (non-sealed) entries:

  * :meth:`set_manifest` - the first entry: the stack "passport" (actor, model,
    strategy version, config fingerprint) that says *what* produced the run.
  * :meth:`event` - any other clear-text, chained record (skips, daily equity
    checkpoints, run start/end). Tamper-evident via the chain, but with no
    deferred outcome to hide there is nothing to seal.

The journal is ENTITY-AGNOSTIC: it hashes plain JSON values and knows nothing
about trading. The trade-aware translation (open -> commit, close -> reveal)
lives in the caller (the telemetry emitter), keeping this module reusable for
any actor whose track must be verifiable.

Stage scope: this is the OFFLINE primitive. On-chain anchoring of
:meth:`batch_root` to Arc + Bitcoin is Stage 13; recomputing P&L from public
exchange fills is Stage 16. Pending commit secrets (salt+payload between commit
and reveal) are persisted to a sidecar ``<journal>.pending.jsonl`` (Stage 14) so
a restarted live process can still reveal opens committed before the restart;
with ``append=True`` the chain itself is resumed (seq / head / pending) from the
existing file. The sidecar holds the commit SECRETS - it is never published.
"""

from __future__ import annotations

import json
import os
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, TextIO

from core.journal.canonical import (
    GENESIS,
    commitment,
    hash_obj,
    merkle_root,
    require_finite,
)

JOURNAL_SCHEMA = 1


def _iso(dt: datetime) -> str:
    """ISO-8601 UTC, second precision, trailing Z (matches the telemetry feed)."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True)
class Manifest:
    """The stack "passport" stamped as the journal's first entry.

    Entity-agnostic: ``actor`` / ``actor_kind`` describe *who* (an agent, a
    human, a service); ``model`` / ``strategy`` / ``strategy_version`` /
    ``config_fingerprint`` describe *what brain + config* produced the
    decisions. A change of any of these is an honest new segment of the track,
    not a reset (the journal stays append-only across segments).
    """

    actor: str
    actor_kind: str            # "agent" | "human" | "service" | ...
    model: str                 # e.g. "synthetic-L3 (deterministic reblend)"
    strategy: str
    strategy_version: str
    config_fingerprint: str
    run_id: str
    mode: str                  # "live" | "dry-run" | "replay"
    symbols: tuple[str, ...] = ()
    journal_schema: int = JOURNAL_SCHEMA
    notes: str = ""

    def to_body(self) -> dict[str, Any]:
        return {
            "actor": self.actor,
            "actor_kind": self.actor_kind,
            "model": self.model,
            "strategy": self.strategy,
            "strategy_version": self.strategy_version,
            "config_fingerprint": self.config_fingerprint,
            "run_id": self.run_id,
            "mode": self.mode,
            "symbols": list(self.symbols),
            "journal_schema": self.journal_schema,
            "notes": self.notes,
        }


@dataclass
class Journal:
    """Append-only hash-chained journal with commit-reveal.

    Parameters
    ----------
    jsonl_path
        File to write entries to (one JSON object per line). ``None`` keeps the
        journal in-memory only (tests).
    salt_fn
        Source of commit salt. Default = 16 cryptographically-random bytes as
        hex. Tests inject a deterministic source for reproducibility.
    append
        ``False`` (default) truncates the file (a clean single-run artifact);
        ``True`` appends across restarts (a continuous live journal).
    """

    jsonl_path: str | None = None
    salt_fn: Callable[[], str] = field(default=lambda: secrets.token_hex(16))
    append: bool = False

    def __post_init__(self) -> None:
        self._seq = 0
        self._head = GENESIS
        self._manifest_set = False
        self._pending: dict[str, dict[str, Any]] = {}  # ref -> {payload, salt} (secret)
        self._revealed: set[str] = set()
        self.entries: list[dict[str, Any]] = []        # in-memory mirror
        # Sidecar secret store: salt+payload of every still-open commit, so a
        # restarted live process can reveal them. Holds SECRETS - lives next
        # to the journal (gitignored) and is never published.
        self._pending_path: str | None = (
            self.jsonl_path + ".pending.jsonl" if self.jsonl_path else None
        )
        # Resume an existing chain when appending: continue the SAME hash-chain
        # (seq / head) and restore the open commits' secrets from the sidecar.
        if (
            self.append
            and self.jsonl_path
            and os.path.exists(self.jsonl_path)
            and os.path.getsize(self.jsonl_path) > 0
        ):
            self._resume()
        self._fh: TextIO | None = (
            open(self.jsonl_path, "a" if self.append else "w", encoding="utf-8")
            if self.jsonl_path else None
        )
        self._pfh: TextIO | None = (
            open(self._pending_path, "a" if self.append else "w", encoding="utf-8")
            if self._pending_path else None
        )

    # ---- resume / durable pending secrets ----
    def _resume(self) -> None:
        """Restore chain state (seq / head / manifest / revealed) from the
        existing journal file and the open commit secrets from the sidecar.

        Only refs that BOTH have a commit in the chain AND are not yet revealed
        are restored to ``_pending`` - so a crash between the sidecar write and
        the journal append (in either order) can never resurrect a phantom ref.
        """
        committed: set[str] = set()
        revealed: set[str] = set()
        last: dict[str, Any] | None = None
        with open(self.jsonl_path, encoding="utf-8") as fh:  # type: ignore[arg-type]
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue  # torn final line (power loss): entry never committed
                self.entries.append(entry)
                kind = entry.get("kind")
                if kind == "manifest":
                    self._manifest_set = True
                elif kind == "commit":
                    committed.add(entry.get("ref"))
                elif kind == "reveal":
                    revealed.add(entry.get("ref"))
                last = entry
        if last is not None:
            self._seq = int(last["seq"])
            self._head = last["hash"]
        self._revealed = revealed
        open_secrets: dict[str, dict[str, Any]] = {}
        if self._pending_path and os.path.exists(self._pending_path):
            with open(self._pending_path, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    # Tolerate a torn / incomplete final line (power loss
                    # mid-write): it can only belong to a commit whose CHAIN
                    # entry never landed (an orphan the filter below drops
                    # anyway), so skipping it loses nothing recoverable - while a
                    # bare raise here would brick the journal on every restart.
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    ref = rec.get("ref")
                    state = rec.get("state")
                    if state == "open":
                        payload, salt = rec.get("payload"), rec.get("salt")
                        if ref is None or payload is None or salt is None:
                            continue  # incomplete 'open' record -> skip
                        open_secrets[ref] = {"payload": payload, "salt": salt}
                    elif state == "revealed":
                        open_secrets.pop(ref, None)
        self._pending = {
            ref: sec for ref, sec in open_secrets.items()
            if ref in committed and ref not in revealed
        }

    def _write_pending(
        self, ref: str, state: str, *,
        payload: dict[str, Any] | None = None, salt: str | None = None,
    ) -> None:
        """Append a secret record to the sidecar (``open`` carries salt+payload;
        ``revealed`` is a tombstone). No-op for in-memory journals."""
        if self._pfh is None:
            return
        rec: dict[str, Any] = {"ref": ref, "state": state}
        if state == "open":
            rec["payload"] = payload
            rec["salt"] = salt
        self._pfh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        self._pfh.flush()

    # ---- low-level chain append ----
    def _append(
        self, kind: str, ref: str | None, body: dict[str, Any], ts: datetime
    ) -> dict[str, Any]:
        # Reject NaN/Inf BEFORE touching any chain state, with a typed error
        # carrying the offending path (the caller can skip the record). Then
        # do all fallible work (hashing) before mutating seq/head/entries, so
        # a failure leaves the chain exactly where it was - never half-advanced.
        require_finite(body)
        seq = self._seq + 1
        entry: dict[str, Any] = {
            "v": JOURNAL_SCHEMA,
            "seq": seq,
            "ts": _iso(ts),
            "kind": kind,
            "ref": ref,
            "body": body,
            "prev_hash": self._head,
        }
        # The entry hash covers every field EXCEPT the hash itself.
        entry["hash"] = hash_obj(entry)
        # Commit state only after hashing succeeded.
        self._seq = seq
        self._head = entry["hash"]
        self.entries.append(entry)
        if self._fh is not None:
            self._fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
            self._fh.flush()
        return entry

    # ---- public API ----
    def set_manifest(self, manifest: Manifest, *, ts: datetime) -> dict[str, Any]:
        """Stamp the stack passport. Must be the FIRST entry, exactly once."""
        if self._manifest_set:
            raise ValueError("manifest already set")
        if self._seq != 0:
            raise ValueError("manifest must be the first journal entry")
        self._manifest_set = True
        return self._append("manifest", None, manifest.to_body(), ts)

    def commit(self, *, ref: str, payload: dict[str, Any], ts: datetime) -> dict[str, Any]:
        """Seal a decision before its outcome. Stores only the commit hash;
        payload + salt are kept private until :meth:`reveal`."""
        if not self._manifest_set:
            raise ValueError("set_manifest() before committing")
        if ref in self._pending or ref in self._revealed:
            raise ValueError(f"duplicate commit for ref {ref!r}")
        # Validate the payload (sealed into the commit hash) before we persist
        # any secret or advance the chain.
        require_finite(payload)
        salt = self.salt_fn()
        self._pending[ref] = {"payload": payload, "salt": salt}
        # Persist the secret FIRST (durable), then chain the commit. If we crash
        # between the two, _resume() drops the orphan secret because no commit
        # for ``ref`` exists in the chain.
        self._write_pending(ref, "open", payload=payload, salt=salt)
        return self._append("commit", ref, {"commit_hash": commitment(payload, salt)}, ts)

    def reveal(self, *, ref: str, outcome: dict[str, Any], ts: datetime) -> dict[str, Any]:
        """Disclose a previously committed decision after its outcome is known.
        Writes payload + salt + outcome; a verifier checks they re-hash to the
        commit. Raises if ``ref`` was never committed."""
        if ref not in self._pending:
            raise ValueError(f"reveal for un-committed ref {ref!r}")
        rec = self._pending[ref]
        body = {"payload": rec["payload"], "salt": rec["salt"], "outcome": outcome}
        # Chain the reveal FIRST (this also runs the non-finite guard on the
        # outcome); only mark the ref closed once it is durably chained. If we
        # crash after the reveal entry but before the sidecar tombstone,
        # _resume() still excludes ``ref`` via the chain's revealed set.
        entry = self._append("reveal", ref, body, ts)
        self._pending.pop(ref, None)
        self._revealed.add(ref)
        self._write_pending(ref, "revealed")
        return entry

    def event(self, *, tag: str, body: dict[str, Any], ts: datetime) -> dict[str, Any]:
        """Append a clear-text, chained record (no commit-reveal). ``tag`` goes
        in ``ref`` to label the event kind (e.g. "skip", "cycle", "run_end")."""
        if not self._manifest_set:
            raise ValueError("set_manifest() before logging events")
        return self._append("event", tag, body, ts)

    # ---- Stage-13 anchoring hook ----
    def batch_root(self, start_seq: int = 1, end_seq: int | None = None) -> str:
        """Merkle root over the entry hashes of ``[start_seq, end_seq]`` (both
        inclusive; ``end_seq=None`` = up to the head). The cheap on-chain
        anchoring hook: Stage 13 writes this single hash to Arc + Bitcoin."""
        end = self._seq if end_seq is None else end_seq
        leaves = [e["hash"] for e in self.entries if start_seq <= e["seq"] <= end]
        return merkle_root(leaves)

    # ---- accessors / lifecycle ----
    @property
    def head(self) -> str:
        """Current chain-tip hash (commits to the entire prefix)."""
        return self._head

    @property
    def seq(self) -> int:
        return self._seq

    @property
    def manifest_set(self) -> bool:
        """True once the manifest is stamped (or restored on resume). A
        resuming live driver checks this to avoid a second set_manifest()."""
        return self._manifest_set

    def pending_refs(self) -> set[str]:
        """Refs committed but not yet revealed (open positions)."""
        return set(self._pending)

    def close(self) -> None:
        if self._fh is not None:
            self._fh.close()
            self._fh = None
        if self._pfh is not None:
            self._pfh.close()
            self._pfh = None

    def __enter__(self) -> "Journal":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


__all__ = ["Journal", "Manifest", "JOURNAL_SCHEMA"]
