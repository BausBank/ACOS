"""Actors file generator - the DEMO screen's static ``actors.json`` (Stage 19 data).

Builds the public actors list for the site's demo network screen from the REAL
Stage-19 artifacts (nothing is invented):

  * ``<demo-dir>/registry.json``        - the bound actors + their journal/fills;
  * ``<demo-dir>/demo_identity.jsonl``  - ERC-8004 passports (agentId, register tx);
  * ``<demo-dir>/demo_registry.jsonl``  - badge issue/revoke history (txs);
  * per-actor ``*.journal.jsonl`` / ``*.fills.jsonl`` (the impostor's published
    journal is its DOCTORED one - the demo's end state);
  * the LIVE actor's passport/badge from the Stage-18 attest files (default:
    ``<demo-dir>/../live/attest_identity.jsonl`` + ``attest_registry.jsonl``).

Every per-actor verification block is a REAL :func:`core.verify.verify.open_verify`
run (chain + seals + fills cross-check) - the log lines report what the verifier
actually found, and trade counts / P&L are recomputed from the artifacts. Values
absent from the artifacts are ``null``, never guessed. The finished document is
validated by :func:`core.site.redact.assert_public` before writing (fail closed).

    python -m core.site.actors --demo-dir backtest_data/demo --out site/actors.json
"""

from __future__ import annotations

import json
import os
from typing import Any

from core.site.emitter import emit_snapshot, load_jsonl
from core.site.redact import assert_public

ACTORS_SCHEMA = 1

# The capital base the demo VTR service verifies against (VtrService default).
_DEMO_CAPITAL = 350.0

# Display names + taglines (site copy, fixed). The numbers in a tagline are
# narrative copy for the screen; the FIELDS next to them are computed from the
# artifacts and are the source of truth.
_LIVE_NAME = "ACOS AGENT"
_LIVE_TAGLINE = "Our real trading agent — same check as everyone."
_DEMO_NAMES = {
    "capitalarc-alpha": "ALPHA α",
    "agent-beta": "BETA β",
    "agent-gamma": "GAMMA γ",
}
_DEMO_TAGLINES = {
    "capitalarc-alpha": "Full honest track. Loses money, hides nothing.",
    "agent-beta": "The impostor. Erased its worst loss — claims +$3, fills say −$15.",
    "agent-gamma": "A shorter honest slice — different history, same rules.",
}
_DEMO_ORDER = ("capitalarc-alpha", "agent-beta", "agent-gamma")


def _norm_hash(h: Any) -> str:
    """Normalise a request hash for matching (issue rows store it bare, revoke
    rows may carry a ``0x`` prefix)."""
    s = str(h or "")
    return (s[2:] if s[:2].lower() == "0x" else s).lower()


def _resolve(demo_dir: str, recorded_path: str) -> str:
    """Registry paths were recorded relative to the build cwd (with Windows
    separators); resolve by basename inside the given demo dir."""
    base = os.path.basename(str(recorded_path).replace("\\", "/"))
    return os.path.join(demo_dir, base)


# --------------------------------------------------------------------------- #
# badge / identity readers (shared by demo + live actors)                      #
# --------------------------------------------------------------------------- #
def _badge_rows(registry_rows: list[dict[str, Any]], subject: str) -> dict[str, Any]:
    """Fold a subject's issue/revoke history into its current badge state."""
    issued: dict[str, dict[str, Any]] = {}
    revoked: dict[str, dict[str, Any]] = {}
    last_issued: dict[str, Any] | None = None
    last_revoked: dict[str, Any] | None = None
    for r in registry_rows:
        if r.get("subject") != subject or not r.get("request_hash"):
            continue
        rh = _norm_hash(r.get("request_hash"))
        if r.get("event") == "issued":
            issued[rh] = r
            last_issued = r
        elif r.get("event") == "revoked":
            revoked[rh] = r
            last_revoked = r
    active = [row for rh, row in issued.items() if rh not in revoked]
    return {
        "active": active,
        "last_issued": last_issued,
        "last_revoked": last_revoked,
        "ever_issued": bool(issued),
    }


def _build_badge(state: dict[str, Any]) -> dict[str, Any] | None:
    """Public badge block: verified (an active badge exists) or revoked."""
    if state["active"]:
        return {
            "status": "verified",
            "response": 100,
            "issued_at": (state["last_issued"] or {}).get("ts"),
        }
    if state["ever_issued"]:
        return {
            "status": "revoked",
            "response": 0,
            "issued_at": (state["last_issued"] or {}).get("ts"),
        }
    return None


def _build_refs(
    identity_row: dict[str, Any] | None, state: dict[str, Any]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Whitelisted reference lists from the identity + badge history rows.

    Returns ``(tx_refs, circle_refs)``: a value starting with ``0x`` is an
    on-chain transaction hash (explorer-linkable) -> ``tx_refs`` ``{label,tx}``;
    anything else is a Circle Console settle/request id (a UUID, NOT a chain
    tx) -> ``circle_refs`` ``{label,id}`` - the site must not render those as
    explorer links.
    """
    tx_refs: list[dict[str, Any]] = []
    circle_refs: list[dict[str, Any]] = []

    def _add(label: str, value: Any) -> None:
        if not value:
            return
        if str(value).startswith("0x"):
            tx_refs.append({"label": label, "tx": value})
        else:
            circle_refs.append({"label": label, "id": value})

    if identity_row:
        _add("identity registered (ERC-8004)",
             identity_row.get("register_tx_hash") or identity_row.get("register_tx"))
    li = state.get("last_issued") or {}
    _add("verification request", li.get("request_tx"))
    _add("validation response", li.get("response_tx"))
    _add("badge feedback", li.get("feedback_tx"))
    if not state.get("active"):
        lr = state.get("last_revoked") or {}
        _add("badge revoked", lr.get("revoke_feedback_tx"))
        _add("response downgraded", lr.get("downgrade_tx"))
    return tx_refs, circle_refs


# --------------------------------------------------------------------------- #
# the 4-line verify log (a REAL open_verify run, reported plainly)             #
# --------------------------------------------------------------------------- #
_CHAIN_MARKERS = ("hash mismatch", "chain link", "seq", "timestamp")
_SEAL_MARKERS = ("commit", "reveal", "manifest")


def _verify_log(
    journal: list[dict[str, Any]],
    fills: list[dict[str, Any]],
    badge: dict[str, Any] | None,
    state: dict[str, Any],
) -> list[str]:
    from core.verify.verify import open_verify

    rep = open_verify(journal, fills=fills, equity_start=_DEMO_CAPITAL,
                      check_anchors=False)
    jrep = rep.journal
    issues = list(jrep.issues) if jrep else []
    chain_ok = not any(m in i for i in issues for m in _CHAIN_MARKERS)
    seals_ok = not any(m in i for i in issues for m in _SEAL_MARKERS)
    lines = [
        f"chain ............ {'PASS' if chain_ok else 'FAIL'}",
        f"seals ............ {'PASS' if seals_ok else 'FAIL'}",
    ]

    crep = rep.crosscheck
    if crep is None or not crep.applicable:
        lines.append("fills cross-check  N/A — nothing to pair")
    elif crep.ok:
        lines.append("fills cross-check  PASS — journal matches venue record")
    else:
        unmatched = list(crep.unmatched_recomputed) + list(crep.unmatched_claimed)
        n = len(unmatched)
        losing = bool(unmatched) and all(
            float(getattr(t, "net_pnl", 0.0)) < 0 for t in crep.unmatched_recomputed
        ) and not crep.unmatched_claimed
        noun = ("losing round-trip" if losing else "round-trip") + ("s" if n != 1 else "")
        lines.append(f"fills cross-check  FAIL — {n} unmatched {noun}")

    if badge is not None and badge["status"] == "verified":
        tx = (state.get("last_issued") or {}).get("response_tx") or "-"
        lines.append(f"→ validationResponse(100) · badge issued · tx {tx}")
    elif badge is not None:
        tx = (state.get("last_revoked") or {}).get("revoke_feedback_tx") or "-"
        lines.append(f"→ validationResponse(0) · badge revoked · tx {tx}")
    else:
        lines.append("→ no badge on record")
    return lines


# --------------------------------------------------------------------------- #
# actor builders                                                               #
# --------------------------------------------------------------------------- #
def _build_demo_actor(
    subject: str,
    meta: dict[str, Any],
    demo_dir: str,
    identity_by_actor: dict[str, dict[str, Any]],
    registry_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    from core.verify.fills_pnl import recompute_from_fills

    # The impostor PUBLISHES its doctored journal (the demo's end state); the
    # honest actors publish their honest one.
    journal_path = _resolve(
        demo_dir, meta.get("doctored_journal_path") or meta["journal_path"]
    )
    fills_path = _resolve(demo_dir, meta["fills_path"])
    journal = load_jsonl(journal_path)
    fills = load_jsonl(fills_path)

    rc = recompute_from_fills(fills)
    identity = identity_by_actor.get(subject)
    state = _badge_rows(registry_rows, subject)
    badge = _build_badge(state)
    tx_refs, circle_refs = _build_refs(identity, state)

    return {
        "name": _DEMO_NAMES.get(subject, subject.upper()),
        "kind": "demo",
        "tagline": _DEMO_TAGLINES.get(subject),
        "n_trades_journal": sum(1 for e in journal if e.get("kind") == "reveal"),
        "n_trades_fills": rc.n_trades,
        "net_pnl_usd": round(rc.net_pnl, 2),
        "badge": badge,
        "passport_id": (identity or {}).get("agent_id"),
        "tx_refs": tx_refs,
        "circle_refs": circle_refs,
        "last_verify": {"log": _verify_log(journal, fills, badge, state)},
    }


def _build_live_actor(
    live_identity_path: str | None, live_registry_path: str | None
) -> dict[str, Any]:
    """The real agent's card: passport/badge facts from the Stage-18 attest
    files when present, ``null`` otherwise. Its live trade numbers come from
    ``snapshot.json`` (the emitter), not this static file."""
    identity_rows = (
        load_jsonl(live_identity_path)
        if live_identity_path and os.path.exists(live_identity_path) else []
    )
    registry_rows = (
        load_jsonl(live_registry_path)
        if live_registry_path and os.path.exists(live_registry_path) else []
    )
    # The registered passport row (latest row that actually carries an agentId).
    identity = None
    for row in identity_rows:
        if row.get("agent_id") is not None:
            identity = row
    subject = (identity or {}).get("actor")
    state = _badge_rows(registry_rows, subject) if subject else {
        "active": [], "last_issued": None, "last_revoked": None, "ever_issued": False,
    }
    badge = _build_badge(state)
    tx_refs, circle_refs = _build_refs(identity, state)
    return {
        "name": _LIVE_NAME,
        "kind": "live",
        "tagline": _LIVE_TAGLINE,
        "n_trades_journal": None,   # live numbers come from snapshot.json
        "n_trades_fills": None,
        "net_pnl_usd": None,
        "badge": badge,
        "passport_id": (identity or {}).get("agent_id"),
        "tx_refs": tx_refs,
        "circle_refs": circle_refs,
        "last_verify": None,        # the live check is run/shown by the emitter side
    }


def build_actors(
    demo_dir: str,
    *,
    live_identity_path: str | None = None,
    live_registry_path: str | None = None,
) -> dict[str, Any]:
    """Build the actors document from the Stage-19 (+ Stage-18 live) artifacts.

    Defaults for the live attest files: ``<demo-dir>/../live/attest_*.jsonl``.
    The result is validated by :func:`core.site.redact.assert_public` (raises
    instead of returning a leaky document).
    """
    parent = os.path.dirname(os.path.abspath(demo_dir))
    if live_identity_path is None:
        live_identity_path = os.path.join(parent, "live", "attest_identity.jsonl")
    if live_registry_path is None:
        live_registry_path = os.path.join(parent, "live", "attest_registry.jsonl")

    with open(os.path.join(demo_dir, "registry.json"), encoding="utf-8") as fh:
        registry = json.load(fh)
    actors_meta: dict[str, Any] = registry["actors"]

    identity_by_actor = {
        row.get("actor"): row
        for row in load_jsonl(os.path.join(demo_dir, "demo_identity.jsonl"))
    }
    registry_rows = load_jsonl(os.path.join(demo_dir, "demo_registry.jsonl"))

    actors = [_build_live_actor(live_identity_path, live_registry_path)]
    ordered = [s for s in _DEMO_ORDER if s in actors_meta] + [
        s for s in actors_meta if s not in _DEMO_ORDER
    ]
    for subject in ordered:
        actors.append(_build_demo_actor(
            subject, actors_meta[subject], demo_dir, identity_by_actor, registry_rows
        ))

    doc = {"schema": ACTORS_SCHEMA, "actors": actors}
    assert_public(doc)  # fail closed: a leaky document is never returned
    return doc


def main(argv: list[str] | None = None) -> None:
    import argparse
    import sys

    # The actor names carry Greek letters; a cp125x Windows console would
    # otherwise crash the summary print (the JSON itself is always UTF-8).
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")

    ap = argparse.ArgumentParser(
        prog="python -m core.site.actors",
        description="Build the demo-screen actors.json from Stage-19 artifacts",
    )
    ap.add_argument("--demo-dir", required=True,
                    help="demo artifacts dir (registry.json, demo_*.jsonl, tracks)")
    ap.add_argument("--live-identity", default=None,
                    help="live attest identity .jsonl (default: <demo-dir>/../live/)")
    ap.add_argument("--live-registry", default=None,
                    help="live attest registry .jsonl (default: <demo-dir>/../live/)")
    ap.add_argument("--out", required=True, help="output actors.json path")
    a = ap.parse_args(argv)

    doc = build_actors(
        a.demo_dir,
        live_identity_path=a.live_identity,
        live_registry_path=a.live_registry,
    )
    emit_snapshot(doc, a.out)  # same atomic pretty-JSON writer

    print("=" * 72)
    for actor in doc["actors"]:
        badge = actor["badge"] or {}
        print(f"  {actor['name']:<12} [{actor['kind']:<4}]  "
              f"badge={badge.get('status', '-'):<8}  "
              f"passport={actor['passport_id'] or '-'}")
    print(f"  -> {a.out}")
    print("=" * 72, flush=True)


if __name__ == "__main__":
    main()
