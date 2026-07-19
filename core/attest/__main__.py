"""CLI for the ERC-8004 attestation layer.

    python -m core.attest register --actor <a> --actor-kind agent [--live]
    python -m core.attest demo     --actor <a> --journal <j> [--live]
    python -m core.attest status   --request-hash <h>
    python -m core.attest revoke   --request-hash <h> [--live]

Default is DRY-RUN everywhere (builds the calls, broadcasts nothing). ``--live``
opts in to real Arc transactions through the configured wallets.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
from datetime import datetime, timezone
from typing import Any

from core.attest import config as cfg
from core.attest import erc8004
from core.attest.client import compute_request_hash
from core.attest.identity import IdentityStore, register_actor
from core.attest.registry import AttestRegistry


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_jsonl(path: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    with open(path, encoding="utf-8") as fh:
        for ln in fh:
            ln = ln.strip()
            if ln:
                out.append(json.loads(ln))
    return out


def _explorer_tx(tx_hash: str | None) -> str:
    if not tx_hash or not str(tx_hash).startswith("0x"):
        return "(dry-run / no on-chain tx)"
    return f"{erc8004.ARC_TESTNET_EXPLORER}/tx/{tx_hash}"


async def cmd_register(args: argparse.Namespace) -> None:
    client = cfg.build_attest_client(dry_run=not args.live, with_reader=args.live)
    store = IdentityStore(cfg.default_identity_map_path())
    try:
        row = await register_actor(
            client, store,
            actor=args.actor, actor_kind=args.actor_kind,
            metadata_uri=args.metadata_uri, ts=_now(),
        )
    finally:
        await client.aclose()
    print(json.dumps(row, indent=2, ensure_ascii=False))


async def cmd_demo(args: argparse.Namespace) -> None:
    from core.verify import open_verify
    from core.x402.server import verdict_digest

    journal = _load_jsonl(args.journal)
    rep = open_verify(journal)  # journal-integrity verdict (PASS on a clean track)
    result = {
        "ok": rep.ok, "checks": rep.checks,
        "summary": rep.summary(), "track_ref": args.actor,
    }
    digest = verdict_digest(result)
    print(f"verdict: ok={rep.ok}  digest={digest}")
    if not rep.ok:
        print("track did NOT pass; refusing to issue a badge.")
        return

    client = cfg.build_attest_client(dry_run=not args.live, with_reader=args.live)
    store = IdentityStore(cfg.default_identity_map_path())
    registry = AttestRegistry(cfg.default_registry_path())
    try:
        row = await register_actor(
            client, store,
            actor=args.actor, actor_kind=args.actor_kind,
            metadata_uri=args.metadata_uri, ts=_now(),
        )
        agent_id = row.get("agent_id")
        print(f"identity: agent_id={agent_id}  register_tx={_explorer_tx(row.get('register_tx_hash'))}")
        if agent_id is None:
            if not args.live:
                print("(dry-run: no on-chain agentId minted; rerun with --live for the proof)")
                agent_id = 0  # placeholder so the dry-run pipeline still exercises
            else:
                print("ERROR: live register returned no agentId; aborting.")
                return

        ts = _now()
        request_hash = compute_request_hash(int(agent_id), digest, ts)
        ev = cfg.evidence_uri()
        badge_ref = await client.issue(
            agent_id=int(agent_id), verdict_digest=digest, request_hash=request_hash,
            request_uri=ev, response_uri=ev, feedback_uri=ev,
        )
        registry.record_issue(
            subject=args.actor, actor_kind=args.actor_kind,
            badge_ref=badge_ref, ts=ts,
        )
        print("badge issued:")
        print(f"  request_hash : 0x{request_hash}")
        print(f"  request_tx   : {_explorer_tx(badge_ref.get('request_tx_hash'))}")
        print(f"  response_tx  : {_explorer_tx(badge_ref.get('response_tx_hash'))}")
        print(f"  feedback_tx  : {_explorer_tx(badge_ref.get('feedback_tx_hash'))}")
        print(f"  feedback_idx : {badge_ref.get('feedback_index')}")

        status = client.read_status(request_hash)
        if status is not None:
            print("read-back (getValidationStatus):")
            print(f"  response={status['response']} passed={status['passed']} "
                  f"validator={status['validator']} agentId={status['agent_id']}")
            ok = (status["passed"]
                  and str(status["response_hash"]).lower() == digest.lower())
            print(f"  VERIFIED ON-CHAIN: {ok}")
        else:
            print("read-back: (dry-run / no chain reader)")
    finally:
        await client.aclose()


async def cmd_set_uri(args: argparse.Namespace) -> None:
    client = cfg.build_attest_client(dry_run=not args.live, with_reader=args.live)
    try:
        tx = await client.set_agent_uri(args.agent_id, args.uri)
        print(f"setAgentURI tx: {_explorer_tx(tx.tx_hash)}")
        if args.live and client.chain_reader is not None:
            print(f"tokenURI now: {client.chain_reader.token_uri(args.agent_id)!r}")
    finally:
        await client.aclose()


async def cmd_status(args: argparse.Namespace) -> None:
    client = cfg.build_attest_client(dry_run=False, with_reader=True)
    try:
        st = client.read_status(args.request_hash)
    finally:
        await client.aclose()
    print(json.dumps(st, indent=2, ensure_ascii=False) if st else "no status")


async def cmd_revoke(args: argparse.Namespace) -> None:
    registry = AttestRegistry(cfg.default_registry_path())
    row = next(
        (r for r in registry.load()
         if r.get("event") == "issued"
         and (str(r.get("request_hash") or "").lstrip("0x")
              == args.request_hash.lstrip("0x"))),
        None,
    )
    if row is None:
        print("no issued badge with that request_hash in the registry")
        return
    agent_id = int(row["agent_id"])
    feedback_index = (
        args.feedback_index if args.feedback_index is not None
        else row.get("feedback_index")
    )
    client = cfg.build_attest_client(dry_run=not args.live, with_reader=args.live)
    try:
        out = await client.revoke(
            agent_id=agent_id, request_hash=args.request_hash,
            feedback_index=feedback_index, response_uri=cfg.evidence_uri(),
        )
        registry.record_revoke(
            subject=row.get("subject", ""), actor_kind=row.get("actor_kind", ""),
            revoke_ref={**out, "agent_id": agent_id}, ts=_now(),
        )
    finally:
        await client.aclose()
    print(json.dumps(out, indent=2, ensure_ascii=False))


def main() -> None:
    cfg.load_dotenv()  # so ATTEST_* env (incl. metadata) is visible to defaults below
    p = argparse.ArgumentParser(prog="python -m core.attest")
    sub = p.add_subparsers(dest="cmd", required=True)

    default_meta = os.getenv("ATTEST_METADATA_URI", "VTR - [Verified Track Record]")

    pr = sub.add_parser("register", help="register an actor's identity (idempotent)")
    pr.add_argument("--actor", required=True)
    pr.add_argument("--actor-kind", default="agent")
    pr.add_argument("--metadata-uri", default=default_meta)
    pr.add_argument("--live", action="store_true")

    pd = sub.add_parser("demo", help="end-to-end: verify -> PASS -> issue -> read back")
    pd.add_argument("--actor", required=True)
    pd.add_argument("--actor-kind", default="agent")
    pd.add_argument("--metadata-uri", default=default_meta)
    pd.add_argument(
        "--journal",
        default="data/journal_smoke.jsonl",
    )
    pd.add_argument("--live", action="store_true")

    ps = sub.add_parser("status", help="read a badge back from the chain")
    ps.add_argument("--request-hash", required=True)

    pv = sub.add_parser("revoke", help="revoke a previously issued badge")
    pv.add_argument("--request-hash", required=True)
    pv.add_argument("--feedback-index", type=int, default=None)
    pv.add_argument("--live", action="store_true")

    pu = sub.add_parser("set-uri", help="update a passport's tokenURI on-chain")
    pu.add_argument("--agent-id", type=int, required=True)
    pu.add_argument("--uri", required=True)
    pu.add_argument("--live", action="store_true")

    args = p.parse_args()
    handler = {
        "register": cmd_register, "demo": cmd_demo,
        "status": cmd_status, "revoke": cmd_revoke, "set-uri": cmd_set_uri,
    }[args.cmd]
    asyncio.run(handler(args))


if __name__ == "__main__":
    main()
