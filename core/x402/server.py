"""aiohttp Trust Toll cashier endpoint (Stage 17).

The seller side of the x402 flow. Wraps the Stage-16 open verifier behind a
sub-cent USDC paywall settled by Circle Gateway Nanopayments:

    GET/POST /verify  (no payment)        -> 402 + PAYMENT-REQUIRED (price + how to pay)
    GET/POST /verify  + PAYMENT-SIGNATURE -> settle via Gateway -> open_verify ->
                                             200 + verdict + PAYMENT-RESPONSE
    GET /            -> free service info (price, network, pay-to)
    GET /healthz     -> free liveness

Two verification modes (entity-agnostic):
  * **submitted track** - the client POSTs ``{journal, manifest?, fills?, capital?}``
    and we verify exactly that (any actor can verify their own track);
  * **default track** - if no track is submitted, we verify our OWN configured
    track (a stable snapshot), so a one-click demo needs no data prep.

Trust split (hybrid): Circle Gateway moves the money; the **verdict** is hashed
to a digest and (optionally) anchored on OUR independent rail so a skeptic
re-checks PASS/FAIL from the public chain without trusting Circle. Verdict
anchoring defaults to OFF here - broadcasting from the live anchor key would race
its hourly nonce; wire a dedicated key / batch job to turn it on.
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from typing import Any, Callable

from aiohttp import web

from core.verify import open_verify
from core.x402.gateway import GatewayError, GatewayFacilitator
from core.x402.ledger import TollLedger, TollReceipt, utc_now_iso
from core.x402.protocol import (
    HEADER_PAYMENT_REQUIRED,
    HEADER_PAYMENT_RESPONSE,
    HEADER_PAYMENT_SIGNATURE,
    build_payment_required,
    build_payment_response,
    decode_header,
    encode_header,
    requirements_from_supported_kind,
)
from core.x402.ratelimit import TokenBucket

_UNSET = object()

# Verify function: takes the parsed request body (the track, or {}) and returns
# {ok: bool, checks: dict, summary: str, track_ref: str}. Injectable for tests.
VerifyFn = Callable[[dict[str, Any]], dict[str, Any]]
# Anchor function: takes the verdict digest hex, returns an anchor ref or None.
AnchorFn = Callable[[str], "str | None"]
# Badge function: takes (verify result, digest); issues an ERC-8004 "Verified"
# badge on PASS and returns a badge ref, or None. Best-effort; never blocks.
BadgeFn = Callable[[dict[str, Any], str], "dict[str, Any] | None"]

# Typed aiohttp app keys (avoids NotAppKeyWarning + gives static typing).
KEY_GATEWAY = web.AppKey("gateway", object)
KEY_LEDGER = web.AppKey("ledger", TollLedger)
KEY_RATE_LIMIT = web.AppKey("rate_limiter", object)
KEY_VERIFY_FN = web.AppKey("verify_fn", object)
KEY_ANCHOR_FN = web.AppKey("anchor_fn", object)
KEY_BADGE_FN = web.AppKey("badge_fn", object)
KEY_CFG = web.AppKey("toll_cfg", dict)


def _load_jsonl(path: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    with open(path, encoding="utf-8") as fh:
        for ln in fh:
            ln = ln.strip()
            if ln:
                out.append(json.loads(ln))
    return out


def verdict_digest(result: dict[str, Any]) -> str:
    """Stable sha256 over the verdict (ok + checks) - the thing we anchor."""
    payload = json.dumps(
        {"ok": result.get("ok"), "checks": result.get("checks", {})},
        sort_keys=True,
        separators=(",", ":"),
    )
    return "0x" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def default_verify_fn(
    *,
    default_journal_path: str | None = None,
    default_manifest_path: str | None = None,
    default_fills_path: str | None = None,
    default_capital: float | None = None,
) -> VerifyFn:
    """Build the real verify function around :func:`core.verify.open_verify`.

    Submitted track (``body['journal']``) wins; otherwise falls back to the
    configured default track on disk (point this at a STABLE snapshot, never the
    live journal being actively written - a torn line would fail the load).
    """

    def _verify(body: dict[str, Any]) -> dict[str, Any]:
        journal = body.get("journal")
        manifest = body.get("manifest")
        fills = body.get("fills")
        capital = body.get("capital", default_capital)
        track_ref = "request-body"
        if not journal:
            if not (default_journal_path and os.path.exists(default_journal_path)):
                raise ValueError(
                    "no track in request body and no default journal configured "
                    "(POST {journal:[...]} or set X402_DEFAULT_JOURNAL)"
                )
            journal = _load_jsonl(default_journal_path)
            track_ref = f"default:{os.path.basename(default_journal_path)}"
            if manifest is None and default_manifest_path and os.path.exists(default_manifest_path):
                manifest = _load_jsonl(default_manifest_path)
            if fills is None and default_fills_path and os.path.exists(default_fills_path):
                fills = _load_jsonl(default_fills_path)
        rep = open_verify(
            journal,
            manifest_records=manifest,
            fills=fills,
            equity_start=capital,
            check_anchors=manifest is not None,
            live=False,  # offline recompute - fast; on-chain re-read is a separate op
        )
        return {
            "ok": rep.ok,
            "checks": rep.checks,
            "summary": rep.summary(),
            "track_ref": track_ref,
        }

    return _verify


async def _handle_info(request: web.Request) -> web.Response:
    cfg = request.app[KEY_CFG]
    return web.json_response(
        {
            "service": "CapitalArc Trust Toll",
            "what": "pay-per-call open verification of a track (PASS/FAIL recomputed from public data)",
            "price_usd": cfg["price_usd"],
            "pay_with": "x402 / Circle Gateway Nanopayments",
            "network": cfg["network"],
            "pay_to": cfg["pay_to"],
            "verify_endpoint": cfg["resource_url"],
        }
    )


async def _handle_health(request: web.Request) -> web.Response:
    return web.json_response({"ok": True})


async def _read_body(request: web.Request) -> dict[str, Any]:
    if request.can_read_body:
        try:
            data = await request.json()
            if isinstance(data, dict):
                return data
        except Exception:
            return {}
    return {}


async def _handle_verify(request: web.Request) -> web.Response:
    app = request.app
    cfg = app[KEY_CFG]
    gw: GatewayFacilitator = app[KEY_GATEWAY]
    ledger: TollLedger = app[KEY_LEDGER]
    rl: TokenBucket | None = app[KEY_RATE_LIMIT]
    verify_fn: VerifyFn = app[KEY_VERIFY_FN]
    anchor_fn: AnchorFn | None = app[KEY_ANCHOR_FN]
    badge_fn: BadgeFn | None = app[KEY_BADGE_FN]

    req_id = str(uuid.uuid4())
    ip = request.remote or "?"
    if rl is not None and not rl.allow(ip):
        return web.json_response({"error": "rate_limited"}, status=429)

    # Build the payment requirements from Gateway's live /supported (cached).
    try:
        kind = await gw.supported_kind()
        req = requirements_from_supported_kind(
            kind, price_usd=cfg["price_usd"], pay_to=cfg["pay_to"]
        )
    except (GatewayError, ValueError) as exc:
        return web.json_response(
            {"error": "cashier_unconfigured", "detail": str(exc)}, status=503
        )

    sig = request.headers.get(HEADER_PAYMENT_SIGNATURE)
    if not sig:
        body402 = build_payment_required(
            [req], resource_url=cfg["resource_url"], description=cfg["description"]
        )
        ledger.record(TollReceipt(
            ts=utc_now_iso(), request_id=req_id, paid=False, stage="402_issued",
            amount_atomic=req.amount, asset=req.asset, network=req.network,
        ))
        return web.json_response(
            {"error": "payment_required", "accepts": body402["accepts"]},
            status=402,
            headers={HEADER_PAYMENT_REQUIRED: encode_header(body402)},
        )

    # Decode the buyer's signed payload and settle it through Gateway.
    try:
        payload = decode_header(sig)
    except ValueError as exc:
        return web.json_response(
            {"error": "bad_payment_signature", "detail": str(exc)}, status=402
        )
    try:
        settle = await gw.settle(payload, req.to_dict())
    except GatewayError as exc:
        return web.json_response(
            {"error": "settlement_unavailable", "detail": str(exc)}, status=502
        )
    if not settle.get("success"):
        ledger.record(TollReceipt(
            ts=utc_now_iso(), request_id=req_id, paid=False, stage="settle_failed",
            settle_error=settle.get("errorReason"), network=settle.get("network"),
            amount_atomic=req.amount, asset=req.asset,
        ))
        return web.json_response(
            {"error": "payment_not_settled", "reason": settle.get("errorReason")},
            status=402,
        )

    # Paid. Run the verification on the submitted (or default) track.
    pay_resp = build_payment_response(settle)
    pay_headers = {HEADER_PAYMENT_RESPONSE: encode_header(pay_resp)}
    body = await _read_body(request)
    try:
        result = verify_fn(body)
    except Exception as exc:
        # Honest failure: payment WAS taken, but verification could not run.
        ledger.record(TollReceipt(
            ts=utc_now_iso(), request_id=req_id, paid=True, stage="verify_error",
            payer=settle.get("payer"), settle_tx=settle.get("transaction"),
            network=settle.get("network"), amount_atomic=req.amount, asset=req.asset,
            extra={"detail": str(exc)},
        ))
        return web.json_response(
            {"error": "verification_error", "detail": str(exc), "payment": pay_resp},
            status=500, headers=pay_headers,
        )

    digest = verdict_digest(result)
    anchor_ref = None
    if anchor_fn is not None:
        try:
            anchor_ref = anchor_fn(digest)
        except Exception:
            anchor_ref = None  # anchoring is best-effort; never blocks the verdict

    # Issue the ERC-8004 "Verified" badge ONLY on PASS (the gate is inside
    # badge_fn). Best-effort, exactly like anchoring: a failure here must never
    # block or fail the paid verdict.
    badge_ref = None
    if badge_fn is not None:
        try:
            badge_ref = badge_fn(result, digest)
        except Exception:
            badge_ref = None

    ledger.record(TollReceipt(
        ts=utc_now_iso(), request_id=req_id, paid=True, stage="paid",
        payer=settle.get("payer"), amount_atomic=req.amount, asset=req.asset,
        network=settle.get("network"), settle_tx=settle.get("transaction"),
        verdict_ok=bool(result.get("ok")), verdict_digest=digest,
        track_ref=result.get("track_ref"), anchor_ref=anchor_ref,
        extra={"badge": badge_ref} if badge_ref else {},
    ))
    return web.json_response(
        {
            "ok": bool(result.get("ok")),
            "checks": result.get("checks", {}),
            "summary": result.get("summary", ""),
            "verdict_digest": digest,
            "anchor": anchor_ref,
            "badge": badge_ref,
            "payment": pay_resp,
        },
        status=200, headers=pay_headers,
    )


def make_app(
    *,
    gateway: GatewayFacilitator | None = None,
    pay_to: str | None = None,
    price_usd: float | None = None,
    network: str | None = None,
    ledger: TollLedger | None = None,
    rate_limiter: Any = _UNSET,
    verify_fn: VerifyFn | None = None,
    anchor_fn: AnchorFn | None = None,
    badge_fn: BadgeFn | None = None,
    resource_url: str = "/verify",
    description: str = "CapitalArc Trust Toll: open verification of a track (PASS/FAIL).",
) -> web.Application:
    """Build the cashier app. Every dependency is injectable (tests pass fakes).

    Defaults read from env: ``X402_PAY_TO`` (required for a real run),
    ``X402_PRICE_USD`` (default 0.001), ``X402_GATEWAY_BASE_URL``,
    ``X402_DEFAULT_JOURNAL`` / ``_MANIFEST`` / ``_FILLS`` / ``X402_DEFAULT_CAPITAL``.
    """
    app = web.Application()
    app[KEY_GATEWAY] = gateway if gateway is not None else GatewayFacilitator()
    app[KEY_LEDGER] = ledger if ledger is not None else TollLedger(
        os.getenv("X402_LEDGER_PATH", "backtest_data/live/toll_ledger.jsonl")
    )
    if rate_limiter is _UNSET:
        # 1 req/s sustained, burst 5, per IP - generous for a demo, abuse-bounded.
        rate_limiter = TokenBucket(rate_per_sec=1.0, capacity=5.0)
    app[KEY_RATE_LIMIT] = rate_limiter
    app[KEY_ANCHOR_FN] = anchor_fn
    app[KEY_BADGE_FN] = badge_fn
    if verify_fn is None:
        verify_fn = default_verify_fn(
            default_journal_path=os.getenv("X402_DEFAULT_JOURNAL"),
            default_manifest_path=os.getenv("X402_DEFAULT_MANIFEST"),
            default_fills_path=os.getenv("X402_DEFAULT_FILLS"),
            default_capital=(
                float(os.environ["X402_DEFAULT_CAPITAL"])
                if os.getenv("X402_DEFAULT_CAPITAL") else None
            ),
        )
    app[KEY_VERIFY_FN] = verify_fn
    app[KEY_CFG] = {
        "price_usd": price_usd if price_usd is not None
        else float(os.getenv("X402_PRICE_USD", "0.001")),
        "pay_to": pay_to or os.getenv("X402_PAY_TO", ""),
        "network": network or os.getenv("X402_NETWORK", "eip155:5042002"),
        "resource_url": resource_url,
        "description": description,
    }

    app.router.add_get("/", _handle_info)
    app.router.add_get("/healthz", _handle_health)
    app.router.add_post(resource_url, _handle_verify)
    app.router.add_get(resource_url, _handle_verify)  # GET ok for the simplest demo
    return app
