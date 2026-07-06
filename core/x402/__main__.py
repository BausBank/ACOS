"""Run the Trust Toll cashier.

    python -m core.x402                 # serve on 127.0.0.1:8402 (config from .env)
    python -m core.x402 --port 9000

Reads config from ``.env`` (see :func:`core.x402.server.make_app`). The only
required value for a real run is ``X402_PAY_TO`` - the EVM address that receives
the USDC toll. Everything else (price, Gateway URL, default track) has a default.

The cashier takes payment via Circle Gateway Nanopayments (gasless, sub-cent)
and serves the Stage-16 open verifier's PASS/FAIL behind it. It needs no Circle
API key - Gateway's x402 settle endpoint is public; the buyer's signature is the
authorization.
"""

from __future__ import annotations

import argparse
import os

from aiohttp import web

from core.anchor.anchorer import load_env_file
from core.x402.server import make_app


def main() -> None:
    load_env_file()
    ap = argparse.ArgumentParser(
        description="CapitalArc Trust Toll cashier (x402 / Circle Gateway Nanopayments)"
    )
    ap.add_argument("--host", default=os.getenv("X402_HOST", "127.0.0.1"))
    ap.add_argument("--port", type=int, default=int(os.getenv("X402_PORT", "8402")))
    a = ap.parse_args()

    app = make_app()
    cfg = app["toll_cfg"]
    if not cfg["pay_to"]:
        raise SystemExit(
            "X402_PAY_TO is not set - the cashier needs an EVM address to receive "
            "the USDC toll. Set X402_PAY_TO in .env (any address you control)."
        )
    print(
        f"[toll] Trust Toll cashier -> http://{a.host}:{a.port}{cfg['resource_url']}  "
        f"price=${cfg['price_usd']}  pay_to={cfg['pay_to']}  network={cfg['network']}",
        flush=True,
    )
    web.run_app(app, host=a.host, port=a.port)


if __name__ == "__main__":
    main()
