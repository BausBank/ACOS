# ACOS — the Agent Capital OS

Copyright (C) 2026 Baus · ACOS (acos.capital) · License: AGPL-3.0

ACOS is an operating system for autonomous agents that manage capital. This
repository is its first shipped layer — **trust**:

- **VTR (Verifiable Track Record)** — an entity-agnostic journal that lets any
  agent prove its history cryptographically, without revealing how it trades.
- **Trust Toll** — verification sold as a ~$0.001 x402 nanopayment.

> Agents that cannot lie about their past.

## What this is

- **Commit-reveal decision journal** (`core/journal`) — every decision is
  sealed (hash commitment) *before* the outcome is known, then revealed after.
  Records form an append-only hash chain: rewriting history breaks the chain.
- **Dual anchoring** (`core/anchor`) — the journal head is anchored hourly
  into **Arc** (an on-chain transaction carrying the chain head) and into
  **Bitcoin via OpenTimestamps**. Two independent clocks; forging a past
  requires rewriting both.
- **Open verifier** (`core/verify`) — recomputes P&L from *public venue
  fills* and cross-checks it against the claimed journal, then checks every
  anchor on-chain. Anyone can run it; no trust in the operator required.
- **Public-site snapshot emitter** (`core/site`) — turns a verified journal
  into a public JSON snapshot using **whitelist redaction**: only explicitly
  allowed keys survive; internal signal vocabulary and commit secrets are
  structurally excluded (`core/site/redact.py`).
- **x402 Trust Toll** (`core/x402`) — verification sold as a ~$0.001
  nanopayment (HTTP 402 flow, Circle Gateway batch settlement). The live
  wallet runner is intentionally not included.
- **Site wiring** (`site/wire.js`) — the static front-end glue that renders a
  snapshot on the public page.

## What is NOT here

The trading strategy. The edge stays private. This layer contains **zero
strategy logic by design** — the journal, anchors, verifier and snapshot
emitter are entity-agnostic and never see how decisions are made, only *that*
they were sealed before outcomes. That is exactly why it is safe to open.

## Package map

| Package | Purpose |
| --- | --- |
| `core/journal` | Commit-reveal journal, canonical JSON hashing, chain verifier |
| `core/anchor` | Anchor records + backends (Arc raw tx, OpenTimestamps), anchor verifier |
| `core/verify` | Open verifier: fills → P&L recompute, cross-check, on-chain anchor history |
| `core/site` | Snapshot emitter with whitelist redaction, actors feed, anchor maturation |
| `core/x402` | HTTP 402 Trust Toll: pay-per-verification via Circle Gateway nanopayments (USDC on Arc) |
| `site/wire.js` | Front-end wiring for the public page |
| `examples/snapshot.sample.json` | Sample public snapshot (replay run) |

## Quickstart

```sh
# verify a journal's hash chain and commit-reveal integrity
python -m core.journal.verify <journal.jsonl>

# emit a public snapshot from a journal (whitelist-redacted)
python -m core.site --journal <journal.jsonl> --out snapshot.json

# see what a snapshot looks like
cat examples/snapshot.sample.json
```

Core packages import with stdlib only; live anchoring/verification against
chains additionally uses `web3`, `eth-account`, `opentimestamps-client`,
loaded lazily.

## Live deployment

- Site: https://acos.capital
- Every number on the page is recomputable from public data: journal → hash
  chain → Arc/Bitcoin anchors → P&L recomputed from public venue fills.

## Built with

Built at the **Lepton Agents Hackathon** on the **Circle Agent Stack**:
Wallets, Gateway nanopayments, x402, USDC on Arc, ERC-8004.

## License

AGPL-3.0 (see LICENSE).
