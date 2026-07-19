# ACOS [ AGENT CAPITAL OS ]

Copyright (C) 2026 Baus · ACOS (acos.capital) · License: AGPL-3.0

ACOS is an operating system for autonomous agents that manage capital. This
repository is its first shipped layer - **trust**:

- **VTR (Verifiable Track Record)** - an entity-agnostic journal that lets any
  agent prove its history cryptographically, without revealing how it trades.
- **Trust Toll** - verification sold as a ~$0.001 x402 nanopayment.

> Agents that cannot lie about their past.

## How it works

- **Commit-reveal decision journal** (`core/journal`) - every decision is
  sealed (hash commitment) *before* the outcome is known, then revealed after.
  Records form an append-only hash chain: rewriting history breaks the chain.
- **Dual anchoring** (`core/anchor`) - the journal head is anchored hourly
  into **Arc** (an on-chain transaction carrying the chain head) and into
  **Bitcoin via OpenTimestamps**. Two independent clocks; forging a past
  requires rewriting both.
- **Open verifier** (`core/verify`) - recomputes P&L from *public venue
  fills* and cross-checks it against the claimed journal, then checks every
  anchor on-chain. Anyone can run it; no trust in the operator required.
- **Public-site snapshot emitter** (`core/site`) - turns a verified journal
  into a public JSON snapshot using **whitelist redaction**: only explicitly
  allowed keys survive; internal signal vocabulary and commit secrets are
  structurally excluded (`core/site/redact.py`).
- **x402 Trust Toll** (`core/x402`) - verification sold as a ~$0.001
  nanopayment (HTTP 402 flow, Circle Gateway batch settlement). The live
  wallet runner is intentionally not included.
- **Circle DCW client** (`core/circle`): a thin async client for Circle
  Developer-Controlled Wallets. Balances, USDC transfers and arbitrary
  contract-execution transactions, with per-request RSA-OAEP-SHA256
  entity-secret encryption. This is the on-chain write path for attestations.
- **ERC-8004 attestations** (`core/attest`): identity passports (ERC-721),
  validation records bound to verdict digests, and revocable reputation
  badges, all on Arc's ERC-8004 registries. Register, badge on PASS, revoke.
- **Site wiring** (`site/wire.js`) - the static front-end glue that renders a
  snapshot on the public page.

Every module is entity-agnostic and contains zero strategy logic: it never
sees how decisions are made, only that each one was sealed before its outcome.

## Package map

| Package | Purpose |
| --- | --- |
| `core/journal` | Commit-reveal journal, canonical JSON hashing, chain verifier |
| `core/anchor` | Anchor records + backends (Arc raw tx, OpenTimestamps), anchor verifier |
| `core/verify` | Open verifier: fills → P&L recompute, cross-check, on-chain anchor history |
| `core/site` | Snapshot emitter with whitelist redaction, actors feed, anchor maturation |
| `core/x402` | HTTP 402 Trust Toll: pay-per-verification via Circle Gateway nanopayments (USDC on Arc) |
| `core/circle` | Async Circle DCW client: balances, USDC transfers, contract execution (RSA-OAEP entity secret) |
| `core/attest` | ERC-8004 attestation layer: identity passports, validation records, revocable badges on Arc registries |
| `site/wire.js` | Front-end wiring for the public page |
| `examples/snapshot.sample.json` | Sample public snapshot (replay run) |
| `examples/create_circle_wallet.py` | One-shot Circle DCW onboarding: wallet set, entity-secret registration, first wallet |

## Quickstart

```sh
# verify a journal's hash chain and commit-reveal integrity
python -m core.journal.verify <journal.jsonl>

# emit a public snapshot from a journal (whitelist-redacted)
python -m core.site --journal <journal.jsonl> --out snapshot.json

# see what a snapshot looks like
cat examples/snapshot.sample.json

# register an agent identity on the ERC-8004 registries (dry-run by default, add --live for a real tx)
python -m core.attest register --actor my-agent

# read a badge back from the chain
python -m core.attest status --request-hash <0x...>
```

Core packages import with stdlib only; live anchoring/verification against
chains additionally uses `web3`, `eth-account`, `opentimestamps-client`,
loaded lazily. The Circle DCW client and attestation layer (`core/circle`,
`core/attest`) additionally use `httpx` and `cryptography`.

## Live deployment

- Site: https://acos.capital
- Every number on the page is recomputable from public data: journal → hash
  chain → Arc/Bitcoin anchors → P&L recomputed from public venue fills.

## Built with

Built at the **Lepton Agents Hackathon** on the **Circle Agent Stack**:
Wallets, Gateway nanopayments, x402, USDC on Arc, ERC-8004.

## License

AGPL-3.0 (see LICENSE).
