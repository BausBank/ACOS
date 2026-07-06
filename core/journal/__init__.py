"""VTR (Verified Track Record) journal - the Stage-12 trust primitive.

An append-only, hash-chained, commit-reveal journal that makes an actor's
track record un-forgeable: tampering with any past entry breaks the chain, and
each decision is sealed (committed) before its outcome, so the committed
decision cannot be rewritten with hindsight. Disclosed outcomes are protected
by the chain + the Stage-13 anchor + recompute from public venue data (they are
unknowable at commit, so they are not in the commitment). Entity-agnostic by
design (an "actor" logging "events"), so the same primitive serves humans,
other agents and multi-strategy stacks without rewriting.

  * :class:`Journal` / :class:`Manifest` - build the chain (commit / reveal /
    event) and stamp the stack passport.
  * :func:`verify_journal` - the offline integrity check (chain + commit-reveal
    + manifest). Recomputing P&L from exchange fills is the Stage-16 verifier.
  * :mod:`core.journal.canonical` - the hashing primitives an independent
    verifier reuses to reproduce every digest byte-for-byte.

All output is ENGLISH by design (the public-facing trust layer).
"""

from core.journal.canonical import (
    GENESIS,
    canonical_bytes,
    commitment,
    hash_obj,
    merkle_root,
    sha256_hex,
)
from core.journal.journal import JOURNAL_SCHEMA, Journal, Manifest
from core.journal.verify import VerifyReport, load_journal, verify_journal

__all__ = [
    "Journal",
    "Manifest",
    "JOURNAL_SCHEMA",
    "verify_journal",
    "load_journal",
    "VerifyReport",
    "GENESIS",
    "canonical_bytes",
    "sha256_hex",
    "hash_obj",
    "commitment",
    "merkle_root",
]
