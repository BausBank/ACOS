"""Anchor backends - where a 32-byte fingerprint is published, and how it is
re-read for verification (Stage 13).

Two independent public rails, so a track is anchored in two systems that fail
differently:

  * :class:`ArcRawTxBackend` - a raw EVM transaction on Arc-testnet whose
    calldata carries the tagged digest (``magic || version || digest``). No
    smart contract: the digest + the block timestamp are what give the proof,
    and any skeptic re-reads them straight from the chain over a public RPC.
    The Circle/Paymaster (sponsored, contract-based) rail is a go-live showcase
    that slots behind the same :class:`AnchorBackend` interface later - the
    trust value is identical either way, so it is deliberately not built here.
  * :class:`OpenTimestampsBackend` - a Bitcoin timestamp via OpenTimestamps.
    Free (calendar servers aggregate many digests into one Bitcoin tx), neutral,
    and ASYNCHRONOUS: ``submit`` returns a *pending* proof immediately; the
    *confirmed* Bitcoin proof appears after the next calendar aggregation makes
    it into a block (~hours), fetched by :meth:`OpenTimestampsBackend.upgrade`.

A backend's network side is injectable (``w3`` / ``submit_fn``) so the whole
pipeline is testable offline; a real broadcast is an explicit, separate step.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Protocol

from core.anchor.record import anchor_calldata, parse_anchor_calldata

# Public OpenTimestamps calendar servers (the reference set). Submitting to
# several and merging gives redundancy if one is down.
DEFAULT_CALENDARS = (
    "https://a.pool.opentimestamps.org",
    "https://b.pool.opentimestamps.org",
    "https://alice.btc.calendar.opentimestamps.org",
)


def _iso(ts_unix: int | float) -> str:
    return datetime.fromtimestamp(int(ts_unix), tz=timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def _signed_raw_tx(signed: Any) -> bytes:
    """The signed transaction's raw bytes, across eth-account versions.

    eth-account renamed this attribute from ``rawTransaction`` (<=0.11.x - the
    version pinned in ``requirements.txt``) to ``raw_transaction`` (>=0.13.x).
    Read whichever exists so the Arc rail works regardless of which eth-account
    an environment resolves. The Stage-13 code hardcoded the snake_case name and
    silently broke against the pinned 0.11.3 (caught in Stage-14 testing).
    """
    raw = getattr(signed, "raw_transaction", None)
    if raw is None:
        raw = getattr(signed, "rawTransaction", None)
    if raw is None:  # pragma: no cover - defensive across future renames
        raise AttributeError(
            "SignedTransaction exposes neither 'raw_transaction' nor "
            "'rawTransaction' - unexpected eth-account version"
        )
    return raw


@dataclass
class AnchorReceipt:
    """Where a digest was published and the proof needed to re-find it.

    ``status`` ∈ {``dry-run``, ``submitted``, ``pending``, ``confirmed``,
    ``failed``}. For Arc, ``submitted`` once the tx is mined; for OTS,
    ``pending`` until the Bitcoin attestation is upgraded in, then ``confirmed``.
    """

    backend: str
    digest_hex: str
    status: str
    ref: str | None = None              # tx hash (Arc) / .ots file path (OTS)
    block: int | None = None
    block_time: str | None = None       # ISO-8601 UTC
    chain_id: int | None = None
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "backend": self.backend,
            "digest_hex": self.digest_hex,
            "status": self.status,
            "ref": self.ref,
            "block": self.block,
            "block_time": self.block_time,
            "chain_id": self.chain_id,
            "detail": self.detail,
        }


class AnchorBackend(Protocol):
    """A public rail a digest can be published to and verified against."""

    name: str

    def submit(self, digest_hex: str, *, dry_run: bool = True) -> AnchorReceipt: ...

    def verify(self, receipt: AnchorReceipt, digest_hex: str) -> tuple[bool, dict[str, Any]]: ...


# --------------------------------------------------------------------------- #
# Arc-testnet raw EVM transaction                                             #
# --------------------------------------------------------------------------- #
class ArcRawTxBackend:
    """Anchor a digest in the calldata of a 0-value EVM self-transaction.

    Parameters
    ----------
    rpc_url, chain_id
        Arc-testnet endpoint + chain id. ``chain_id`` is read from the node when
        left ``None``.
    private_key
        Signer for the anchor tx. A DEDICATED anchor key (not the trading key)
        is the right hygiene. If ``None``, a throwaway key is generated FOR
        DRY-RUN ONLY (exercises build+sign without a funded account); a live
        submit with no key raises.
    to_address
        Where the self-tx is sent (defaults to the signer's own address). The
        value is 0; only the calldata matters.
    expected_address
        The anchor identity a VERIFIER pins out-of-band (the operator's public
        anchor address). verify() requires the on-chain tx's ``from`` to equal
        it - so "the digest is on-chain" becomes "the ANCHOR KEY published this
        digest", not "somebody put 37 public bytes on some chain". Without it,
        verify still self-checks against the receipt's recorded sender but warns
        the identity is unpinned.
    w3
        Injectable web3 client (tests pass a fake). Built lazily otherwise.
    """

    name = "arc-rawtx"

    def __init__(
        self,
        rpc_url: str | None = None,
        *,
        private_key: str | None = None,
        to_address: str | None = None,
        expected_address: str | None = None,
        chain_id: int | None = None,
        w3: Any = None,
        gas_limit: int | None = None,
        wait_timeout: float = 180.0,
    ) -> None:
        self.rpc_url = rpc_url or os.getenv("ARC_RPC_URL", "https://rpc.testnet.arc.network")
        self._private_key = private_key
        self._to_address = to_address
        self._expected_address = expected_address
        self._chain_id = chain_id
        self._w3 = w3
        self.gas_limit = gas_limit
        self.wait_timeout = wait_timeout

    # -- lazy web3 --
    def _web3(self) -> Any:
        if self._w3 is None:
            from web3 import Web3

            self._w3 = Web3(Web3.HTTPProvider(self.rpc_url, request_kwargs={"timeout": 30}))
        return self._w3

    def _account(self, *, dry_run: bool) -> Any:
        from eth_account import Account

        if self._private_key:
            return Account.from_key(self._private_key)
        if dry_run:
            return Account.create()  # throwaway, dry-run only
        raise RuntimeError(
            "ArcRawTxBackend: no private_key set; a live anchor submit needs a "
            "funded dedicated anchor key (fund its address from the Arc faucet)."
        )

    def submit(self, digest_hex: str, *, dry_run: bool = True) -> AnchorReceipt:
        w3 = self._web3()
        acct = self._account(dry_run=dry_run)
        from_addr = acct.address
        to_addr = self._to_address or from_addr
        data = anchor_calldata(digest_hex)
        chain_id = self._chain_id if self._chain_id is not None else w3.eth.chain_id

        nonce = w3.eth.get_transaction_count(from_addr)
        gas_price = w3.eth.gas_price
        gas = self.gas_limit
        if gas is None:
            try:
                gas = w3.eth.estimate_gas(
                    {"from": from_addr, "to": to_addr, "value": 0, "data": data}
                )
                gas = int(gas * 1.25)  # headroom
            except Exception:
                gas = 60_000  # a self-tx + 37 bytes of calldata is tiny

        tx = {
            "to": to_addr,
            "value": 0,
            "data": data,
            "nonce": nonce,
            "gas": gas,
            "gasPrice": gas_price,
            "chainId": chain_id,
        }
        signed = acct.sign_transaction(tx)
        tx_hash = "0x" + signed.hash.hex().removeprefix("0x")

        if dry_run:
            return AnchorReceipt(
                backend=self.name, digest_hex=digest_hex, status="dry-run",
                ref=tx_hash, chain_id=chain_id,
                detail={
                    "from": from_addr, "to": to_addr, "nonce": nonce,
                    "gas": gas, "gas_price_wei": int(gas_price),
                    "calldata": data.hex(),
                    "raw_tx": _signed_raw_tx(signed).hex(),
                    "ephemeral_key": not bool(self._private_key),
                    "note": "NOT broadcast (dry-run)",
                },
            )

        sent = w3.eth.send_raw_transaction(_signed_raw_tx(signed))
        rcpt = w3.eth.wait_for_transaction_receipt(sent, timeout=self.wait_timeout)
        block_num = int(rcpt["blockNumber"])
        block = w3.eth.get_block(block_num)
        return AnchorReceipt(
            backend=self.name, digest_hex=digest_hex, status="submitted",
            ref="0x" + bytes(sent).hex().removeprefix("0x"),
            block=block_num, block_time=_iso(block["timestamp"]), chain_id=chain_id,
            detail={"from": from_addr, "to": to_addr, "calldata": data.hex()},
        )

    def verify(self, receipt: AnchorReceipt, digest_hex: str) -> tuple[bool, dict[str, Any]]:
        """Re-read the tx from the chain and confirm it is a MINED, successful
        tx, sent by the expected anchor identity, on the expected chain, whose
        calldata carries the expected digest. Each of those is necessary: the
        digest alone is public, so "a tx carries it" is not "the anchor key
        committed to this journal in a real past block".
        """
        if not receipt.ref:
            return False, {"error": "no tx hash in receipt"}
        if receipt.status == "dry-run":
            # Offline: recompute the calldata FROM the digest (do not trust the
            # receipt's stored calldata string), and report it is unpublished.
            expected = anchor_calldata(digest_hex)
            stored = receipt.detail.get("calldata", "")
            ok = stored == expected.hex()
            return ok, {"dry_run": True, "unpublished": True,
                        "recovered": parse_anchor_calldata(expected)}

        w3 = self._web3()
        try:
            tx = w3.eth.get_transaction(receipt.ref)
        except Exception as exc:  # tx not found / RPC error
            return False, {"error": f"tx lookup failed: {exc!r}"}
        if tx is None:
            return False, {"error": "tx not found"}

        # Must be MINED (not a mempool/never-mined tx whose calldata anyone can
        # craft but which was never timestamped in a block).
        block_num = tx.get("blockNumber")
        if block_num is None:
            return False, {"error": "tx not mined yet (no block) - not a timestamp"}
        block_num = int(block_num)

        # Must be SUCCESSFUL (a reverted tx still lands in a block with calldata).
        try:
            rcpt = w3.eth.get_transaction_receipt(receipt.ref)
        except Exception as exc:
            return False, {"error": f"receipt lookup failed: {exc!r}"}
        if rcpt is not None and rcpt.get("status") is not None and int(rcpt["status"]) != 1:
            return False, {"error": "tx reverted (status != 1)"}

        # Must be sent by the expected anchor identity (when the verifier pins it).
        sender = tx.get("from")
        if self._expected_address and sender and sender.lower() != self._expected_address.lower():
            return False, {"error": f"tx from {sender} != expected anchor {self._expected_address}"}

        # Must be on the expected chain (when pinned).
        tx_chain = tx.get("chainId")
        tx_chain = int(tx_chain) if tx_chain is not None else None
        if self._chain_id is not None and tx_chain is not None and tx_chain != self._chain_id:
            return False, {"error": f"tx chainId {tx_chain} != expected {self._chain_id}"}

        # Must carry exactly the expected digest in calldata.
        raw_input = tx["input"]
        data = bytes(raw_input) if isinstance(raw_input, (bytes, bytearray)) else bytes.fromhex(
            str(raw_input).removeprefix("0x")
        )
        recovered = parse_anchor_calldata(data)
        if recovered != digest_hex:
            return False, {"error": "calldata does not carry the expected digest",
                           "recovered": recovered}

        block = w3.eth.get_block(block_num)
        return True, {
            "confirmed": True,   # mined + successful + identity/chain/calldata bound
            "recovered": recovered,
            "from": sender,
            "block": block_num,
            "block_time": _iso(block["timestamp"]),
            "chain_id": tx_chain if tx_chain is not None else receipt.chain_id,
            "identity_pinned": bool(self._expected_address),
        }


# --------------------------------------------------------------------------- #
# Bitcoin via OpenTimestamps                                                  #
# --------------------------------------------------------------------------- #
class OpenTimestampsBackend:
    """Anchor a digest to Bitcoin via OpenTimestamps.

    The digest is treated as a tiny "file" (its 32 bytes), so the standard
    detached ``.ots`` format applies: the proof commits to ``SHA256(digest)``.
    A skeptic reconstructs the file (the published ``anchor_hash`` bytes) and
    runs the reference ``ots verify`` on the ``.ots`` - no trust in us.

    Parameters
    ----------
    out_dir
        Directory the ``.ots`` proof files are written to.
    calendars
        Calendar server URLs to submit to (and merge).
    submit_fn
        Injectable ``(digest_bytes, url, timeout) -> Timestamp`` so tests run
        without network. Defaults to a real ``RemoteCalendar.submit``.
    bitcoin_verify_fn
        Injectable ``(ots_path, digest_hex) -> list[int]`` returning the Bitcoin
        block heights an AUTHORITATIVE validator confirms (empty if none). The
        default shells out to the reference ``ots verify`` (which walks the
        op-chain to a real Bitcoin block header) - a self-fabricated ``.ots`` is
        therefore NOT trusted just because it carries a bare attestation object.
    """

    name = "opentimestamps"

    def __init__(
        self,
        out_dir: str,
        *,
        calendars: tuple[str, ...] = DEFAULT_CALENDARS,
        submit_fn: Callable[[bytes, str, float], Any] | None = None,
        bitcoin_verify_fn: Callable[[str, str], list[int]] | None = None,
        timeout: float = 20.0,
    ) -> None:
        self.out_dir = out_dir
        self.calendars = calendars
        self.timeout = timeout
        self._submit_fn = submit_fn
        self._bitcoin_verify_fn = bitcoin_verify_fn

    def _ots_path(self, digest_hex: str) -> str:
        return os.path.join(self.out_dir, f"anchor_{digest_hex[:16]}.ots")

    def _default_submit(self, file_hash: bytes, url: str, timeout: float) -> Any:
        from opentimestamps.calendar import RemoteCalendar

        return RemoteCalendar(url).submit(file_hash, timeout=timeout)

    def submit(self, digest_hex: str, *, dry_run: bool = True) -> AnchorReceipt:
        digest = bytes.fromhex(digest_hex)
        # Treat the 32-byte digest as the "file"; OTS commits to SHA256(file).
        file_hash = hashlib.sha256(digest).digest()

        if dry_run:
            # No calendar submission -> the timestamp would be empty (the OTS
            # lib refuses to serialize that). Model dry-run as "what would be
            # submitted", offline-verifiable via file_sha256.
            return AnchorReceipt(
                backend=self.name, digest_hex=digest_hex, status="dry-run", ref=None,
                detail={
                    "file_sha256": file_hash.hex(),
                    "would_submit_to": list(self.calendars),
                    "note": "NOT submitted (dry-run)",
                },
            )

        from opentimestamps.core.op import OpSHA256
        from opentimestamps.core.serialize import StreamSerializationContext
        from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp

        os.makedirs(self.out_dir, exist_ok=True)
        ts = Timestamp(file_hash)
        submit_fn = self._submit_fn or self._default_submit
        calendars_ok: list[str] = []
        errors: dict[str, str] = {}
        for url in self.calendars:
            try:
                cal_ts = submit_fn(file_hash, url, self.timeout)
                ts.merge(cal_ts)
                calendars_ok.append(url)
            except Exception as exc:
                errors[url] = repr(exc)[:160]

        if not calendars_ok:
            return AnchorReceipt(
                backend=self.name, digest_hex=digest_hex, status="failed", ref=None,
                detail={"file_sha256": file_hash.hex(), "calendar_errors": errors,
                        "note": "no calendar accepted the digest"},
            )

        detached = DetachedTimestampFile(OpSHA256(), ts)
        ots_path = self._ots_path(digest_hex)
        with open(ots_path, "wb") as fh:
            detached.serialize(StreamSerializationContext(fh))
        # Drop the raw 32-byte digest next to the .ots so a THIRD-PARTY OTS tool
        # (opentimestamps.org / `ots verify <file>`) has the exact "file" the
        # proof commits to (the .ots commits to SHA256(digest)). Our own verifier
        # recomputes the digest from the public anchor_hash and never needs this
        # file - it exists purely to make the proof self-contained for outsiders.
        digest_path = ots_path[:-4] + ".digest"  # "<...>.ots" -> "<...>.digest"
        with open(digest_path, "wb") as fh:
            fh.write(digest)

        return AnchorReceipt(
            backend=self.name, digest_hex=digest_hex, status="pending", ref=ots_path,
            detail={
                "file_sha256": file_hash.hex(),
                "digest_path": digest_path,
                "calendars_ok": calendars_ok,
                "calendar_errors": errors,
                "note": "pending Bitcoin confirmation; run upgrade() after ~hours",
            },
        )

    def _default_bitcoin_verify(self, ots_path: str, digest_hex: str) -> list[int]:
        """Authoritative Bitcoin validation against a REAL block header, fetched
        from a public explorer (pure Python). Returns validated block height(s).

        Deliberately NOT the reference ``ots verify`` CLI: that needs an
        OpenSSL/python-bitcoinlib toolchain that is not portable (it fails to
        load on this platform), which would make the OTS rail unverifiable
        locally. A self-fabricated attestation cannot match a real block's merkle
        root, so this never trusts a bare attestation object.
        """
        from core.anchor.bitcoin_verify import explorer_bitcoin_verify

        return explorer_bitcoin_verify(ots_path, digest_hex)

    def upgrade(self, receipt: AnchorReceipt) -> AnchorReceipt:
        """Pull the completed (Bitcoin-bearing) timestamp from the calendar into
        the ``.ots`` (run hours after submit), then RE-VALIDATE against a real
        Bitcoin block. ``status`` becomes ``confirmed`` ONLY when a real Bitcoin
        attestation validates - not merely because the file carries one. Uses a
        pure-Python calendar fetch (no dependency on the reference ``ots`` CLI)."""
        from core.anchor.bitcoin_verify import upgrade_via_calendar

        path = receipt.ref
        new = AnchorReceipt(**receipt.to_dict())
        if not path or not os.path.exists(path):
            new.detail = {**receipt.detail, "upgrade": {"error": "no .ots file"}}
            return new
        try:
            upgraded = upgrade_via_calendar(path)
        except Exception:
            upgraded = False
        ok, info = self.verify(receipt, receipt.digest_hex)
        # Gate the persisted status on the FULL verify result (ok), not just
        # info["confirmed"]: a .ots that validates against a real block but whose
        # root does not commit to THIS digest (file_hash_ok=False) must not be
        # recorded as confirmed for this receipt.
        if ok and info.get("confirmed") and info.get("bitcoin_blocks"):
            new.status = "confirmed"
            new.block = info["bitcoin_blocks"][0]
        new.detail = {**receipt.detail, "upgrade_ran": upgraded, "verify": info}
        return new

    def verify(
        self, receipt: AnchorReceipt, digest_hex: str, *, validate_bitcoin: bool = True
    ) -> tuple[bool, dict[str, Any]]:
        """Confirm the ``.ots`` commits to ``SHA256(digest)`` and report its real
        attestation status.

        ``confirmed`` is set ONLY when an AUTHORITATIVE validator (the reference
        ``ots verify``, or an injected ``bitcoin_verify_fn``) confirms a Bitcoin
        attestation - a self-fabricated ``.ots`` carrying a bare attestation
        object does NOT count. A pending-only proof is reported ``pending``
        (a calendar promise, cryptographically confirmable only after the next
        Bitcoin aggregation), never ``confirmed``.
        """
        from opentimestamps.core.notary import (
            BitcoinBlockHeaderAttestation,
            PendingAttestation,
        )
        from opentimestamps.core.serialize import StreamDeserializationContext
        from opentimestamps.core.timestamp import DetachedTimestampFile

        if receipt.status == "dry-run":
            # Offline: confirm the would-be file hash matches the digest.
            expected = hashlib.sha256(bytes.fromhex(digest_hex)).hexdigest()
            ok = receipt.detail.get("file_sha256") == expected
            return ok, {"dry_run": True, "unpublished": True,
                        "file_hash_ok": ok, "confirmed": False, "pending": False}

        path = receipt.ref
        if not path or not os.path.exists(path):
            return False, {"error": f"no .ots file at {path!r}", "confirmed": False}
        digest = bytes.fromhex(digest_hex)
        expected_file_hash = hashlib.sha256(digest).digest()
        with open(path, "rb") as fh:
            detached = DetachedTimestampFile.deserialize(StreamDeserializationContext(fh))
        file_hash_ok = detached.timestamp.msg == expected_file_hash

        pending_uris: list[str] = []
        claimed_blocks: list[int] = []
        for _msg, att in detached.timestamp.all_attestations():
            if isinstance(att, PendingAttestation):
                pending_uris.append(str(att.uri))
            elif isinstance(att, BitcoinBlockHeaderAttestation):
                claimed_blocks.append(int(att.height))

        # Authoritative Bitcoin validation - never trust the bare attestation.
        validated: list[int] = []
        if validate_bitcoin and claimed_blocks:
            verifier = self._bitcoin_verify_fn or self._default_bitcoin_verify
            validated = list(verifier(path, digest_hex))

        confirmed = bool(validated)
        pending = bool(pending_uris) and not confirmed
        ok = file_hash_ok and (confirmed or pending)
        return ok, {
            "file_hash_ok": file_hash_ok,
            "pending_calendars": pending_uris,
            "claimed_bitcoin_blocks": claimed_blocks,
            "bitcoin_blocks": validated,   # only AUTHORITATIVELY validated heights
            "confirmed": confirmed,
            "pending": pending,
        }


__all__ = [
    "AnchorReceipt",
    "AnchorBackend",
    "ArcRawTxBackend",
    "OpenTimestampsBackend",
    "DEFAULT_CALENDARS",
]
