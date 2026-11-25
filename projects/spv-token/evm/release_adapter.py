"""Authorize EVM releases after checking canonical BSV burn and token provenance."""

from collections.abc import Callable
from dataclasses import dataclass, field

from Crypto.Hash import keccak
from ecdsa import SECP256k1, VerifyingKey
from ecdsa.ecdsa import InvalidPointError
from ecdsa.numbertheory import SquareRootError
from ecdsa.util import sigdecode_string

from statement import AssetDescriptor, fixed, uint

from evm.bsv_burn_evidence import (
    BsvConfirmationPolicy, BurnReference, CanonicalBurn, read_confirmed_burn, require_canonical_burn_block,
)
from evm.reserve_rpc import ReserveScope, Rpc, _data, _object, _quantity
from usdc_amount import USDC_DECIMALS


class ReleaseEvidenceError(ValueError):
    """The burn or destination reserve has not provided acceptable authorization evidence."""


def _hash(value: bytes) -> bytes:
    return keccak.new(digest_bits=256, data=value).digest()


_DOMAIN_TYPE = b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
_REDEMPTION_TYPE = (
    b"Redemption(uint32 bsvNetwork,bytes32 burnTxid,uint32 burnVout,bytes32 burnBlockHash,"
    b"bytes32 assetId,uint32 reserveDomain,address recipient,uint64 quantity,uint64 fee,uint64 signerEpoch)"
)
_BURN_EVENT_TYPE = b"BurnEvent(uint32 bsvNetwork,bytes32 burnTxid,uint32 burnVout)"
_DOMAIN_HASH = _hash(_DOMAIN_TYPE)
_REDEMPTION_HASH = _hash(_REDEMPTION_TYPE)
_BURN_EVENT_HASH = _hash(_BURN_EVENT_TYPE)
_NAME_HASH = _hash(b"BSV USDC Test Reserve")
_VERSION_HASH = _hash(b"1")
_RELEASE_SELECTOR = _hash(b"release((uint32,bytes32,uint32,bytes32,bytes32,uint32,address,uint64,uint64,uint64),bytes)")[:4]


def _word(value: int, size: int = 32) -> bytes:
    uint(value, size)
    return value.to_bytes(32, "big")


def _address(address: bytes) -> bytes:
    return bytes(12) + fixed(address, 20)


def burn_event_id(network: int, reference: BurnReference) -> bytes:
    return _hash(_BURN_EVENT_HASH + _word(network, 4) + reference.txid + _word(reference.vout, 4))


@dataclass(frozen=True)
class ReleaseClaim:
    bsv_network: int
    burn_txid: bytes
    burn_vout: int
    burn_block_hash: bytes
    asset_id: bytes
    reserve_domain: int
    recipient: bytes
    quantity: int
    fee: int
    signer_epoch: int

    def abi_words(self) -> bytes:
        return b"".join((
            _word(self.bsv_network, 4), fixed(self.burn_txid, 32), _word(self.burn_vout, 4),
            fixed(self.burn_block_hash, 32), fixed(self.asset_id, 32), _word(self.reserve_domain, 4),
            _address(self.recipient), _word(self.quantity, 8), _word(self.fee, 8), _word(self.signer_epoch, 8),
        ))

    def digest(self, scope: ReserveScope) -> bytes:
        domain = _hash(_DOMAIN_HASH + _NAME_HASH + _VERSION_HASH + _word(scope.chain_id) + _address(scope.vault))
        message = _hash(_REDEMPTION_HASH + self.abi_words())
        return _hash(b"\x19\x01" + domain + message)


@dataclass(frozen=True)
class ReleaseAuthorization:
    claim: ReleaseClaim
    digest: bytes
    signature: bytes = field(repr=False)

    def calldata(self) -> bytes:
        words = self.claim.abi_words()
        signature = fixed(self.signature, 65)
        offset = len(words) + 32
        padding = bytes((-len(signature)) % 32)
        return _RELEASE_SELECTOR + words + _word(offset) + _word(len(signature)) + signature + padding


@dataclass(frozen=True)
class Settlement:
    burn_id: bytes
    digest: bytes
    finalized: bool


@dataclass(frozen=True)
class _Head:
    height: int
    hash: bytes

    def pin(self) -> dict:
        return {"blockHash": _hex(self.hash), "requireCanonical": True}


def _hex(value: bytes) -> str:
    return "0x" + value.hex()


def _head(rpc: Rpc, label: str) -> _Head:
    block = _object(rpc("eth_getBlockByNumber", label, False), f"{label} EVM block")
    result = _Head(_quantity(block.get("number"), f"{label} EVM height"),
                   _data(block.get("hash"), 32, f"{label} EVM hash"))
    if not any(result.hash):
        raise ReleaseEvidenceError(f"missing {label} EVM hash")
    return result


def _heads(rpc: Rpc, scope: ReserveScope) -> tuple[_Head, _Head]:
    if _quantity(rpc("eth_chainId"), "RPC chain ID") != scope.chain_id:
        raise ReleaseEvidenceError("RPC chain does not match release reserve")
    finalized = _head(rpc, "finalized")
    latest = _head(rpc, "latest")
    if (finalized.height > latest.height
            or (finalized.height == latest.height and finalized.hash != latest.hash)):
        raise ReleaseEvidenceError("inconsistent latest and finalized EVM blocks")
    return latest, finalized


def _call(rpc: Rpc, scope: ReserveScope, at: _Head, selector: bytes, args: bytes = b"") -> bytes:
    result = rpc("eth_call", {"to": _hex(scope.vault), "data": _hex(_hash(selector)[:4] + args)}, at.pin())
    return _data(result, 32, "reserve RPC return")


def _bool_result(word: bytes) -> bool:
    value = int.from_bytes(word, "big")
    if value not in (0, 1):
        raise ReleaseEvidenceError("invalid reserve boolean return")
    return bool(value)


def _settled_digest(rpc: Rpc, scope: ReserveScope, at: _Head, burn_id: bytes) -> bytes | None:
    if not _bool_result(_call(rpc, scope, at, b"settled(bytes32)", burn_id)):
        return None
    return _call(rpc, scope, at, b"settledDigest(bytes32)", burn_id)


def _read_settlement(
    rpc: Rpc, scope: ReserveScope, latest: _Head, finalized: _Head, burn_id: bytes,
) -> Settlement | None:
    observed = _settled_digest(rpc, scope, latest, burn_id)
    confirmed = observed if finalized == latest else _settled_digest(rpc, scope, finalized, burn_id)
    if confirmed is not None and observed != confirmed:
        raise ReleaseEvidenceError("finalized reserve settlement differs from current settlement")
    if observed is None:
        return None
    return Settlement(burn_id, observed, confirmed is not None)


def read_settlement(rpc: Rpc, scope: ReserveScope, reference: BurnReference) -> Settlement | None:
    """Recover the original settlement digest, separately from current BSV validity."""
    latest, finalized = _heads(rpc, scope)
    return _read_settlement(rpc, scope, latest, finalized, burn_event_id(scope.bsv_network, reference))


def _signer_state(rpc: Rpc, scope: ReserveScope, latest: _Head) -> tuple[int, bytes]:
    scoped_fields = (
        (b"deploymentChainId()", _word(scope.chain_id)),
        (b"assetId()", scope.asset_id),
        (b"reserveDomain()", _word(scope.reserve_domain, 4)),
        (b"bsvNetwork()", _word(scope.bsv_network, 4)),
        (b"token()", _address(scope.reserve_asset)),
    )
    if any(_call(rpc, scope, latest, method) != expected for method, expected in scoped_fields):
        raise ReleaseEvidenceError("reserve contract does not match release scope")
    if _bool_result(_call(rpc, scope, latest, b"releasesPaused()")):
        raise ReleaseEvidenceError("reserve releases are paused")
    epoch = int.from_bytes(_call(rpc, scope, latest, b"signerEpoch()"), "big")
    signer_word = _call(rpc, scope, latest, b"releaseSigner()")
    if not 0 < epoch < (1 << 64) or any(signer_word[:12]) or not any(signer_word[12:]):
        raise ReleaseEvidenceError("reserve has no valid release signer")
    return epoch, signer_word[12:]


def _verify_signature(digest: bytes, signature: bytes, signer: bytes) -> None:
    if type(signature) is not bytes or len(signature) != 65 or signature[64] not in (27, 28):
        raise ReleaseEvidenceError("release signer returned a malformed signature")
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:64], "big")
    if not 0 < r < SECP256k1.order or not 0 < s <= SECP256k1.order // 2:
        raise ReleaseEvidenceError("release signer returned noncanonical signature values")
    try:
        candidates = VerifyingKey.from_public_key_recovery_with_digest(
            signature[:64], digest, curve=SECP256k1, sigdecode=sigdecode_string,
        )
    except (InvalidPointError, SquareRootError, ValueError):
        raise ReleaseEvidenceError("release signature recovery failed") from None
    address = _hash(candidates[signature[64] - 27].to_string())[-20:]
    if address != signer:
        raise ReleaseEvidenceError("release signature does not match the configured signer")


def authorize_release(
    bsv_rpc: Rpc, evm_rpc: Rpc, policy: BsvConfirmationPolicy, scope: ReserveScope,
    asset: AssetDescriptor, reference: BurnReference,
    *, verify_provenance: Callable[[CanonicalBurn, AssetDescriptor], bool],
    sign_digest: Callable[[bytes], bytes],
    resume: ReleaseAuthorization | None = None,
) -> ReleaseAuthorization | Settlement:
    """Authorize one confirmed burn, with external provenance and signing roots.

    The provenance verifier checks the exact fetched transaction and selected burn
    against the asset's authenticated issuance/transfer history. A successful BSV
    RPC read only supplies transaction inclusion and confirmation evidence.
    """
    if (scope.bsv_network != asset.network or scope.reserve_domain != asset.reserve_domain
            or scope.asset_id != asset.asset_id() or asset.decimals != USDC_DECIMALS
            or asset.reserve_asset != _address(scope.reserve_asset)):
        raise ReleaseEvidenceError("BSV asset and configured reserve mismatch")
    observed = read_confirmed_burn(bsv_rpc, policy, reference, asset)
    if verify_provenance(observed, asset) is not True:
        raise ReleaseEvidenceError("burn provenance was not authenticated")
    require_canonical_burn_block(bsv_rpc, policy, reference)

    latest, finalized = _heads(evm_rpc, scope)
    settlement = _read_settlement(evm_rpc, scope, latest, finalized, burn_event_id(scope.bsv_network, reference))
    if settlement is not None:
        return settlement

    epoch, signer = _signer_state(evm_rpc, scope, latest)
    claim = ReleaseClaim(
        scope.bsv_network, reference.txid, reference.vout, reference.block_hash, observed.receipt.asset_id,
        observed.receipt.reserve_domain, observed.receipt.recipient, observed.receipt.quantity,
        observed.receipt.fee, epoch,
    )
    if claim.recipient == scope.vault:
        raise ReleaseEvidenceError("burn recipient is the reserve itself")
    digest = claim.digest(scope)
    if resume is not None:
        if resume.claim != claim or resume.digest != digest:
            raise ReleaseEvidenceError("previous release authorization has a different burn, vault, or signer epoch")
        authorization = resume
    else:
        # The EVM reads may have taken long enough for a BSV reorg.
        require_canonical_burn_block(bsv_rpc, policy, reference)
        authorization = ReleaseAuthorization(claim, digest, sign_digest(digest))
    _verify_signature(digest, authorization.signature, signer)
    require_canonical_burn_block(bsv_rpc, policy, reference)
    return authorization
