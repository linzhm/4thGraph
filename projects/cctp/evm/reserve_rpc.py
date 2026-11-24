"""Read a finalized deposit from an authenticated, configured EVM RPC."""

from collections.abc import Callable
from dataclasses import dataclass
from json import JSONDecodeError, dumps, load
import re
from urllib.error import URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


DEPOSIT_TOPIC = bytes.fromhex(
    "bde8e6d134d2a5998f0607e7ef45563cde6edf6ce07605e38e75a8d5adcf86e3"
)
_HEX_QUANTITY = re.compile(r"0x(?:0|[1-9a-fA-F][0-9a-fA-F]{0,63})")
_HEX_DATA = re.compile(r"0x[0-9a-fA-F]*")
_FIELD = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
Rpc = Callable[..., object]


class DepositEvidenceError(ValueError):
    """The source has not provided acceptable finalized deposit evidence."""


class EvmJsonRpc:
    """Read-only JSON-RPC transport. The endpoint may contain a provider token."""

    _METHODS = frozenset(("eth_chainId", "eth_getTransactionReceipt", "eth_getBlockByNumber", "eth_call"))

    def __init__(self, url: str, *, timeout: float = 15):
        endpoint = urlsplit(url)
        local_http = endpoint.scheme == "http" and endpoint.hostname in ("127.0.0.1", "::1", "localhost")
        if (endpoint.scheme != "https" and not local_http) or not endpoint.hostname:
            raise ValueError("use HTTPS or a loopback EVM RPC URL")
        if endpoint.username or endpoint.password or endpoint.fragment:
            raise ValueError("invalid EVM RPC URL")
        self._url = url
        self._timeout = timeout

    def __call__(self, method: str, *params: object) -> object:
        if method not in self._METHODS:
            raise ValueError("unsupported EVM read method")
        body = dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
        request = Request(self._url, data=body, headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "BSV-Script-Lab-CCTP/0.1",
        })
        try:
            with urlopen(request, timeout=self._timeout) as response:
                envelope = load(response)
        except (URLError, TimeoutError, JSONDecodeError, UnicodeDecodeError):
            raise DepositEvidenceError(f"EVM RPC transport failed for {method}") from None
        if not isinstance(envelope, dict) or envelope.get("id") != 1 or "result" not in envelope:
            raise DepositEvidenceError(f"EVM RPC did not return a result for {method}")
        if envelope.get("error") is not None:
            raise DepositEvidenceError(f"EVM RPC failed for {method}")
        return envelope["result"]


@dataclass(frozen=True)
class ReserveScope:
    chain_id: int
    reserve_domain: int
    bsv_network: int
    vault: bytes
    reserve_asset: bytes
    asset_id: bytes

    def __post_init__(self):
        for value, bits, name in (
            (self.chain_id, 64, "chain ID"),
            (self.reserve_domain, 32, "reserve domain"),
            (self.bsv_network, 32, "BSV network"),
        ):
            if type(value) is not int or not 0 <= value < (1 << bits):
                raise ValueError(f"invalid {name}")
        if self.chain_id == 0:
            raise ValueError("invalid chain ID")
        for value, size, name in (
            (self.vault, 20, "reserve address"),
            (self.reserve_asset, 20, "reserve asset address"),
            (self.asset_id, 32, "bridge asset ID"),
        ):
            if type(value) is not bytes or len(value) != size or not any(value):
                raise ValueError(f"invalid {name}")


@dataclass(frozen=True)
class FinalizedDeposit:
    scope: ReserveScope
    tx_hash: bytes
    receipt_log_ordinal: int
    block_number: int
    block_hash: bytes
    finalized_number: int
    finalized_hash: bytes
    vault_nonce: int
    depositor: bytes
    quantity: int
    owner: bytes

    @property
    def source_asset(self) -> bytes:
        return bytes(12) + self.scope.reserve_asset

    @property
    def fee(self) -> int:
        # Deposit v1 requires an exact incoming credit and collects no fee.
        return 0


def _object(value: object, label: str) -> dict:
    if not isinstance(value, dict):
        raise DepositEvidenceError(f"missing or malformed {label}")
    return value


def _quantity(value: object, label: str) -> int:
    if not isinstance(value, str) or not _HEX_QUANTITY.fullmatch(value):
        raise DepositEvidenceError(f"malformed {label}")
    return int(value, 16)


def _data(value: object, size: int, label: str) -> bytes:
    if not isinstance(value, str) or len(value) != 2 + 2 * size or not _HEX_DATA.fullmatch(value):
        raise DepositEvidenceError(f"malformed {label}")
    return bytes.fromhex(value[2:])


def _uint(word: bytes, size: int, label: str) -> int:
    value = int.from_bytes(word, "big")
    if value >= (1 << size):
        raise DepositEvidenceError(f"noncanonical {label}")
    return value


def _address(word: bytes, label: str) -> bytes:
    if any(word[:12]) or not any(word[12:]):
        raise DepositEvidenceError(f"noncanonical {label}")
    return word[12:]


def _owner_key(owner: bytes) -> bool:
    x = int.from_bytes(owner[1:], "big")
    if owner[0] not in (2, 3) or x >= _FIELD:
        return False
    square = (pow(x, 3, _FIELD) + 7) % _FIELD
    root = pow(square, (_FIELD + 1) // 4, _FIELD)
    return root != 0 and root * root % _FIELD == square


def _decode_event(log: dict, scope: ReserveScope) -> tuple[int, bytes, int, bytes]:
    if _data(log.get("address"), 20, "log emitter") != scope.vault:
        raise DepositEvidenceError("log emitter is not the configured reserve")
    topics = log.get("topics")
    if not isinstance(topics, list) or len(topics) != 4:
        raise DepositEvidenceError("incorrect reserve deposit topics")
    event_type, nonce, depositor, asset = (_data(topic, 32, "deposit topic") for topic in topics)
    if event_type != DEPOSIT_TOPIC or asset != scope.asset_id:
        raise DepositEvidenceError("incorrect reserve deposit topic or bridge asset")
    data = _data(log.get("data"), 256, "deposit event data")
    if (_uint(data[:32], 32, "reserve domain") != scope.reserve_domain
            or _uint(data[32:64], 32, "BSV network") != scope.bsv_network
            or _address(data[64:96], "reserve asset") != scope.reserve_asset):
        raise DepositEvidenceError("deposit domain, BSV network, or reserve asset mismatch")
    if int.from_bytes(data[128:160], "big") != 160 or int.from_bytes(data[160:192], "big") != 33:
        raise DepositEvidenceError("noncanonical owner offset or length")
    owner = data[192:225]
    if any(data[225:]) or not _owner_key(owner):
        raise DepositEvidenceError("invalid compressed deposit owner")
    nonce_value = _uint(nonce, 64, "vault nonce")
    quantity = _uint(data[96:128], 64, "deposit quantity")
    if quantity == 0 or nonce_value == 0:
        raise DepositEvidenceError("empty deposit or vault nonce")
    return nonce_value, _address(depositor, "depositor"), quantity, owner


def read_finalized_deposit(
    rpc: Rpc, scope: ReserveScope, tx_hash: bytes, receipt_log_ordinal: int,
) -> FinalizedDeposit:
    """Check one receipt-local log under the configured RPC's finality policy.

    The RPC is a trust root for chain data. A canonical block and finalized
    checkpoint are required even when callers supply a successful receipt.
    """
    if type(tx_hash) is not bytes or len(tx_hash) != 32 or not any(tx_hash):
        raise ValueError("expected a nonzero EVM transaction hash")
    if type(receipt_log_ordinal) is not int or not 0 <= receipt_log_ordinal < (1 << 32):
        raise ValueError("expected a uint32 receipt-local log ordinal")

    if _quantity(rpc("eth_chainId"), "RPC chain ID") != scope.chain_id:
        raise DepositEvidenceError("RPC chain does not match reserve scope")
    receipt = _object(rpc("eth_getTransactionReceipt", "0x" + tx_hash.hex()), "transaction receipt")
    if _quantity(receipt.get("status"), "receipt status") != 1:
        raise DepositEvidenceError("deposit receipt did not succeed")
    if _data(receipt.get("transactionHash"), 32, "receipt transaction hash") != tx_hash:
        raise DepositEvidenceError("receipt transaction hash mismatch")
    block_hash = _data(receipt.get("blockHash"), 32, "receipt block hash")
    block_number = _quantity(receipt.get("blockNumber"), "receipt block number")
    tx_index = _quantity(receipt.get("transactionIndex"), "receipt transaction index")

    finalized = _object(rpc("eth_getBlockByNumber", "finalized", False), "finalized block")
    finalized_number = _quantity(finalized.get("number"), "finalized block number")
    finalized_hash = _data(finalized.get("hash"), 32, "finalized block hash")
    if not any(finalized_hash) or not any(block_hash):
        raise DepositEvidenceError("missing block hash")
    if finalized_number < block_number:
        raise DepositEvidenceError("deposit block has not finalized")

    canonical = _object(rpc("eth_getBlockByNumber", hex(block_number), False), "canonical deposit block")
    if (_quantity(canonical.get("number"), "canonical block number") != block_number
            or _data(canonical.get("hash"), 32, "canonical block hash") != block_hash
            or (finalized_number == block_number and finalized_hash != block_hash)):
        raise DepositEvidenceError("receipt block is not canonical")
    txs = canonical.get("transactions")
    if not isinstance(txs, list) or tx_index >= len(txs):
        raise DepositEvidenceError("transaction index missing in canonical block")
    if _data(txs[tx_index], 32, "canonical transaction hash") != tx_hash:
        raise DepositEvidenceError("transaction hash does not match canonical position")

    logs = receipt.get("logs")
    if not isinstance(logs, list) or receipt_log_ordinal >= len(logs):
        raise DepositEvidenceError("missing receipt-local log position")
    first_index = _quantity(_object(logs[0], "first receipt log").get("logIndex"), "first log index")
    for ordinal, item in enumerate(logs):
        log = _object(item, "receipt log")
        if (_quantity(log.get("logIndex"), "block log index") != first_index + ordinal
                or log.get("removed", False) is not False
                or _data(log.get("blockHash"), 32, "log block hash") != block_hash
                or _quantity(log.get("blockNumber"), "log block number") != block_number
                or _data(log.get("transactionHash"), 32, "log transaction hash") != tx_hash
                or _quantity(log.get("transactionIndex"), "log transaction index") != tx_index):
            raise DepositEvidenceError("log does not match its canonical receipt position")

    nonce, depositor, quantity, owner = _decode_event(logs[receipt_log_ordinal], scope)
    return FinalizedDeposit(
        scope, tx_hash, receipt_log_ordinal, block_number, block_hash,
        finalized_number, finalized_hash, nonce, depositor, quantity, owner,
    )
