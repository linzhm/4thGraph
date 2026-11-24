"""Base Sepolia and BSV testnet preparation and read-only receipt verification."""

from argparse import ArgumentParser
from dataclasses import dataclass
from decimal import Decimal
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import subprocess
import sys

from ecdsa import SECP256k1

from statement import AssetDescriptor, uint

from projects.cctp.evm.bsv_burn_evidence import (
    BsvConfirmationPolicy, BurnReference, read_confirmed_burn, require_canonical_burn_block,
)
from projects.cctp.evm.release_adapter import ReleaseClaim, _address, _hash, _hex, _word, read_settlement
from projects.cctp.evm.reserve_rpc import (
    EvmJsonRpc, ReserveScope, _data, _object, _quantity, read_finalized_deposit,
)


BASE_RPC = "https://sepolia.base.org"
BASE_CHAIN = 84532
BASE_USDC = bytes.fromhex("036cbd53842c5426634e7929541ec2318f3dcf7e")
BSV_GENESIS = "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"
BSV_CHRONICLE_HEIGHT = 1_713_168
# Observed BSV testnet Chronicle activation block. Genesis is shared by other
# Bitcoin-family test chains, so require a later BSV-specific checkpoint.
BSV_CHRONICLE_BLOCK = "00000000046e321cb1aa6941a7cdc2a97ca65d0caa19e7302df68d1045bd5435"
ROOT = Path(__file__).resolve().parent
DEFAULT_ARTIFACT = ROOT / "out/TestUsdcReserve.sol/TestUsdcReserve.json"
PUBLIC_BLOCKERS = (
    "The integrated recursive lifecycle has no public testnet acceptance evidence.",
    "Operators must control the designated external signers and fund both test networks.",
    "Confirm relay/mining policy for the final BSV transaction and verifier script sizes.",
)


class TestnetError(ValueError):
    """The request or public test network does not match the expected scope."""


class BaseReadOnlyRpc(EvmJsonRpc):
    _METHODS = EvmJsonRpc._METHODS | {
        "eth_getCode", "eth_getBalance", "eth_getTransactionCount", "eth_getTransactionByHash",
        "eth_gasPrice", "eth_estimateGas",
    }


class BsvReadOnlyRpc:
    """Keep node credentials in a cookie file on the same machine as bitcoin-cli."""

    _METHODS = frozenset((
        "getnetworkinfo", "getblockchaininfo", "getblockhash", "getblock",
        "getrawtransaction", "getblockheader", "gettxout",
    ))

    def __init__(self, cookie: Path, port: int):
        if not 1 <= port <= 65535 or not cookie.is_file():
            raise TestnetError("invalid BSV loopback port or RPC cookie path")
        self._command = (
            "bitcoin-cli", "-testnet", "-rpcconnect=127.0.0.1", f"-rpcport={port}",
            f"-rpccookiefile={cookie}", "-rpcclienttimeout=30",
        )

    def __call__(self, method, *params):
        if method not in self._METHODS:
            raise TestnetError("unsupported read-only BSV RPC")
        args = [json.dumps(value) if isinstance(value, (bool, int)) else value for value in params]
        try:
            result = subprocess.run(
                (*self._command, method, *args), capture_output=True, text=True, check=True, timeout=35,
            ).stdout
        except (subprocess.SubprocessError, OSError):
            raise TestnetError(f"BSV RPC failed on {method}; check testnet node and cookie") from None
        result = result.strip()
        if not result:
            return None
        # bitcoin-cli prints string results directly and JSON objects as JSON.
        if method == "getblockhash" or (method in {"getrawtransaction", "getblockheader"} and params[-1] is False):
            return result
        return json.loads(result, parse_float=Decimal)


def address(value, label):
    result = _data(value, 20, label)
    if not any(result):
        raise TestnetError(f"zero {label}")
    return result


def _variable_hex(value, label):
    if not isinstance(value, str) or re.fullmatch(r"0x(?:[0-9a-fA-F]{2})*", value) is None:
        raise TestnetError(f"malformed {label}")
    return bytes.fromhex(value[2:])


@dataclass(frozen=True)
class DeploymentRequest:
    deployer: bytes
    nonce: int
    admin: bytes
    pause_guardian: bytes
    release_signer: bytes
    fee_recipient: bytes
    depositor: bytes
    relayer: bytes
    asset: AssetDescriptor

    @classmethod
    def parse(cls, value):
        data = _object(value, "deployment request")
        members = {
            "deployer", "nonce", "admin", "pause_guardian", "release_signer", "fee_recipient",
            "depositor", "relayer", "bsv_testnet_txid", "bsv_testnet_vout", "bsv_network",
            "reserve_domain", "policy_id",
        }
        if data.keys() != members:
            raise TestnetError("unexpected or missing deployment request fields")
        roles = tuple(address(data[name], name) for name in (
            "deployer", "admin", "pause_guardian", "release_signer", "fee_recipient", "depositor", "relayer",
        ))
        _, admin, guardian, release_signer, _, _, _ = roles
        if len({admin, guardian, release_signer}) != 3:
            raise TestnetError("admin, guardian, and release signer must be separate test wallets")
        uint(data["nonce"], 8)
        network = data["bsv_network"]
        reserve_domain = data["reserve_domain"]
        uint(network, 4)
        uint(reserve_domain, 4)
        if network in (0, 1) or reserve_domain in (0, 6, 7):
            raise TestnetError("use separate public test bridge identifiers, outside local and Circle fixtures")
        anchor_tx = _data(data["bsv_testnet_txid"], 32, "issuance anchor transaction")
        policy_id = _data(data["policy_id"], 32, "policy ID")
        if not any(anchor_tx) or not any(policy_id):
            raise TestnetError("empty issuance anchor transaction or policy ID")
        outpoint = anchor_tx[::-1] + uint(data["bsv_testnet_vout"], 4)
        asset = AssetDescriptor(network, outpoint, 6, reserve_domain, _address(BASE_USDC), policy_id)
        return cls(roles[0], data["nonce"], *roles[1:], asset)

    def constructor_words(self):
        return b"".join((
            _word(BASE_CHAIN), _word(self.asset.reserve_domain, 4), _word(self.asset.network, 4),
            self.asset.asset_id(), _address(BASE_USDC), _address(self.admin), _address(self.pause_guardian),
            _address(self.release_signer), _address(self.fee_recipient),
        ))

    def vault(self):
        # RLP([sender, nonce]) for a 20-byte EOA and a uint64 Ethereum nonce.
        nonce = self.nonce.to_bytes((self.nonce.bit_length() + 7) // 8, "big")
        encoded_nonce = nonce if 0 < self.nonce < 128 else bytes([0x80 + len(nonce)]) + nonce
        payload = b"\x94" + self.deployer + encoded_nonce
        return _hash(bytes([0xC0 + len(payload)]) + payload)[-20:]

    def scope(self):
        return ReserveScope(BASE_CHAIN, self.asset.reserve_domain, self.asset.network,
                            self.vault(), BASE_USDC, self.asset.asset_id())


@dataclass(frozen=True)
class ReserveArtifact:
    creation: bytes
    runtime: bytes
    immutable_ranges: tuple[tuple[int, int], ...]
    sha256: str

    @classmethod
    def load(cls, path: Path):
        raw = path.read_bytes()
        artifact = _object(json.loads(raw), "Foundry build")
        metadata = artifact["metadata"]
        settings = metadata["settings"]
        source_name = "src/TestUsdcReserve.sol"
        source_digest = metadata["sources"][source_name]["keccak256"]
        if (
            settings["compilationTarget"] != {source_name: "TestUsdcReserve"}
            or not metadata["compiler"]["version"].startswith("0.8.28+")
            or settings["evmVersion"] != "cancun"
            or settings["optimizer"] != {"enabled": True, "runs": 200}
            or source_digest != _hex(_hash((ROOT / source_name).read_bytes()))
        ):
            raise TestnetError("reserve artifact does not match the current source and compiler profile")
        runtime = _variable_hex(artifact["deployedBytecode"]["object"], "runtime bytecode")
        creation = _variable_hex(artifact["bytecode"]["object"], "creation bytecode")
        slots = artifact["deployedBytecode"]["immutableReferences"]
        ranges = tuple(sorted((r["start"], r["length"]) for entries in slots.values() for r in entries))
        last = 0
        for start, length in ranges:
            if start < last or length != 32 or start + length > len(runtime) or any(runtime[start:start + length]):
                raise TestnetError("invalid Solidity immutable bytecode offset")
            last = start + length
        if not creation or not runtime or len(slots) != 6 or any(not entries for entries in slots.values()):
            raise TestnetError("empty bytecode or wrong reserve immutable field count")
        return cls(creation, runtime, ranges, sha256(raw).hexdigest())

    def check_runtime(self, actual):
        if len(actual) != len(self.runtime):
            raise TestnetError("deployed reserve runtime length differs")
        masked = bytearray(actual)
        for start, length in self.immutable_ranges:
            masked[start:start + length] = bytes(length)
        if bytes(masked) != self.runtime:
            raise TestnetError("deployed reserve bytecode differs")


def _head(rpc, label):
    block = _object(rpc("eth_getBlockByNumber", label, False), f"Base {label} block")
    return _quantity(block.get("number"), f"Base {label} height"), _data(block.get("hash"), 32, f"Base {label} hash")


def _pin(block_hash):
    return {"blockHash": _hex(block_hash), "requireCanonical": True}


def _call(rpc, target, snapshot, selector, args=b""):
    payload = {"to": _hex(target), "data": _hex(_hash(selector)[:4] + args)}
    return _data(rpc("eth_call", payload, _pin(snapshot)), 32, "Base contract result")


def probe_base(rpc):
    if _quantity(rpc("eth_chainId"), "EVM chain ID") != BASE_CHAIN:
        raise TestnetError("EVM RPC must be Base Sepolia")
    latest, latest_hash = _head(rpc, "latest")
    finalized, finalized_hash = _head(rpc, "finalized")
    if finalized > latest or (finalized == latest and finalized_hash != latest_hash):
        raise TestnetError("Base latest/finalized RPC views disagree")
    code = _variable_hex(rpc("eth_getCode", _hex(BASE_USDC), _pin(finalized_hash)), "USDC bytecode")
    if not code or _call(rpc, BASE_USDC, finalized_hash, b"decimals()") != _word(6):
        raise TestnetError("missing or wrong Circle Base Sepolia test USDC")
    return {
        "chain_id": BASE_CHAIN, "latest_height": latest, "finalized_height": finalized,
        "finalized_hash": _hex(finalized_hash), "usdc": _hex(BASE_USDC), "decimals": 6,
        "usdc_runtime_keccak256": _hex(_hash(code)), "canonical_block_hash_eth_call": True,
    }


def probe_bsv(rpc, request=None, *, min_anchor_depth=2):
    chain = _object(rpc("getblockchaininfo"), "BSV blockchain info")
    network = _object(rpc("getnetworkinfo"), "BSV network info")
    subversion = network.get("subversion")
    version = re.fullmatch(r"/Bitcoin SV:(\d+)\.(\d+)\.(\d+)(?:[^/]*)/", subversion or "")
    if chain.get("chain") != "test" or not version or tuple(map(int, version.groups())) < (1, 2, 3):
        raise TestnetError("expected Chronicle-capable Bitcoin SV public testnet node")
    height = chain.get("blocks")
    if (
        type(height) is not int or height < BSV_CHRONICLE_HEIGHT
        or chain.get("headers") != height or chain.get("initialblockdownload")
        or rpc("getblockhash", 0) != BSV_GENESIS
        or rpc("getblockhash", BSV_CHRONICLE_HEIGHT) != BSV_CHRONICLE_BLOCK
        or rpc("getblockhash", height) != chain.get("bestblockhash")
    ):
        raise TestnetError("BSV node has not shown a synchronized Chronicle testnet chain")
    result = {"chain": "test", "height": height, "node": subversion,
              "chronicle_height": BSV_CHRONICLE_HEIGHT, "tip": chain["bestblockhash"]}
    if request:
        txid = request.asset.issuance_outpoint[:32][::-1].hex()
        vout = int.from_bytes(request.asset.issuance_outpoint[32:], "little")
        utxo = _object(rpc("gettxout", txid, vout, True), "unspent BSV issuance anchor")
        if (utxo.get("bestblock") != chain["bestblockhash"]
                or type(utxo.get("confirmations")) is not int
                or utxo["confirmations"] < max(min_anchor_depth, 100 if utxo.get("coinbase") else 1)):
            raise TestnetError("BSV anchor is not mature and sufficiently confirmed at the checked tip")
        satoshis = Decimal(str(utxo.get("value", ""))) * 100_000_000
        if not satoshis.is_finite() or satoshis < 1 or satoshis != satoshis.to_integral_value():
            raise TestnetError("invalid BSV issuance anchor amount")
        result["issuance_anchor"] = {
            "txid": txid, "vout": vout, "confirmations": utxo["confirmations"], "satoshis": int(satoshis),
        }
    return result


def plan_deployment(request, artifact):
    return {
        "classification": "unsigned_review_draft",
        "public_acceptance_ready": False,
        "blockers": list(PUBLIC_BLOCKERS),
        "expected_contract": _hex(request.vault()),
        "asset_id": _hex(request.asset.asset_id()),
        "artifact_sha256": artifact.sha256,
        "transaction": {
            "chainId": hex(BASE_CHAIN), "from": _hex(request.deployer), "nonce": hex(request.nonce),
            "data": _hex(artifact.creation + request.constructor_words()), "value": "0x0",
        },
    }


def check_funding(rpc, request, artifact=None):
    chain = probe_base(rpc)
    _, latest_hash = _head(rpc, "latest")
    latest_pin = _pin(latest_hash)
    role_balances = {
        label: _quantity(rpc("eth_getBalance", _hex(wallet), latest_pin), f"{label} ETH balance")
        for label, wallet in (
            ("deployer", request.deployer), ("depositor", request.depositor), ("relayer", request.relayer),
            ("admin", request.admin), ("pause_guardian", request.pause_guardian),
        )
    }
    usdc_units = int.from_bytes(_call(rpc, BASE_USDC, latest_hash, b"balanceOf(address)",
                                     _address(request.depositor)), "big")
    nonce = _quantity(rpc("eth_getTransactionCount", _hex(request.deployer), "pending"), "pending deployer nonce")
    report = {
        "base": chain, "roles_eth_wei": role_balances, "depositor_usdc_base_units": usdc_units,
        "deployer_pending_nonce": nonce, "nonce_matches_review_request": nonce == request.nonce,
        "all_transaction_roles_have_eth": all(role_balances.values()),
        "depositor_has_main_scenario_usdc": usdc_units >= 1024,
    }
    if artifact and nonce == request.nonce and role_balances["deployer"] > 0:
        tx = plan_deployment(request, artifact)["transaction"]
        operands = {name: tx[name] for name in ("from", "data", "value")}
        gas = _quantity(rpc("eth_estimateGas", operands), "deployment gas estimate")
        gas_price = _quantity(rpc("eth_gasPrice"), "Base gas price")
        report["l2_deployment_gas_estimate"] = gas
        report["l2_estimated_deployment_wei"] = gas * gas_price
        report["deployer_covers_l2_estimate"] = role_balances["deployer"] >= gas * gas_price
    return report


def _check_creation(tx, sender_field, request, artifact):
    if (
        "to" not in tx or tx["to"] is not None
        or _data(tx.get(sender_field), 20, "deployment sender") != request.deployer
        or _quantity(tx.get("nonce"), "deployment nonce") != request.nonce
        or _quantity(tx.get("chainId"), "deployment chain ID") != BASE_CHAIN
        or tx.get("value") != "0x0"
        or _variable_hex(tx.get("input"), "deployment input") != artifact.creation + request.constructor_words()
    ):
        raise TestnetError("deployment transaction does not match the reviewed request")


def verify_signed_deployment(request, artifact, signed_transaction):
    """Inspect an externally signed EIP-1559 envelope entirely offline."""
    if not signed_transaction or signed_transaction[0] != 2:
        raise TestnetError("external deployment must use an EIP-1559 signed transaction")
    try:
        encoded = subprocess.run(
            ("cast", "decode-transaction", "--network", "ethereum"),
            input=_hex(signed_transaction) + "\n", capture_output=True, text=True, check=True, timeout=20,
        ).stdout
    except (subprocess.SubprocessError, OSError):
        raise TestnetError("could not decode signed deployment with Foundry cast") from None
    tx = _object(json.loads(encoded), "signed deployment")
    _check_creation(tx, "signer", request, artifact)
    tx_hash = _hash(signed_transaction)
    if _data(tx.get("hash"), 32, "signed transaction hash") != tx_hash:
        raise TestnetError("signed transaction hash differs from the decoded envelope")
    r = _quantity(tx.get("r"), "signed R")
    s = _quantity(tx.get("s"), "signed S")
    if not 0 < r < SECP256k1.order or not 0 < s <= SECP256k1.order // 2:
        raise TestnetError("signed deployment has noncanonical ECDSA values")
    gas_limit = _quantity(tx.get("gas"), "signed gas limit")
    fee_cap = _quantity(tx.get("maxFeePerGas"), "signed fee cap")
    priority_fee_cap = _quantity(tx.get("maxPriorityFeePerGas"), "signed priority fee cap")
    if gas_limit < 53_000 or fee_cap == 0 or priority_fee_cap > fee_cap:
        raise TestnetError("signed deployment has invalid gas limits or fee caps")
    return {
        "verified": "signed_eip1559_deployment_envelope_matches_review_draft",
        "hash": _hex(tx_hash), "signer": _hex(request.deployer), "nonce": request.nonce,
        "chain_id": BASE_CHAIN, "expected_contract": _hex(request.vault()),
        "gas_limit": gas_limit, "max_fee_per_gas": fee_cap, "max_priority_fee_per_gas": priority_fee_cap,
        "max_l2_fee_wei": gas_limit * fee_cap, "public_acceptance_ready": False,
    }


def _verified_receipt(rpc, tx_hash):
    if _quantity(rpc("eth_chainId"), "EVM chain ID") != BASE_CHAIN:
        raise TestnetError("EVM RPC must be Base Sepolia")
    key = _hex(tx_hash)
    receipt = _object(rpc("eth_getTransactionReceipt", key), "deployment receipt")
    if receipt.get("transactionHash") != key or receipt.get("status") != "0x1":
        raise TestnetError("deployment transaction has no successful receipt")
    height = _quantity(receipt.get("blockNumber"), "receipt block height")
    receipt_hash = _data(receipt.get("blockHash"), 32, "deployment block hash")
    tx_index = _quantity(receipt.get("transactionIndex"), "deployment transaction index")
    finalized, finalized_hash = _head(rpc, "finalized")
    block = _object(rpc("eth_getBlockByNumber", hex(height), False), "deployment block")
    txs = block.get("transactions")
    if (
        height > finalized or (height == finalized and receipt_hash != finalized_hash)
        or block.get("hash") != _hex(receipt_hash) or block.get("number") != hex(height)
        or not isinstance(txs, list) or tx_index >= len(txs) or txs[tx_index] != key
    ):
        raise TestnetError("deployment does not belong to a canonical finalized Base block")
    return receipt, finalized_hash


def verify_deployment(rpc, request, artifact, tx_hash):
    receipt, finalized_hash = _verified_receipt(rpc, tx_hash)
    vault = request.vault()
    tx = _object(rpc("eth_getTransactionByHash", _hex(tx_hash)), "deployed transaction")
    _check_creation(tx, "from", request, artifact)
    if (
        tx.get("hash") != _hex(tx_hash) or tx.get("blockHash") != receipt["blockHash"]
        or _data(receipt.get("contractAddress"), 20, "deployment contract") != vault
    ):
        raise TestnetError("confirmed deployment receipt does not match the reviewed request")
    artifact.check_runtime(_variable_hex(rpc("eth_getCode", _hex(vault), _pin(finalized_hash)), "reserve bytecode"))
    fields = (
        (b"deploymentChainId()", _word(BASE_CHAIN)), (b"reserveDomain()", _word(request.asset.reserve_domain)),
        (b"bsvNetwork()", _word(request.asset.network)), (b"assetId()", request.asset.asset_id()),
        (b"token()", _address(BASE_USDC)), (b"feeRecipient()", _address(request.fee_recipient)),
        (b"admin()", _address(request.admin)), (b"pauseGuardian()", _address(request.pause_guardian)),
        (b"releaseSigner()", _address(request.release_signer)),
    )
    if any(_call(rpc, vault, finalized_hash, signature) != expected for signature, expected in fields):
        raise TestnetError("finalized reserve scope or configured roles differ")
    return {
        "tx_hash": _hex(tx_hash), "block_hash": receipt["blockHash"], "vault": _hex(vault),
        "asset_id": _hex(request.asset.asset_id()), "artifact_sha256": artifact.sha256,
        "verified": "canonical_finalized_deployment", "public_acceptance_ready": False,
    }


def verify_paired_settlement(rpc, bsv, request, reference, signer_epoch, *, min_confirmations):
    """Observe a finalized payout and matching confirmed receipt. Provenance is a separate gate."""
    probe_bsv(bsv)
    policy = BsvConfirmationPolicy(request.asset.network, "test", bytes.fromhex(BSV_GENESIS)[::-1],
                                   min_confirmations)
    burn = read_confirmed_burn(bsv, policy, reference, request.asset)
    claim = ReleaseClaim(
        request.asset.network, reference.txid, reference.vout, reference.block_hash, request.asset.asset_id(),
        request.asset.reserve_domain, burn.receipt.recipient, burn.receipt.quantity, burn.receipt.fee, signer_epoch,
    )
    digest = claim.digest(request.scope())
    settlement = read_settlement(rpc, request.scope(), reference)
    if settlement is None or not settlement.finalized or settlement.digest != digest:
        raise TestnetError("no finalized settlement for the exact BSV receipt and signer epoch")
    confirmations = require_canonical_burn_block(bsv, policy, reference)
    return {
        "bsv_vout": reference.vout, "bsv_txid": reference.txid[::-1].hex(),
        "bsv_block_hash": reference.block_hash[::-1].hex(), "bsv_confirmations": confirmations,
        "recipient": _hex(claim.recipient), "quantity": claim.quantity, "fee": claim.fee,
        "burn_id": _hex(settlement.burn_id), "attestation_digest": _hex(digest),
        "verified": "confirmed_burn_receipt_matches_finalized_settlement",
        "recursive_provenance_verified": False,
    }


def _bsv_from_env(port):
    cookie = os.environ.get("CCTP_BSV_TESTNET_COOKIE")
    return BsvReadOnlyRpc(Path(cookie), port) if cookie else None


def main(argv=None):
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", type=Path, default=DEFAULT_ARTIFACT)
    commands = parser.add_subparsers(dest="command", required=True)
    preflight = commands.add_parser("preflight")
    preflight.add_argument("--request", type=Path)
    preflight.add_argument("--bsv-rpc-port", type=int, default=18332)
    preflight.add_argument("--estimate-deploy", action="store_true")
    commands.add_parser("plan-deployment").add_argument("request", type=Path)
    signed = commands.add_parser("verify-signed-deployment")
    signed.add_argument("request", type=Path)
    signed.add_argument("signed_transaction", type=Path, help="private local file containing the signed hex envelope")
    deploy = commands.add_parser("verify-deployment")
    deploy.add_argument("request", type=Path)
    deploy.add_argument("deployment_txid")
    deposit = commands.add_parser("verify-deposit")
    deposit.add_argument("request", type=Path)
    deposit.add_argument("deployment_txid")
    deposit.add_argument("deposit_txid")
    deposit.add_argument("receipt_log_ordinal", type=int)
    deposit.add_argument("--expected-owner")
    deposit.add_argument("--expected-quantity", type=int, default=1024)
    settlement = commands.add_parser("verify-paired-settlement")
    settlement.add_argument("request", type=Path)
    settlement.add_argument("deployment_txid")
    settlement.add_argument("burn_txid", help="BSV txid in display order")
    settlement.add_argument("burn_vout", type=int)
    settlement.add_argument("burn_block_hash", help="BSV block hash in display order")
    settlement.add_argument("burn_height", type=int)
    settlement.add_argument("signer_epoch", type=int)
    settlement.add_argument("--bsv-rpc-port", type=int, default=18332)
    settlement.add_argument("--bsv-confirmations", type=int, default=2)
    args = parser.parse_args(argv)
    try:
        offline = args.command in {"plan-deployment", "verify-signed-deployment"}
        rpc = None if offline else BaseReadOnlyRpc(os.environ.get("CCTP_BASE_SEPOLIA_RPC", BASE_RPC))
        request = DeploymentRequest.parse(json.loads(args.request.read_bytes())) if args.request else None
        if args.command == "preflight":
            if args.estimate_deploy and request is None:
                raise TestnetError("gas estimation requires a deployment request")
            artifact = ReserveArtifact.load(args.artifact) if args.estimate_deploy else None
            report = check_funding(rpc, request, artifact) if request else {"base": probe_base(rpc)}
            bsv = _bsv_from_env(args.bsv_rpc_port)
            report["bsv"] = (probe_bsv(bsv, request) if bsv else {"status": "authorized_testnet_node_not_configured"})
            report["public_acceptance_ready"] = False
            report["blockers"] = list(PUBLIC_BLOCKERS)
        else:
            artifact = ReserveArtifact.load(args.artifact)
            if args.command == "plan-deployment":
                report = plan_deployment(request, artifact)
            elif args.command == "verify-signed-deployment":
                signed_tx = _variable_hex(args.signed_transaction.read_text().strip(), "external signed transaction")
                report = verify_signed_deployment(request, artifact, signed_tx)
            else:
                txid = _data(args.deployment_txid, 32, "deployment txid")
                report = verify_deployment(rpc, request, artifact, txid)
                if args.command == "verify-deposit":
                    evidence = read_finalized_deposit(rpc, request.scope(),
                                                     _data(args.deposit_txid, 32, "deposit txid"),
                                                     args.receipt_log_ordinal)
                    expected_owner = _data(args.expected_owner, 33, "BSV owner") if args.expected_owner else None
                    if (evidence.depositor != request.depositor or evidence.quantity != args.expected_quantity
                            or (expected_owner is not None and evidence.owner != expected_owner)):
                        raise TestnetError("finalized deposit differs from the requested test scenario")
                    report["deposit"] = {
                        "tx_hash": _hex(evidence.tx_hash), "block_hash": _hex(evidence.block_hash),
                        "receipt_log_ordinal": evidence.receipt_log_ordinal,
                        "quantity": evidence.quantity, "owner": _hex(evidence.owner), "finalized": True,
                    }
                if args.command == "verify-paired-settlement":
                    bsv = _bsv_from_env(args.bsv_rpc_port)
                    if bsv is None:
                        raise TestnetError("paired settlement verification requires an authorized BSV testnet cookie")
                    reference = BurnReference(
                        _data("0x" + args.burn_txid, 32, "BSV burn txid")[::-1], args.burn_vout,
                        _data("0x" + args.burn_block_hash, 32, "BSV burn block hash")[::-1], args.burn_height,
                    )
                    report["settlement"] = verify_paired_settlement(
                        rpc, bsv, request, reference, args.signer_epoch, min_confirmations=args.bsv_confirmations,
                    )
        print(json.dumps(report, indent=2))
    except (ValueError, OSError, KeyError, TypeError, ArithmeticError) as exc:
        # Avoid disclosing endpoint tokens and cookie file paths in CLI diagnostics.
        print(f"Testnet verification failed: {exc}" if isinstance(exc, ValueError)
              else "Testnet verification failed: check files or RPC result format", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
