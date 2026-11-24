from dataclasses import replace
from decimal import Decimal
import json
from pathlib import Path
import shutil
import socket
import subprocess
from tempfile import TemporaryDirectory
import time
from unittest import TestCase, skipUnless
from unittest.mock import patch

from projects.cctp.evm.public_testnet import (
    BASE_CHAIN, BASE_RPC, BASE_USDC, BSV_CHRONICLE_BLOCK, BSV_CHRONICLE_HEIGHT, BSV_GENESIS, DEFAULT_ARTIFACT, ROOT,
    BaseReadOnlyRpc, BsvReadOnlyRpc, DeploymentRequest, ReserveArtifact, TestnetError,
    check_funding, plan_deployment, probe_base, probe_bsv, verify_deployment,
    verify_paired_settlement, verify_signed_deployment,
)
from projects.cctp.evm.anvil_fixture import LocalEvm, deposit_position
from burn_receipt import BurnReceipt
from shared.transaction import Input, Transaction

from projects.cctp.evm.bsv_burn_evidence import BurnReference
from projects.cctp.evm.release_adapter import ReleaseClaim, Settlement, _address, _hash, _hex, _word, burn_event_id
from projects.cctp.evm.reserve_rpc import DepositEvidenceError, read_finalized_deposit


def _fixture_request():
    return {
        "deployer": _hex(bytes.fromhex("6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0")),
        "nonce": 0,
        "admin": _hex(b"a" * 20),
        "pause_guardian": _hex(b"g" * 20),
        "release_signer": _hex(b"s" * 20),
        "fee_recipient": _hex(b"f" * 20),
        "depositor": _hex(b"d" * 20),
        "relayer": _hex(b"r" * 20),
        "bsv_testnet_txid": _hex(bytes(range(32))),
        "bsv_testnet_vout": 1,
        "bsv_network": 2,
        "reserve_domain": 84532,
        "policy_id": _hex(b"p" * 32),
    }


class PublicTestnetTests(TestCase):
    def setUp(self):
        self.request = DeploymentRequest.parse(_fixture_request())
        self.artifact = ReserveArtifact(b"\x60\x01", b"\x60" + bytes(32) + b"\x00", ((1, 32),), "a" * 64)
        self.tx_hash = b"t" * 32
        self.block_hash = b"b" * 32
        self.latest_hash = b"l" * 32
        self.final_hash = b"f" * 32
        self.receipt = {
            "status": "0x1", "transactionHash": _hex(self.tx_hash), "blockNumber": "0x2",
            "blockHash": _hex(self.block_hash), "transactionIndex": "0x1",
            "contractAddress": _hex(self.request.vault()),
        }
        self.deployment = {
            "hash": _hex(self.tx_hash), "blockHash": _hex(self.block_hash), "to": None,
            "from": _hex(self.request.deployer), "nonce": "0x0", "chainId": hex(BASE_CHAIN),
            "value": "0x0", "input": _hex(self.artifact.creation + self.request.constructor_words()),
        }
        self.chain_id = BASE_CHAIN
        self.finalized_height = 3
        self.vault_code = b"\x60" + b"i" * 32 + b"\x00"
        self.finalized_admin = self.request.admin
        self.bsv_genesis = BSV_GENESIS
        self.bsv_checkpoint = BSV_CHRONICLE_BLOCK
        self.bsv_height = BSV_CHRONICLE_HEIGHT + 500
        self.bsv_anchor = {
            "bestblock": "a" * 64, "confirmations": 5, "value": Decimal("0.025"), "coinbase": False,
        }

    def evm(self, method, *args):
        r = self.request
        if method == "eth_chainId":
            return hex(self.chain_id)
        if method == "eth_getBlockByNumber":
            tag, full = args
            self.assertFalse(full)
            if tag == "latest":
                return {"number": "0x4", "hash": _hex(self.latest_hash)}
            if tag == "finalized":
                return {"number": hex(self.finalized_height), "hash": _hex(self.final_hash)}
            if tag == "0x2":
                return {"number": "0x2", "hash": _hex(self.block_hash),
                        "transactions": [_hex(b"x" * 32), _hex(self.tx_hash)]}
        if method == "eth_getCode":
            account, pin = args
            self.assertEqual(pin, {"blockHash": _hex(self.final_hash), "requireCanonical": True})
            return _hex(b"\x23" if account == _hex(BASE_USDC) else self.vault_code)
        if method == "eth_getTransactionReceipt":
            self.assertEqual(args, (_hex(self.tx_hash),))
            return self.receipt
        if method == "eth_getTransactionByHash":
            self.assertEqual(args, (_hex(self.tx_hash),))
            return self.deployment
        if method == "eth_getBalance":
            self.assertEqual(args[1], {"blockHash": _hex(self.latest_hash), "requireCanonical": True})
            return hex(1_000_000_000)
        if method == "eth_getTransactionCount":
            self.assertEqual(args, (_hex(r.deployer), "pending"))
            return hex(r.nonce)
        if method == "eth_call":
            target, pin = args
            self.assertTrue(pin["requireCanonical"])
            expected = {
                b"deploymentChainId()": _word(BASE_CHAIN), b"bsvNetwork()": _word(r.asset.network),
                b"reserveDomain()": _word(r.asset.reserve_domain), b"assetId()": r.asset.asset_id(),
                b"token()": _address(BASE_USDC), b"feeRecipient()": _address(r.fee_recipient),
                b"admin()": _address(self.finalized_admin), b"pauseGuardian()": _address(r.pause_guardian),
                b"releaseSigner()": _address(r.release_signer), b"decimals()": _word(6),
                b"balanceOf(address)": _word(1024),
            }
            for sig, value in expected.items():
                if target["data"].startswith(_hex(_hash(sig)[:4])):
                    return _hex(value)
        if method == "eth_estimateGas":
            tx, = args
            self.assertEqual(tx["data"], self.deployment["input"])
            self.assertEqual({"from", "data", "value"}, tx.keys())
            return hex(200_000)
        if method == "eth_gasPrice":
            return hex(100)
        self.fail(f"unexpected EVM method {method}")

    def bsv(self, method, *args):
        if method == "getnetworkinfo":
            return {"subversion": "/Bitcoin SV:1.2.3/"}
        if method == "getblockchaininfo":
            return {"chain": "test", "blocks": self.bsv_height, "headers": self.bsv_height, "bestblockhash": "a" * 64}
        if method == "getblockhash":
            return {0: self.bsv_genesis, BSV_CHRONICLE_HEIGHT: self.bsv_checkpoint,
                    self.bsv_height: "a" * 64}[args[0]]
        if method == "gettxout":
            self.assertEqual(args, (bytes(range(32)).hex(), 1, True))
            return self.bsv_anchor
        self.fail(f"unexpected BSV method {method}")

    def test_review_draft_uses_deterministic_create_address_and_scope(self):
        plan = plan_deployment(self.request, self.artifact)
        self.assertEqual(plan["expected_contract"], "0xcd234a471b72ba2f1ccf0a70fcaba648a5eecd8d")
        self.assertEqual(_hex(replace(self.request, nonce=1).vault()), "0x343c43a37d37dff08ae8c4a11544c718abb4fcf8")
        self.assertEqual(plan["transaction"]["chainId"], hex(BASE_CHAIN))
        self.assertEqual(plan["transaction"]["data"], self.deployment["input"])
        self.assertNotIn("to", plan["transaction"])
        self.assertEqual(plan["classification"], "unsigned_review_draft")
        self.assertFalse(plan["public_acceptance_ready"])
        self.assertEqual(self.request.asset.issuance_outpoint[:32], bytes(range(32))[::-1])
        self.assertEqual(self.request.asset.reserve_asset[12:], BASE_USDC)

    def test_rejects_fixture_network_and_shared_control_roles(self):
        with self.assertRaisesRegex(TestnetError, "separate public test bridge"):
            DeploymentRequest.parse(_fixture_request() | {"bsv_network": 1})
        data = _fixture_request()
        with self.assertRaisesRegex(TestnetError, "separate test wallets"):
            DeploymentRequest.parse(data | {"release_signer": data["admin"]})
        with self.assertRaisesRegex(TestnetError, "missing deployment request fields"):
            DeploymentRequest.parse(data | {"private_key": "disallowed extra field"})

    def test_funding_queries_are_read_only_and_check_scope(self):
        report = check_funding(self.evm, self.request, self.artifact)
        self.assertTrue(report["nonce_matches_review_request"])
        self.assertTrue(report["deployer_covers_l2_estimate"])
        self.assertEqual(report["depositor_usdc_base_units"], 1024)
        self.chain_id = 8453
        with self.assertRaisesRegex(TestnetError, "must be Base Sepolia"):
            probe_base(self.evm)
        with self.assertRaisesRegex(ValueError, "unsupported EVM read method"):
            BaseReadOnlyRpc(BASE_RPC)("eth_sendRawTransaction", "0x")

    def test_bsv_preflight_pins_post_fork_checkpoint_and_unspent_anchor(self):
        self.assertEqual(probe_bsv(self.bsv, self.request)["issuance_anchor"]["satoshis"], 2_500_000)
        self.bsv_anchor["coinbase"] = True
        with self.assertRaisesRegex(TestnetError, "not mature"):
            probe_bsv(self.bsv, self.request)
        self.bsv_checkpoint = "b" * 64
        with self.assertRaisesRegex(TestnetError, "synchronized Chronicle"):
            probe_bsv(self.bsv, self.request)

    def test_bitcoin_cli_string_results_and_read_allowlist(self):
        with TemporaryDirectory() as d:
            cookie = Path(d) / ".cookie"
            cookie.touch()
            node = BsvReadOnlyRpc(cookie, 18332)
            with patch("subprocess.run") as process:
                process.return_value.stdout = f"{BSV_GENESIS}\n"
                self.assertEqual(node("getblockhash", 0), BSV_GENESIS)
                self.assertEqual(process.call_args.args[0][-2:], ("getblockhash", "0"))
                with self.assertRaisesRegex(TestnetError, "unsupported read-only"):
                    node("sendrawtransaction", "deadbeef")

    def test_finalized_deployment_checks_actual_initcode_runtime_and_roles(self):
        evidence = verify_deployment(self.evm, self.request, self.artifact, self.tx_hash)
        self.assertEqual(evidence["verified"], "canonical_finalized_deployment")
        self.finalized_height = 1
        with self.assertRaisesRegex(TestnetError, "canonical finalized"):
            verify_deployment(self.evm, self.request, self.artifact, self.tx_hash)
        self.finalized_height = 3
        self.deployment["input"] += "00"
        with self.assertRaisesRegex(TestnetError, "reviewed request"):
            verify_deployment(self.evm, self.request, self.artifact, self.tx_hash)
        self.deployment["input"] = _hex(self.artifact.creation + self.request.constructor_words())
        self.vault_code = b"\x61" + self.vault_code[1:]
        with self.assertRaisesRegex(TestnetError, "bytecode differs"):
            verify_deployment(self.evm, self.request, self.artifact, self.tx_hash)
        self.vault_code = b"\x60" + self.vault_code[1:]
        self.finalized_admin = b"q" * 20
        with self.assertRaisesRegex(TestnetError, "scope or configured roles"):
            verify_deployment(self.evm, self.request, self.artifact, self.tx_hash)

    def test_paired_settlement_requires_exact_digest_and_keeps_provenance_unverified(self):
        request = self.request
        burn = BurnReceipt(request.asset.asset_id(), request.asset.reserve_domain, b"r" * 20, 640)
        tx = Transaction((Input(b"p" * 32, 0),), (burn.output(),))
        block_hash = b"b" * 32
        reference = BurnReference(tx.txid_wire(), 0, block_hash, self.bsv_height - 2)
        claim = ReleaseClaim(request.asset.network, reference.txid, reference.vout, reference.block_hash,
                             burn.asset_id, burn.reserve_domain, burn.recipient, burn.quantity, burn.fee, 1)
        settlement = Settlement(burn_event_id(request.asset.network, reference), claim.digest(request.scope()), True)

        def rpc(method, *args):
            if method == "getblockhash" and args == (reference.block_height,):
                return block_hash[::-1].hex()
            if method == "getblock":
                self.assertEqual(args, (block_hash[::-1].hex(), 1))
                return {"hash": args[0], "height": reference.block_height, "tx": [tx.txid()]}
            if method == "getrawtransaction":
                self.assertEqual(args, (tx.txid(), False))
                return tx.serialize().hex()
            return self.bsv(method, *args)

        with patch("projects.cctp.evm.public_testnet.read_settlement", return_value=settlement):
            observed = verify_paired_settlement(self.evm, rpc, request, reference, 1, min_confirmations=2)
            self.assertFalse(observed["recursive_provenance_verified"])
            self.assertEqual(observed["quantity"], 640)
            with self.assertRaisesRegex(TestnetError, "no finalized settlement"):
                verify_paired_settlement(self.evm, rpc, request, reference, 2, min_confirmations=2)

    @skipUnless(all(shutil.which(tool) for tool in ("forge", "anvil", "cast")), "requires Foundry")
    def test_local_rpc_deployment_matches_unsigned_draft_and_finalized_receipt(self):
        # Mimic Base's chain number and Circle address on disposable loopback
        # Anvil. All transaction submissions in this test stay on that process.
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        url = f"http://127.0.0.1:{port}"
        node = subprocess.Popen(
            ["anvil", "--host", "127.0.0.1", "--port", str(port), "--chain-id", str(BASE_CHAIN), "--silent"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

        def command(*args):
            return subprocess.run(args, cwd=ROOT, capture_output=True, text=True, timeout=45, check=True).stdout.strip()

        try:
            rpc = BaseReadOnlyRpc(url)
            deadline = time.monotonic() + 5
            while True:
                try:
                    self.assertEqual(rpc("eth_chainId"), hex(BASE_CHAIN))
                    break
                except DepositEvidenceError:
                    if node.poll() is not None or time.monotonic() >= deadline:
                        raise
                    time.sleep(0.05)
            evm = LocalEvm(rpc, url)
            admin, guardian, release_signer, fee_recipient, depositor, relayer = evm.accounts()[:6]
            # Well-known test-only key used solely on this local node.
            key = "00" * 31 + "01"
            deployer = command("cast", "wallet", "address", "--private-key", key)
            command("cast", "rpc", "--rpc-url", url, "anvil_setBalance", deployer, hex(10**18))
            command("forge", "build", "--root", str(ROOT))
            mock_artifact = ROOT / "out/TestUsdcReserve.t.sol/MockUsdc.json"
            mock_runtime = json.loads(mock_artifact.read_text())["deployedBytecode"]["object"]
            command("cast", "rpc", "--rpc-url", url, "anvil_setCode", _hex(BASE_USDC), mock_runtime)
            request = DeploymentRequest.parse(_fixture_request() | {
                "deployer": deployer, "admin": admin, "pause_guardian": guardian,
                "release_signer": release_signer, "fee_recipient": fee_recipient,
                "depositor": depositor, "relayer": relayer,
            })
            artifact = ReserveArtifact.load(DEFAULT_ARTIFACT)
            draft = plan_deployment(request, artifact)
            signed = command(
                "cast", "mktx", "--rpc-url", "http://127.0.0.1:1", "--chain", str(BASE_CHAIN),
                "--nonce", "0", "--gas-limit", "3000000", "--gas-price", "3000000000",
                "--priority-gas-price", "1000000000", "--private-key", key, "--create",
                draft["transaction"]["data"],
            )
            signed_bytes = bytes.fromhex(signed[2:])
            verified = verify_signed_deployment(request, artifact, signed_bytes)
            self.assertEqual(verified["expected_contract"], draft["expected_contract"])
            self.assertEqual(verified["max_l2_fee_wei"], 3_000_000 * 3_000_000_000)
            with self.assertRaisesRegex(TestnetError, "reviewed request"):
                verify_signed_deployment(replace(request, nonce=1), artifact, signed_bytes)
            command("cast", "publish", "--rpc-url", url, "--json", signed)
            receipt = rpc("eth_getTransactionReceipt", verified["hash"])
            self.assertEqual(receipt["contractAddress"].lower(), draft["expected_contract"])
            tx_hash = bytes.fromhex(receipt["transactionHash"][2:])
            with self.assertRaisesRegex(TestnetError, "canonical finalized"):
                verify_deployment(rpc, request, artifact, tx_hash)
            evm.mine_finality()
            result = verify_deployment(rpc, request, artifact, tx_hash)
            self.assertEqual(result["vault"], draft["expected_contract"])
            self.assertFalse(result["public_acceptance_ready"])
            self.assertTrue(probe_base(rpc)["canonical_block_hash_eth_call"])

            owner = "0x0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
            evm.send(_hex(BASE_USDC), "mint(address,uint256)", depositor, "1024", sender=admin)
            evm.send(_hex(BASE_USDC), "approve(address,uint256)", result["vault"], "1024", sender=depositor)
            deposit = evm.send(result["vault"], "deposit(uint64,bytes)", "1024", owner, sender=depositor)
            pos = deposit_position(deposit, result["vault"])
            evm.mine_finality()
            evidence = read_finalized_deposit(rpc, request.scope(), pos.transaction_hash, pos.log_ordinal)
            self.assertEqual(evidence.owner, bytes.fromhex(owner[2:]))
            self.assertEqual(evidence.quantity, 1024)
            self.assertEqual(evidence.depositor, request.depositor)
        finally:
            if node.poll() is None:
                node.terminate()
                try:
                    node.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    node.kill()
                    node.wait()
