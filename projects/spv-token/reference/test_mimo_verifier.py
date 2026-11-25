"""Shared-verifier checks across split, administration, MIMO and burn shapes."""
from dataclasses import replace
from hashlib import new, sha256
from importlib.util import find_spec
import json
import os
from pathlib import Path
import shutil
import subprocess
from tempfile import TemporaryDirectory
import unittest

from ecdsa import SECP256k1, SigningKey

from burn_receipt import BurnReceipt, read_burn
from circom_fixture_prover import CompiledProver
from mimo_verifier import MimoProfile
from mint import MintPolicy, authorize_mint, prepare_mint
from mint_events import Deposit, DepositPosition, EMPTY_ROOT, MintEvents
from operational_token import TokenPolicy, freeze_witness, ordinary_witness
from regtest_mint import Node, RpcFailure, base58check, sign_p2pkh
from shared.script import asm
from shared.transaction import Input, Output, Transaction, preimage_all
from statement import AssetDescriptor, Slot, public_inputs, transfer_bytes
from test_operational_token import fixture_signer
from transaction_relation import TokenState
from transaction_verifier import verifier_key_id
from transfer import COMPACT_SCRIPTCODE


class TransferProver:
    def __init__(self, directory, profile):
        self.directory = directory
        directory.mkdir()
        include = Path(__file__).resolve().parents[1] / "circuits/transfer_commitment.circom"
        source = directory / "transfer.circom"
        source.write_text(
            f'pragma circom 2.2.3;\ninclude "{include}";\n'
            'component main {public [digestHigh, digestLow]} = '
            f'TransferCommitment({profile.incoming}, {profile.flow_outputs}, 192);\n'
        )
        result = subprocess.run(
            ["circom", str(source), "--prime", "bls12381", "--r1cs", "--wasm", "-o", str(directory)],
            capture_output=True, text=True,
        )
        if result.returncode:
            raise RuntimeError(result.stderr)
        self.prover = CompiledProver.load(directory / "transfer.r1cs")
        self.profile = profile
        self.key = self.prover.key

    def prove(self, asset, tx, parent, inputs, outputs):
        lock = self.profile.lock(asset, self.key)
        statement = transfer_bytes(asset, verifier_key_id(self.key), tx, parent, lock,
                                   inputs, outputs, script_code=COMPACT_SCRIPTCODE)
        signals = public_inputs(statement)
        preimage = preimage_all(tx, 0, parent.outputs[0].value, COMPACT_SCRIPTCODE)

        def slots(items):
            return [list(s.index.to_bytes(4, "little") + s.quantity.to_bytes(8, "little")) for s in items]

        witness_input = self.directory / "input.json"
        witness_input.write_text(json.dumps({
            "prefix": list(asset.asset_id() + verifier_key_id(self.key)), "preimage": list(preimage),
            "inputSlots": slots(inputs), "outputSlots": slots(outputs),
            "digestHigh": str(signals[0]), "digestLow": str(signals[1]),
        }))
        generated = self.directory / "transfer_js"
        witness = self.directory / "witness.wtns"
        result = subprocess.run(
            ["node", str(generated / "generate_witness.js"), str(generated / "transfer.wasm"),
             str(witness_input), str(witness)], capture_output=True, text=True,
        )
        if result.returncode:
            raise RuntimeError(result.stderr)
        return self.prover.prove(witness)


@unittest.skipUnless(find_spec("tx_engine") and shutil.which("circom") and shutil.which("node"),
                     "requires chain-gang, Circom and Node.js")
class ActualMimoTests(unittest.TestCase):
    def test_actual_split_freeze_unfreeze_distinct_mimo_and_merge(self):
        if os.environ.get("CCTP_EVM_LIFECYCLE") == "1":
            from evm.anvil_fixture import HAS_FOUNDRY, start_anvil

            self.assertTrue(HAS_FOUNDRY, "cross-chain lifecycle requires forge, cast and anvil")
            self.assertIn("REGTEST_COOKIE", os.environ, "cross-chain lifecycle requires BSV Node regtest")
            with start_anvil() as evm:
                self._run_lifecycle(evm)
        else:
            self._run_lifecycle()

    def _run_lifecycle(self, evm=None):
        from shared.chain_gang import validate_at_heights

        owner_key, owner = fixture_signer(11)
        freeze_key, admin = fixture_signer(12)
        profiles = tuple(MimoProfile(a, b, 5, freeze_key, burn) for a, b, burn in
                         ((1, 2, False), (2, 2, False), (2, 1, False), (1, 1, True), (1, 0, True)))
        node = None
        sponsor_value = 100_000_000
        confirmed_blocks = {}

        def include(tx):
            node.submit(tx)
            block = node.call("generatetoaddress", 1, address)[0]
            if tx.txid() not in node.call("getblock", block, 1)["tx"]:
                raise AssertionError("transaction was not included in the BSV regtest block")
            confirmed_blocks[tx.txid_wire()] = block
            return block

        evidence = {"scope": "Anchored BSV mint and v2 transaction relations using a test deposit attestation", "transactions": {}}
        if "REGTEST_COOKIE" in os.environ:
            node = Node(os.environ["REGTEST_URL"], Path(os.environ["REGTEST_COOKIE"]))
            evidence["node"] = node.call("getnetworkinfo")["subversion"]
            owner_hash = new("ripemd160", sha256(owner_key).digest()).digest()
            address = base58check(b"\x6f" + owner_hash)
            coinbase = node.fund(address)
            # A reused regtest can cross its short subsidy halving interval.
            sponsor_value = min(sponsor_value, coinbase.outputs[0].value // 11)
            setup = Transaction((Input(coinbase.txid_wire(), 0),),
                                (Output(sponsor_value, asm("OP_1")),) * 10)
            setup = sign_p2pkh(setup, coinbase, 0, SigningKey.from_secret_exponent(11, curve=SECP256k1))
            include(setup)
        else:
            setup = Transaction((Input(b"f" * 32, 0),), (Output(100_000_000, asm("OP_1")),) * 10)

        anchor = Input(setup.txid_wire(), 5)
        reserve = None
        if evm:
            from cross_chain_fixture import AdoptedBsvChain, DurableBridge, LocalReserve

            reserve = LocalReserve(evm, anchor.outpoint())
            asset = reserve.asset
            evidence["scope"] = (
                "Local EVM and BSV regtest lifecycle with mock USDC and test proof parameters. "
                "BSV token ancestry is checked by the release host against confirmed transactions. "
                "Journal evidence uses SQLite across signer interruption, restart and reconciliation."
            )
            evidence["source_chain"] = {
                "chain_id": reserve.scope.chain_id, "vault": reserve.vault, "mock_usdc": reserve.usdc,
            }
            evidence["evm_deposits"] = {}
            evidence["evm_releases"] = {}
            evidence["mint_journal"] = {}
            evidence["reconciliation"] = {}
        else:
            asset = AssetDescriptor(1, anchor.outpoint(), 6, 7, b"r" * 32, b"p" * 32)

        def confirm(tx, parents, label):
            validate_at_heights(tx, parents, spend_height=100, activation_height=2,
                                utxo_heights=(3,) * len(parents))
            if node:
                block = include(tx)
                evidence["transactions"][label] = {
                    "txid": tx.txid(), "blockhash": block, "bytes": len(tx.serialize()),
                }

        project = Path(__file__).resolve().parents[1]
        with TemporaryDirectory(prefix=".mimo-", dir=project) as temp:
            provers = tuple(TransferProver(Path(temp) / f"profile-{i}", profile)
                            for i, profile in enumerate(profiles))
            locks = tuple(p.profile.lock(asset, p.key) for p in provers)
            policy = TokenPolicy(locks, freeze_key)

            def token(quantity, *, frozen=False):
                return Output(1000, policy.lock(TokenState(asset.asset_id(), quantity, owner_key, frozen)))

            verifiers = tuple(Transaction((Input(setup.txid_wire(), i),), (Output(sponsor_value * 9 // 10, lock),))
                              for i, lock in enumerate(locks))
            mint_key, mint_signer = fixture_signer(13)
            chain_id = reserve.scope.chain_id if reserve else 84532
            reserve_contract = reserve.scope.vault if reserve else b"r" * 20
            mint_policy = MintPolicy(asset, chain_id, reserve_contract, mint_key, policy.lock)
            genesis = Transaction((anchor,), (Output(sponsor_value // 2, mint_policy.state_lock(EMPTY_ROOT)),))
            mint_policy.check_genesis(genesis)
            if node:
                for parent in verifiers:
                    include(parent)
            confirm(genesis, (setup,), "mint-genesis")
            if reserve:
                bridge = DurableBridge(reserve, mint_policy, Path(temp) / "bridge.sqlite3")
                first_deposit, evidence["evm_deposits"]["1024"] = reserve.deposit(1024, owner_key)
            else:
                first_deposit = Deposit(
                    DepositPosition(chain_id, asset.reserve_domain, reserve_contract, b"t" * 32, 0),
                    asset.reserve_asset, asset.network, asset.asset_id(), 1024, 0, owner_key,
                )

            def run_mint(plan, transitions, label, *, interrupt=False):
                if not reserve:
                    signed = authorize_mint(plan, lambda _: plan.deposit, mint_signer)
                    confirm(signed, (plan.prior, setup), label)
                    return signed

                if not transitions:
                    node.call("generatetoaddress", 1, address)
                predecessor_chain = AdoptedBsvChain(node, confirmed_blocks)

                def current_mint_state():
                    return predecessor_chain.mint_state(mint_policy, genesis, transitions)

                predecessor = current_mint_state()
                signed, journal = bridge.authorize_mint(plan, current_mint_state, mint_signer, interrupt=interrupt)
                if not transitions:
                    pending = bridge.reconcile(0, 0)
                    self.assertEqual(pending["pending_mint"], plan.deposit.net_quantity)
                    evidence["reconciliation"]["before_first_mint_broadcast"] = pending
                confirm(signed, (plan.prior, setup), label)
                node.call("generatetoaddress", 1, address)
                confirmed_chain = AdoptedBsvChain(node, confirmed_blocks)
                confirmed = bridge.record_mint(confirmed_chain, signed, predecessor, plan.deposit.position.event_id())
                evidence["mint_journal"][label] = journal | confirmed
                return signed

            plan = prepare_mint(mint_policy, genesis, MintEvents(), first_deposit, Input(setup.txid_wire(), 6))
            origin = run_mint(plan, (), "mint-1024", interrupt=True)

            def transfer(label, prover, verifier, sources, output_amounts, receipt=None):
                parents, vouts, input_amounts = zip(*sources, strict=True)
                outputs = tuple(token(quantity) for quantity in output_amounts)
                flow_amounts = output_amounts
                if receipt is not None:
                    outputs += (receipt.output(),)
                    flow_amounts += (receipt.quantity,)
                tx = Transaction(
                    (Input(verifier.txid_wire(), 0), *(Input(p.txid_wire(), i) for p, i in zip(parents, vouts))),
                    outputs,
                )
                incoming = tuple(Slot(i, q) for i, q in enumerate(input_amounts, 1))
                outgoing = tuple(Slot(i, q) for i, q in enumerate(flow_amounts))
                signals, proof = prover.prove(asset, tx, verifier, incoming, outgoing)
                all_parents = (verifier, *parents)
                witness = prover.profile.witness(asset, prover.key, proof, tx, all_parents, policy)
                signed = tx.with_script(0, witness)
                for i, parent in enumerate(parents, 1):
                    signed = signed.with_script(i, ordinary_witness(tx, i, parent, policy, verifier, owner))
                if label == "distinct-mimo":
                    wrong = prover.profile.witness_material(
                        prover.key, proof, signals, tx, (verifier, parents[1], parents[0]),
                    )
                    broken = signed.with_script(0, wrong)
                    with self.assertRaisesRegex(ValueError, "OP_EQUALVERIFY"):
                        validate_at_heights(broken, all_parents, spend_height=100, activation_height=2,
                                            utxo_heights=(3,) * len(all_parents))
                    if node:
                        with self.assertRaises(RpcFailure) as rejected:
                            node.submit(broken)
                        self.assertEqual(rejected.exception.code, -26)
                        evidence["wrong_parent_rejection"] = str(rejected.exception)
                if receipt is not None:
                    receipt_vout = len(output_amounts)
                    self.assertEqual(read_burn(signed, receipt_vout, asset), receipt)
                    altered = replace(receipt, recipient=b"b" * 20)
                    changed_tx = replace(signed, outputs=(*signed.outputs[:receipt_vout], altered.output()))
                    with self.assertRaises(ValueError):
                        validate_at_heights(changed_tx, all_parents, spend_height=100, activation_height=2,
                                            utxo_heights=(3,) * len(all_parents))
                    if node:
                        with self.assertRaises(RpcFailure) as rejected:
                            node.submit(changed_tx)
                        self.assertEqual(rejected.exception.code, -26)
                        evidence[f"{label}-wrong-recipient"] = str(rejected.exception)
                confirm(signed, all_parents, label)
                return signed

            split = transfer("split", provers[0], verifiers[0], ((origin, 1, 1024),), (640, 384))

            def toggle(label, parent, sponsor, freeze):
                tx = Transaction((Input(parent.txid_wire(), 0), Input(setup.txid_wire(), sponsor)),
                                 (token(640, frozen=freeze),))
                signed = tx.with_script(0, freeze_witness(tx, 0, parent, policy, admin))
                confirm(signed, (parent, setup), label)
                return signed

            frozen = toggle("freeze", split, 7, True)
            if reserve:
                freeze_chain = AdoptedBsvChain(node, confirmed_blocks)
                freeze_lineage = freeze_chain.lineage(mint_policy, policy, provers)
                circulating, frozen_units = freeze_chain.supply(freeze_lineage, (frozen, 0), (split, 1))
                self.assertEqual((circulating, frozen_units), (1024, 640))
                evidence["reconciliation"]["frozen_split"] = bridge.reconcile(circulating, frozen_units)
            active = toggle("unfreeze", frozen, 8, False)
            mimo = transfer("distinct-mimo", provers[1], verifiers[1],
                            ((active, 0, 640), (split, 1, 384)), (640, 384))
            merged = transfer("merge", provers[2], verifiers[2], ((mimo, 0, 640), (mimo, 1, 384)), (1024,))
            recipient = reserve.recipient if reserve else b"a" * 20
            partial = BurnReceipt(asset.asset_id(), asset.reserve_domain, recipient, 640)
            change = transfer("partial-burn", provers[3], verifiers[3], ((merged, 0, 1024),), (384,), partial)
            self.assertEqual(policy.parse(change.outputs[0].script).quantity, 384)

            if reserve:
                node.call("generatetoaddress", 1, address)
                chain = AdoptedBsvChain(node, confirmed_blocks)
                lineage = chain.lineage(mint_policy, policy, provers)
                change_wallet, evidence["wallet_change"] = chain.payment(change, 0, asset, policy, lineage, owner_key)
                spent_wallet, evidence["wallet_spent"] = chain.payment(split, 1, asset, policy, lineage, owner_key)
                self.assertEqual((change_wallet.quantity, change_wallet.spend_status.value), (384, "unspent"))
                self.assertEqual((spent_wallet.quantity, spent_wallet.spend_status.value), (384, "spent"))
                with self.assertRaisesRegex(ValueError, "wrong asset or token lock"):
                    chain.payment(change, 1, asset, policy, lineage, owner_key)

                evidence["evm_releases"]["640"] = bridge.release(
                    chain, change, 1, lineage, circulating=change_wallet.quantity, interrupt=True,
                )
                evidence["main_path_accounting"] = bridge.reconcile(change_wallet.quantity, 0)
                second_deposit, evidence["evm_deposits"]["128"] = reserve.deposit(128, owner_key)
            else:
                second_deposit = replace(
                    first_deposit, position=replace(first_deposit.position, transaction_hash=b"s" * 32),
                    gross_quantity=128,
                )

            second_plan = prepare_mint(mint_policy, origin, plan.successor, second_deposit,
                                       Input(setup.txid_wire(), 9))
            second = run_mint(second_plan, (origin,), "mint-128")
            full = replace(partial, quantity=128)
            destroyed = transfer("full-burn", provers[4], verifiers[4], ((second, 1, 128),), (), full)
            self.assertEqual(destroyed.outputs, (full.output(),))
            if reserve:
                node.call("generatetoaddress", 1, address)
                chain = AdoptedBsvChain(node, confirmed_blocks)
                lineage = chain.lineage(mint_policy, policy, provers)
                final_supply, final_frozen = chain.supply(lineage, (change, 0))
                self.assertEqual((final_supply, final_frozen), (384, 0))
                evidence["evm_releases"]["128"] = bridge.release(
                    chain, destroyed, 0, lineage, circulating=final_supply,
                )
                evidence["final_accounting"] = bridge.reconcile(final_supply, final_frozen)
                self.assertEqual((evidence["final_accounting"]["pending_mint"],
                                  evidence["final_accounting"]["pending_release"]), (0, 0))
                evidence["journal_audit"] = bridge.audit()
        if node and "CCTP_MIMO_REPORT" in os.environ:
            Path(os.environ["CCTP_MIMO_REPORT"]).write_text(json.dumps(evidence, indent=2) + "\n")
