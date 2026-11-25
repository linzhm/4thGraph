"""Exercise the lifecycle verifier's native transaction and signer binding."""

from hashlib import sha256
import unittest

from ecdsa import BadSignatureError, SECP256k1, VerifyingKey
from ecdsa.util import sigdecode_der

from burn_receipt import BurnReceipt
from covenant_backtrace import PROOF_FIELDS
from settlement_checkpoint import CLAIM_BYTES, MAX_PROGRAM, META_BYTES, _prefix
from prepared_lifecycle import MAX_LITERAL_PROGRAM, Action, _authorize_after_proof, lifecycle_relation
from prepared_lifecycle_wire import (ACTIVE, BURN, COMPACT_CODE, DOMAIN, FREEZE, FROZEN, ISSUANCE,
                                     MINT, NO_BURN, REMAINDER, TRANSFER, UNFREEZE, State, event_output)
from route_a_funding import reconstruction_script
from regtest_support import test_signer
from shared.evaluate import ScriptError, evaluate
from shared.script import asm, decode_num, push
from shared.transaction import Input, Transaction, hash256, preimage_all
from statement import AssetDescriptor, uint


class LifecycleBindingTests(unittest.TestCase):
    def test_reused_funding_fragments_leave_only_the_original_bytes(self):
        kernel = bytes(range(24))
        raw = b"".join(kernel + sha256(bytes([index])).digest()[:12] for index in range(64))
        old = reconstruction_script(raw)
        compact = reconstruction_script(raw, share_fragments=True)
        self.assertLess(len(compact), len(old))
        self.assertEqual(evaluate(compact, [b"prefix"]), ([b"prefix", raw], []))

    def setUp(self):
        self.alice = test_signer(21)
        self.bob = test_signer(22)
        self.issuer = test_signer(23)
        self.manager = test_signer(24)
        self.asset = AssetDescriptor(1, b"\x11" * 32 + bytes(4), 6, 7, b"a" * 32, b"p" * 32)
        self.policy = b"d" * 32
        self.program = bytes(range(255)) * 390
        self.inputs = tuple(Input(bytes([120 + i]) * 32, 0) for i in range(4))
        self.claim = b"\x01" + bytes(i % 251 + 1 for i in range(CLAIM_BYTES - 1))

    def metadata(self, c, max_program):
        if c[0] != 1:
            return c[:1] + bytes(META_BYTES - 1)
        p, pad = _prefix(c, self.program, REMAINDER, max_program=max_program)
        return b"\x01" + sha256(p).digest() + uint(len(p) + len(pad), 4) + c[1:37]

    def run_binding(self, action, signers, claims=None, *, extra=False, max_program=MAX_PROGRAM,
                    template_outputs=False):
        claims = (self.claim, self.claim) if claims is None else claims
        outputs = tuple(x.output(self.policy) for x in action.outputs)
        outputs += (action.burn.output() if action.burn else NO_BURN, event_output(action.event))
        if extra:
            outputs += (outputs[0],)
        tx = Transaction(self.inputs, outputs)
        prevouts = b"".join(x.outpoint() for x in self.inputs)
        preimage = preimage_all(tx, 1, 120_000, COMPACT_CODE)
        digest = hash256(preimage)
        signed = b"".join(signer(digest) + b"\x41" for signer in signers)
        stack = [self.program] + [b"x"] * PROOF_FIELDS
        stack += [signed, action.encode(), b"".join(claims), self.policy, prevouts, preimage]
        relation = lifecycle_relation(self.asset, self.issuer[0], self.manager[0], max_program=max_program,
                                      template_outputs=template_outputs)
        checked, alt = evaluate(relation, stack)
        wire = (DOMAIN + self.asset.issuance_outpoint + self.policy + self.issuer[0] + self.manager[0]
                + prevouts[72:] + b"".join(self.metadata(claim, max_program) for claim in claims) + action.encode())
        expected = hash256(wire)
        self.assertEqual(len(checked), PROOF_FIELDS + 2)
        self.assertEqual(tuple(map(decode_num, checked[-2:])),
                         (int.from_bytes(expected[:16], "big"), int.from_bytes(expected[16:], "big")))

        def checksig(sig, key):
            try:
                return sig[-1] == 0x41 and VerifyingKey.from_string(key, curve=SECP256k1).verify_digest(
                    sig[:-1], digest, sigdecode=sigdecode_der,
                )
            except BadSignatureError:
                return False

        # Feed the actual altstack values through the final Groth16 result.
        restore = b"".join(push(value) + asm("OP_TOALTSTACK") for value in alt)
        authorized, remaining = evaluate(restore + _authorize_after_proof(), [b"\x01"], checksig=checksig)
        self.assertEqual(authorized, [b"\x01"])
        self.assertEqual(remaining, [])

    def test_literal_funding_uses_the_same_parent_and_output_relation(self):
        self.program = push(bytes(460_055))
        a, sa = self.alice
        b, sb = self.bob
        action = Action(TRANSFER, (State(ACTIVE, 5, owner=a), State(ACTIVE, 7, owner=b)), (a, b))
        self.run_binding(action, (sa, sb), max_program=MAX_LITERAL_PROGRAM)
        with self.assertRaisesRegex(ScriptError, "VERIFY"):
            self.run_binding(action, (sa, sb))

    def test_all_action_output_vectors_and_roles(self):
        a, sa = self.alice
        b, sb = self.bob
        i, si = self.issuer
        m, sm = self.manager
        coins = State(ACTIVE, 5, owner=a), State(ACTIVE, 7, owner=b)
        frozen = State(FROZEN, 5, owner=a), coins[1]
        burn = BurnReceipt(self.asset.asset_id(), 7, b"b" * 20, 12)
        rows = (
            (Action(MINT, (State(ISSUANCE, 5, 1), coins[0]), (i, i), event=b"e" * 32), (si, si),
             (bytes(CLAIM_BYTES), b"\x02" + bytes(CLAIM_BYTES - 1))),
            (Action(TRANSFER, coins, (a, b)), (sa, sb), None),
            (Action(FREEZE, frozen, (m, m), mask=1), (sm, sm), None),
            (Action(UNFREEZE, coins, (m, m), mask=1), (sm, sm), None),
            (Action(BURN, (State(), State()), (a, b), burn=burn), (sa, sb), None),
        )
        for templated in (False, True):
            for action, signers, claims in rows:
                with self.subTest(action=action.kind, templated=templated):
                    self.run_binding(action, signers, claims, template_outputs=templated)
            with self.assertRaisesRegex(ScriptError, "EQUALVERIFY"):
                self.run_binding(rows[1][0], (sa, sb), extra=True, template_outputs=templated)
