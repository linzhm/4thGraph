from dataclasses import replace
import unittest

from inventory_payment import token_output, token_witness
from inventory_ticket import (_open_ticket, template_ticket_token_parts, template_ticket_token_witness,
                              ticket_lock, ticket_token_parts, ticket_token_witness, ticket_witness)
from inventory_tree import InventoryState
from shared.chain_gang import validate_at_heights
from shared.evaluate import ScriptError, evaluate
from shared.script import asm, number, push
from shared.transaction import Input, Output, Transaction, hash256, preimage_all
from test_operational_token import fixture_signer
from transfer import COMPACT_SCRIPTCODE


class VoucherTicketTests(unittest.TestCase):
    def setUp(self):
        self.wallet, self.wallet_sign = fixture_signer(17)
        self.holder, self.holder_sign = fixture_signer(19)
        self.coupon = Input(b"c" * 32, 128, b"test issuer signature")
        self.verifier = Transaction((Input(b"v" * 32, 0),), (Output(2000, asm("OP_1")),))
        self.ticket = Transaction((self.coupon,), (Output(1000, ticket_lock(self.verifier, self.wallet)),))
        self.parts = ticket_token_parts(hash256(b"inventory ticket"), (self.coupon.outpoint(),), input_count=3)
        self.previous = token_output(InventoryState(100, 1000, self.holder), self.parts)
        self.origin = Transaction((Input(b"t" * 32, 0),), (self.previous,))

    def signed(self, verifier, ticket, payer=None):
        parents = (verifier, ticket, self.origin)
        tx = Transaction(tuple(Input(p.txid_wire(), 0) for p in parents), (self.previous,))
        signed = tx.with_script(1, ticket_witness(tx, ticket, payer or self.wallet_sign))
        signed = signed.with_script(2, token_witness(tx, 2, self.previous, ticket, self.holder_sign, compact_holder=True))
        return signed, parents

    def test_positive_and_resigned_spends(self):
        good, parents = self.signed(self.verifier, self.ticket)
        validate_at_heights(good, parents, spend_height=100, activation_height=2, utxo_heights=[3] * 3)
        foreign = replace(self.verifier, locktime=1)
        wrong_coupon = replace(self.ticket, inputs=(replace(self.coupon, vout=127),))
        for invalid, parents in (self.signed(foreign, self.ticket), self.signed(self.verifier, wrong_coupon),
                                 self.signed(self.verifier, self.ticket, self.holder_sign)):
            with self.subTest(tx=invalid.txid()), self.assertRaises(ValueError):
                validate_at_heights(invalid, parents, spend_height=100, activation_height=2, utxo_heights=[3] * 3)

    def test_canonical_funding_parser_opens_actual_output(self):
        script = _open_ticket((self.coupon.outpoint(),))
        w = Input(self.verifier.txid_wire(), 0).outpoint()

        def open_raw(raw, *, vout=0):
            vector = w + hash256(raw) + vout.to_bytes(4, "little") + bytes(36)
            return evaluate(push(b"owner signature") + push(raw) + push(vector) + script)

        self.assertEqual(open_raw(self.ticket.serialize()), ([b"owner signature"], []))
        ordinary = self.ticket.outputs[0]
        # Check output position and canonical field boundaries even when the
        # supplied funding bytes match the authenticated vin1 txid exactly.
        changed = (
            replace(self.ticket, inputs=(self.coupon, self.coupon)),
            replace(self.ticket, outputs=(ordinary, ordinary)),
            replace(self.ticket, outputs=(replace(ordinary, script=ordinary.script + asm("OP_NOP")),)),
            replace(self.ticket, outputs=(replace(ordinary, script=ordinary.script[:-1] + asm("OP_1")),)),
            replace(self.ticket, inputs=(replace(self.coupon, script=bytes(253)),)),
            replace(self.ticket, inputs=(replace(self.coupon, script=ordinary.serialize()),),
                    outputs=(Output(1000, asm("OP_1")),)),
        )
        for funding in changed:
            with self.subTest(funding=funding.txid()), self.assertRaises(ScriptError):
                open_raw(funding.serialize())
        with self.assertRaises(ScriptError):
            open_raw(self.ticket.serialize(), vout=1)

    def test_derived_prefix_authenticates_all_real_positions(self):
        parts = ticket_token_parts(hash256(b"inventory ticket"), (self.coupon.outpoint(),),
                                   input_count=4, derive_prevouts=True)
        prev = token_output(InventoryState(100, 1000, self.holder), parts)
        origins = tuple(Transaction((Input(bytes([k]) * 32, 0),), (prev,)) for k in (3, 4))
        parents = (self.verifier, self.ticket, *origins)
        tx = Transaction(tuple(Input(p.txid_wire(), 0) for p in parents), (prev, prev))
        signed = tx.with_script(1, ticket_witness(tx, self.ticket, self.wallet_sign))
        for vin in (2, 3):
            signed = signed.with_script(vin, ticket_token_witness(tx, vin, prev, self.ticket, self.holder_sign,
                                                                derive_prevouts=True))
        validate_at_heights(signed, parents, spend_height=100, activation_height=2, utxo_heights=[3] * 4)
        tail = b"".join(item.outpoint() for item in tx.inputs[2:])
        compact = preimage_all(tx, 2, prev.value, COMPACT_SCRIPTCODE)
        owner = self.holder_sign(hash256(preimage_all(tx, 2, prev.value, prev.script))) + b"\x41"
        raw = self.ticket.serialize()
        self.assertEqual(signed.inputs[2].script, b"".join(map(push, (owner, raw, tail, compact))))
        other_w = replace(self.verifier, locktime=1)
        other_ticket = replace(self.ticket, outputs=(Output(1000, ticket_lock(other_w, self.wallet)),))
        bad_cases = ((raw, tail[36:] + tail[:36]), (raw, tail[:-1]), (raw, tail + bytes(36)),
                     (other_ticket.serialize(), tail), (raw[:-1], tail), (raw, bytes(72) + tail))
        for source, bad_tail in bad_cases:
            with self.subTest(ticket_size=len(source), tail_size=len(bad_tail)), self.assertRaises(ValueError):
                changed = signed.with_script(2, b"".join(map(push, (owner, source, bad_tail, compact))))
                validate_at_heights(changed, parents, spend_height=100, activation_height=2, utxo_heights=[3] * 4)

    def test_template_reconstructs_independently_signed_funding(self):
        issuer, issue = fixture_signer(21)
        coupon = Output(40_000, push(issuer) + asm("OP_CHECKSIG"))
        base = Transaction((Input(b"c" * 32, 1),), (coupon, coupon))
        other = replace(base, locktime=1)
        all_sources = ((base, 0), (base, 1), (other, 1))
        scope = hash256(b"template ticket")

        def verify(tx, parents):
            validate_at_heights(tx, parents, spend_height=100, activation_height=2, utxo_heights=[3] * len(parents))

        # Single choice, shared coupon txid and unrelated coupon txids.
        for sources in (all_sources[:1], all_sources[:2], all_sources):
            coupons = tuple(Input(source.txid_wire(), vout).outpoint() for source, vout in sources)
            parts = template_ticket_token_parts(scope, coupons, input_count=4)
            prev = token_output(InventoryState(100, 1000, self.holder), parts)
            origins = tuple(Transaction((Input(bytes([k]) * 32, 0),), (prev, prev)) for k in (3, 4))
            source, vout = sources[-1]
            value = (128, 10_000, 32_768)[len(sources) - 1]
            verifier = replace(self.verifier, outputs=self.verifier.outputs * 2)
            w_vout = int(len(sources) > 1)
            output = Output(value, ticket_lock(verifier, self.wallet, verifier_vout=w_vout))
            candidate = Transaction((Input(source.txid_wire(), vout),), (output,))
            digest = hash256(preimage_all(candidate, 0, coupon.value, coupon.script))
            issuer_der = issue(digest)
            funding = candidate.with_script(0, push(issuer_der + b"\x41"))
            verify(funding, (source,))
            with self.assertRaises(ValueError):
                verify(candidate.with_script(0, push(self.wallet_sign(digest) + b"\x41")), (source,))
            parents = (verifier, funding, *origins)
            positions = (w_vout, 0, 0, 1)
            tx = Transaction(tuple(Input(p.txid_wire(), i) for p, i in zip(parents, positions, strict=True)), (prev, prev))
            signed = tx.with_script(1, ticket_witness(tx, funding, self.wallet_sign))
            for vin in (2, 3):
                signed = signed.with_script(vin, template_ticket_token_witness(tx, vin, prev, funding, self.holder_sign, coupons))
            verify(signed, parents)

            signature = self.holder_sign(hash256(preimage_all(tx, 2, prev.value, prev.script))) + b"\x41"
            binding = preimage_all(tx, 2, prev.value, COMPACT_SCRIPTCODE)
            tail = b"".join(item.outpoint() for item in tx.inputs[2:])
            slot = len(coupons) - 1
            fields = [push(signature), push(self.wallet), push(tx.inputs[0].outpoint()), number(value),
                      push(issuer_der), number(slot), push(tail), push(binding)]
            self.assertEqual(signed.inputs[2].script, b"".join(fields))
            for index, bad in ((1, push(self.holder)), (2, push(coupons[0])), (3, number(value + 1)),
                               (4, push(self.wallet_sign(digest))), (5, number(len(coupons))), (5, number(-1)),
                               (6, push(tail[36:] + tail[:36])), (6, push(tail[:-1]))):
                with self.subTest(coupon=slot, field=index), self.assertRaises(ValueError):
                    verify(signed.with_script(2, b"".join(fields[:index] + [bad] + fields[index+1:])), parents)
            if slot > 0:
                with self.assertRaises(ValueError):
                    verify(signed.with_script(2, b"".join(fields[:5] + [number(0)] + fields[6:])), parents)
            for changed in (replace(funding, version=1), replace(funding, locktime=1),
                            replace(funding, inputs=(replace(funding.inputs[0], sequence=1),)),
                            funding.with_script(0, push(issuer_der + b"\x43"))):
                with self.assertRaises(ValueError):
                    template_ticket_token_witness(tx, 2, prev, changed, self.holder_sign, coupons)

    def test_template_rejects_resigned_replacements(self):
        issuer, issuer_sign = fixture_signer(21)
        coupon = Output(10_000, push(issuer) + asm("OP_CHECKSIG"))
        source = Transaction((Input(b"c" * 32, 0),), (coupon, coupon))
        approved = Input(source.txid_wire(), 0)
        coupons = (approved.outpoint(),)
        parts = template_ticket_token_parts(hash256(b"template ticket"), coupons, input_count=3)
        token = token_output(InventoryState(100, 1000, self.holder), parts)
        origin = replace(self.origin, outputs=(token,))
        candidate = Transaction((approved,), (Output(1000, ticket_lock(self.verifier, self.wallet)),))

        def fund(unsigned):
            digest = hash256(preimage_all(unsigned, 0, coupon.value, coupon.script))
            signed = unsigned.with_script(0, push(issuer_sign(digest) + b"\x41"))
            validate_at_heights(signed, (source,), spend_height=100, activation_height=2, utxo_heights=[3])
            return signed

        honest = fund(candidate)
        def payment(w, actual, payer, holder):
            parents = (w, actual, origin)
            tx = Transaction(tuple(Input(p.txid_wire(), 0) for p in parents), (token,))
            signed = tx.with_script(1, ticket_witness(tx, actual, payer))
            signed = signed.with_script(2, template_ticket_token_witness(tx, 2, token, honest, holder, coupons))
            validate_at_heights(signed, parents, spend_height=100, activation_height=2, utxo_heights=[3] * 3)

        payment(self.verifier, honest, self.wallet_sign, self.holder_sign)
        # These are real signed coupon spends with identical ticket locks and
        # values. A fresh payer and owner signature on each replacement cannot
        # transplant the authenticated ticket or the designated verifier.
        for wrong in (replace(candidate, version=1), replace(candidate, locktime=1),
                      replace(candidate, inputs=(replace(approved, sequence=1),)),
                      replace(candidate, inputs=(replace(approved, vout=1),))):
            actual = fund(wrong)
            with self.subTest(replacement=actual.txid()), self.assertRaises(ValueError):
                payment(self.verifier, actual, self.wallet_sign, self.holder_sign)
        with self.assertRaises(ValueError):
            payment(replace(self.verifier, locktime=1), honest, self.wallet_sign, self.holder_sign)
        with self.assertRaises(ValueError):
            payment(self.verifier, honest, self.holder_sign, self.holder_sign)
        with self.assertRaises(ValueError):
            payment(self.verifier, honest, self.wallet_sign, self.wallet_sign)
