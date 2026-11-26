"""Check authorization barriers in emitted bytecode and in BSV Node."""

from itertools import product
import unittest

from tx_engine import Script, Tx, TxIn

from assemble import assemble
from p2pkh_r1 import locking_script_from_owner_hash
from fourthgraph.bsv.script import OPS, asm, push
from signature import authorization, current_input_unlock
from test_payment import TRUE, check, child, fixture_signature, locking_script, parent, signer


def decode_program(raw):
    """Read opcode boundaries without treating pushed bytes as instructions."""
    instructions = []
    offset = 0
    while offset < len(raw):
        start = offset
        opcode = raw[offset]
        offset += 1
        if opcode <= 75:
            offset += opcode
        elif 76 <= opcode <= 78:
            width = 1 << (opcode - 76)
            if offset + width > len(raw):
                raise ValueError('truncated push length')
            size = int.from_bytes(raw[offset:offset + width], 'little')
            offset += width + size
        if offset > len(raw):
            raise ValueError('truncated push payload')
        instructions.append((start, opcode))
    return instructions


def end_barriers(instructions, barriers):
    """Intersect the barriers crossed by every syntactic path to the end."""
    branches = {}
    nesting = []
    for index, (_, opcode) in enumerate(instructions):
        if opcode in (OPS['OP_IF'], OPS['OP_NOTIF']):
            nesting.append((index, None))
        elif opcode == OPS['OP_ELSE']:
            conditional, alternative = nesting.pop()
            if alternative is not None:
                raise ValueError('multiple alternatives')
            nesting.append((conditional, index))
        elif opcode == OPS['OP_ENDIF']:
            conditional, alternative = nesting.pop()
            branches[conditional] = (conditional + 1, (alternative if alternative is not None else index) + 1)
            if alternative is not None:
                branches[alternative] = (index + 1,)
    if nesting:
        raise ValueError('unbalanced branches')

    incoming = [None] * (len(instructions) + 1)
    incoming[0] = set()
    for index, (offset, _) in enumerate(instructions):
        if incoming[index] is None:
            continue
        crossed = incoming[index] | barriers.get(offset, set())
        for successor in branches.get(index, (index + 1,)):
            if incoming[successor] is None:
                incoming[successor] = crossed.copy()
            else:
                incoming[successor].intersection_update(crossed)
    return incoming[-1]


class AuthorizationBarrierTests(unittest.TestCase):
    def test_actual_lock_bytecode_requires_all_authorization_barriers(self):
        owner = bytes(range(20))
        for compiled in (False, True):
            with self.subTest(compiled=compiled):
                raw = locking_script_from_owner_hash(owner, compiled_curve=compiled)
                instructions = decode_program(raw)
                self.assertNotIn(OPS['OP_RETURN'], [opcode for _, opcode in instructions])
                self.assertEqual(instructions[-1][1], OPS['OP_CHECKSIG'])

                def block(name):
                    return assemble(owner, compiled_curve=compiled, entry=name)

                locations = {instructions[-1][0]: {'native transaction check'}}

                def last_operation(needle, label, *, suffix_length=0):
                    start = raw.index(needle)
                    self.assertEqual(raw.count(needle), 1, label)
                    offset = start + len(needle) - suffix_length - 1
                    self.assertIn(offset, offsets, label)
                    locations[offset] = {label}

                offsets = {offset for offset, _ in instructions}
                last_operation(block('CHECK_TYPE'), 'sighash domain')
                last_operation(asm('OP_DEPTH 3 OP_NUMEQUALVERIFY'), 'stack shape')
                last_operation(asm('OP_OVER OP_HASH160') + push(owner) + asm('OP_EQUALVERIFY'),
                               'owner HASH160')
                last_operation(block('CHECK_R1_FIELDS'), 'scalar bounds and curve equation')
                last_operation(asm('OP_DUP OP_1') + block('N') + asm('OP_WITHIN OP_VERIFY OP_DUP 5 OP_PICK OP_MUL')
                               + block('N') + asm('OP_MOD OP_1 OP_NUMEQUALVERIFY'), 'inverse check')
                verify_result = asm('OP_FROMALTSTACK OP_BOOLOR OP_VERIFY')
                cleanup = block('CLEAR_POINTS')
                self.assertTrue(block('VERIFY_R1_POINT').endswith(verify_result + cleanup))
                last_operation(verify_result + cleanup, 'ECDSA result', suffix_length=len(cleanup))
                self.assertEqual(end_barriers(instructions, locations), set().union(*locations.values()))

    def test_node_enforces_owner_authorization_in_each_spend_context(self):
        owner_key, q, owner_hash = signer(7)
        other_key, _, _ = signer(19)
        paths = ((0x41, (400, 600)), (0x61, (400, 600)), (0x63, (900,)), (0xe3, (900,)))
        contexts = ((False, 1), (True, 1), (True, 3))
        # P2SH, SIGPUSHONLY, CLTV, CSV and NULLFAIL. MINIMALDATA and
        # CLEANSTACK are deliberately absent from these block-style flags.
        extra_flags = sum(1 << bit for bit in (0, 5, 9, 10, 14))
        for compiled, version, (flag, amounts) in product((False, True), (1, 2), paths):
            previous = [parent(TRUE, 400, '22'),
                        parent(locking_script(owner_hash, compiled_curve=compiled), 1000, '33')]
            fixture = child(previous, amounts)
            unsigned = Tx(version, fixture.tx_ins, fixture.tx_outs, 0)
            auth = authorization(unsigned, 1, 1000, flag)
            witnesses = (
                ('authorized', current_input_unlock(auth, q, fixture_signature(owner_key, auth.digest()))),
                ('different key', current_input_unlock(auth, q, fixture_signature(other_key, auth.digest()))),
                ('absent', Script()),
            )
            for (chronicle, height), (case, witness) in product(contexts, witnesses):
                with self.subTest(compiled=compiled, version=version, flag=hex(flag),
                                  chronicle=chronicle, height=height, case=case):
                    tx = Tx(version, [unsigned.tx_ins[0], TxIn(previous[1].id(), 0, witness)],
                            unsigned.tx_outs, 0)
                    want = case == 'authorized' and (chronicle or not (flag & 0x20))
                    check(tx, previous, 1, want, chronicle=chronicle, funding_height=height,
                          extra_flags=extra_flags)
