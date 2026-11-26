"""Exercise the SHAKE Script with the independent chain-gang interpreter."""

from hashlib import shake_128, shake_256
import unittest

from shake_script import keccak_f1600_script, shake128_script, shake256_script
from fourthgraph.bsv.script import asm, push
from fourthgraph.bsv.transaction import Input, Output, Transaction
from tx_engine import Context, Script, Tx


def _engine_script(raw):
    script = Script()
    script.append_data(raw)
    return script


class ShakeScriptTests(unittest.TestCase):
    def test_zero_state_permutation(self):
        # XKCP tests/TestVectors/KeccakF-1600-IntermediateValues.txt, final lanes.
        zero_state_lanes = '''
        F1258F7940E1DDE7 84D5CCF933C0478A D598261EA65AA9EE BD1547306F80494D 8B284E056253D057
        FF97A42D7F8E6FD4 90FEE5A0A44647C4 8C5BDA0CD6192E76 AD30A6F71B19059C 30935AB7D08FFC64
        EB5AA93F2317D635 A9A6E6260D712103 81A57C16DBCF555F 43B831CD0347C826 01F22F1A11A5569F
        05E5635A21D9AE61 64BEFEF28CC970F2 613670957BC46611 B87C5A554FD00ECB 8C3EE88A1CCF32C8
        940C7922AE3A2614 1841F924A2C509E4 16F53526E70465C2 75F644E97F30A13B EAF1FF7B5CECA249
        '''
        expected = b''.join(bytes.fromhex(lane)[::-1] for lane in zero_state_lanes.split())
        # Leave a sentinel on each stack before executing the reusable fragment.
        code = push(b'main') + push(b'alt') + asm('OP_TOALTSTACK') + push(bytes(200))
        code += keccak_f1600_script() + push(expected) + asm('OP_EQUALVERIFY')
        code += push(b'main') + asm('OP_EQUALVERIFY OP_FROMALTSTACK') + push(b'alt') + asm('OP_EQUAL')
        self.assertTrue(Context(script=_engine_script(code), tx_version=1).evaluate())

    def test_packed_rows_match_lane_permutation_across_lane_boundaries(self):
        edge_bits = b''.join((1 << (63 if lane % 2 else 0)).to_bytes(8, 'little') for lane in range(25))
        for state in (edge_bits, bytes(range(200))):
            with self.subTest(state=state.hex()):
                code = push(state) + asm('OP_DUP') + keccak_f1600_script() + asm('OP_SWAP')
                code += keccak_f1600_script(packed_rows=False) + asm('OP_EQUAL')
                self.assertTrue(Context(script=_engine_script(code), tx_version=1).evaluate())

    def test_padding_and_squeezing_match_hashlib(self):
        modes = ((shake128_script, shake_128, 168), (shake256_script, shake_256, 136))
        for emitter, oracle, rate in modes:
            lengths = ((0, 32), (34, 32), (rate - 1, 64), (rate, 64), (rate + 1, rate + 37))
            for input_bytes, output_bytes in lengths:
                with self.subTest(xof=emitter.__name__, input_bytes=input_bytes, output_bytes=output_bytes):
                    message = bytes((index * 129 + 7) % 256 for index in range(input_bytes))
                    expected = oracle(message).digest(output_bytes)
                    code = push(message) + emitter(input_bytes, output_bytes) + push(expected) + asm('OP_EQUAL')
                    self.assertTrue(Context(script=_engine_script(code), tx_version=2).evaluate())

    def test_wrong_input_length_fails(self):
        code = push(b'a') + shake256_script(2, 32) + asm('OP_DROP OP_1')
        self.assertFalse(Context(script=_engine_script(code), tx_version=1).evaluate(quiet=True))

    def test_explicit_chronicle_context(self):
        message = bytes(range(34))
        regimes = ((14999, 14998), (15000, 14999), (15001, 15000))
        for emitter, oracle in ((shake128_script, shake_128), (shake256_script, shake_256)):
            digest = oracle(message).digest(32)
            lock = emitter(len(message), len(digest)) + push(digest) + asm('OP_EQUAL')
            # Synthetic inputs/UTXOs isolate the Script primitive from signing.
            funding = Transaction((Input(b'\x53' * 32, 0),), (Output(1000, lock),), version=1)
            parent = Tx.parse(funding.serialize())
            for version in (1, 2):
                for spend_height, utxo_height in regimes:
                    for matches in (True, False):
                        with self.subTest(xof=emitter.__name__, version=version,
                                          height=spend_height, matches=matches):
                            payload = message if matches else b'\xff' + message[1:]
                            spend = Transaction(
                                (Input(funding.txid_wire(), 0, push(payload)),),
                                (Output(900, asm('OP_1')),),
                                version=version,
                            )
                            candidate = Tx.parse(spend.serialize())
                            args = ([parent], spend_height, 15000, [(funding.txid(), 0, utxo_height)])
                            if matches:
                                candidate.validate_with_chronicle_context(*args, consensus_only=True)
                            else:
                                with self.assertRaises(ValueError):
                                    candidate.validate_with_chronicle_context(*args, consensus_only=True)


if __name__ == '__main__':
    unittest.main()
