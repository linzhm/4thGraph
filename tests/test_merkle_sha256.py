from hashlib import sha256
import unittest

from fourthgraph.bsv.evaluate import ScriptError, evaluate as evaluate_script
from fourthgraph.bsv.script import asm, encode_num, number
from fourthgraph.compiler.lowering import compile_word
from fourthgraph.compiler.source import CompileError, SourceCompiler, evaluate


def merkle_word(arguments):
    return SourceCompiler(
        f": root ( bytes bytes u32 -- bytes ) merkle-sha256-root {arguments} ;"
    ).words["root"]


class MerkleSha256Tests(unittest.TestCase):
    def test_ordered_paths_and_preserved_alt_stack(self):
        leaf = sha256(b"leaf").digest()
        for depth, index, tag in ((0, 0, b"\x02"), (2, 1, b"\x00"), (13, 7863, b"\xa5"), (32, 2**32 - 1, b"\x02")):
            with self.subTest(depth=depth, index=index, tag=tag):
                siblings = [sha256(bytes([i])).digest() for i in range(depth)]
                expected = leaf
                for level, sibling in enumerate(siblings):
                    ordered = sibling + expected if index >> level & 1 else expected + sibling
                    expected = sha256(tag + ordered).digest()

                path = b"".join(siblings)
                word = merkle_word(f"#{depth} {tag.hex()}")
                self.assertEqual(evaluate(word, leaf, path, index), (expected,))
                for mode in ("baseline", "stack", "dataflow"):
                    script = compile_word(word, mode, spend_entry=True).script
                    wrapped = number(7) + asm("OP_TOALTSTACK") + script + asm("OP_FROMALTSTACK")
                    self.assertEqual(
                        evaluate_script(wrapped, [leaf, path, encode_num(index)]),
                        ([expected, encode_num(7)], []),
                    )

    def test_shape_and_position_checks_are_inside_the_word(self):
        word = merkle_word("2 02")
        code = compile_word(word, "stack").script
        leaf, path = bytes(32), bytes(64)
        for stack in (
            (leaf[:-1], path, 0), (leaf, path[:-1], 0), (leaf, path + b"\0", 0),
            (leaf, path, -1), (leaf, path, 4), (leaf, path, 2**32),
        ):
            with self.subTest(leaf=len(stack[0]), path=len(stack[1]), index=stack[2]):
                with self.assertRaises(ValueError):
                    evaluate(word, *stack)
                with self.assertRaises(ScriptError):
                    evaluate_script(code, [*stack[:2], encode_num(stack[2])])

    def test_static_arguments_and_stack_type_are_checked(self):
        for arguments, reason in (
            ("x 02", "Merkle depth"),
            ("33 02", "Merkle depth"),
            ("-1 02", "Merkle depth"),
            ("2 100", "Merkle parent tag"),
            ("2 gg", "Merkle parent tag"),
        ):
            with self.subTest(arguments=arguments), self.assertRaisesRegex(CompileError, reason):
                merkle_word(arguments)
        with self.assertRaises(CompileError):
            SourceCompiler(": root ( bytes bytes cell -- bytes ) merkle-sha256-root 2 02 ;")
