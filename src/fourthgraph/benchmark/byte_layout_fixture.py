"""Exercise independent and combined byte-layout bindings against a byte oracle."""

from pathlib import Path
from random import Random

from fourthgraph.bsv.script import push
from fourthgraph.compiler.byte_layout import ByteLayoutBuilder
from .formula_fixture import check_outputs


class ByteLayoutFixture:
    name = "byte-layout"
    entry = "convert-fields"
    implementations = (name,)

    @staticmethod
    def source(implementation):
        if implementation != ByteLayoutFixture.name:
            raise ValueError("byte-layout has one frozen caller")
        return (Path(__file__).with_name("fixtures") / "byte-layout.fth").read_bytes()

    @staticmethod
    def builder(source):
        return ByteLayoutBuilder(source.decode())

    @staticmethod
    def vectors():
        rng = Random(23204)
        patterns = (bytes(224), b"\xff" * 224, bytes(range(224)), bytes(range(223, -1, -1)),
                    *(rng.randbytes(224) for _ in range(20)))
        for sample in patterns:
            short, wide = sample[:32], sample[32:]
            lanes = b"".join(wide[i:i+32][::-1] for i in range(0, 192, 32))
            first = bytes(value ^ mask for value, mask in zip(short[::-1], range(32), strict=True))
            second = bytes(value ^ mask for value, mask in zip(lanes, bytes.fromhex("3cc369") * 64, strict=True))
            yield (short.hex(), wide.hex()), (first.hex(), second.hex())

    @staticmethod
    def encode(value):
        return push(bytes.fromhex(value))

    @staticmethod
    def wrong(operands):
        short, wide = map(bytes.fromhex, operands)
        if short[0] % 2:
            short = bytes((short[0] ^ 1,)) + short[1:]
        else:
            wide = bytes((wide[0] ^ 1,)) + wide[1:]
        return short.hex(), wide.hex()

    def check(self, script):
        return check_outputs(self.vectors(), script, bytes.fromhex)
