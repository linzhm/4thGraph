"""Compare SHA-256 repetition plans against the Python hash oracle."""

from hashlib import sha256, shake_256
from pathlib import Path

from fourthgraph.bsv.script import push
from fourthgraph.compiler.hash_chain import HashChainBuilder
from .formula_fixture import check_outputs


class HashChainFixture:
    name = "hash-chain"
    entry = "hash-chain-checkpoint"
    implementations = (name,)

    @staticmethod
    def source(implementation):
        if implementation != HashChainFixture.name:
            raise ValueError("hash-chain has one frozen caller")
        return (Path(__file__).with_name("fixtures") / "hash-chain.fth").read_bytes()

    @staticmethod
    def builder(source):
        return HashChainBuilder(source.decode())

    @staticmethod
    def vectors():
        for size in (0, 1, 31, 32, 55, 56, 63, 64, 65, 253, 255, 256, 520, 1024, 4096):
            samples = (bytes(size), shake_256(b"hash-chain-vector").digest(size)) if size else (b"",)
            for data in samples:
                first = digest = sha256(data).digest()
                for _ in range(65):
                    digest = sha256(digest).digest()
                yield (data.hex(),), (first.hex(), digest.hex())

    @staticmethod
    def encode(value):
        return push(bytes.fromhex(value))

    @staticmethod
    def wrong(operands):
        data = bytes.fromhex(operands[0])
        changed = bytes([data[0] ^ 1]) + data[1:] if data else b"\x01"
        return (changed.hex(),)

    def check(self, script):
        return check_outputs(self.vectors(), script, bytes.fromhex)
