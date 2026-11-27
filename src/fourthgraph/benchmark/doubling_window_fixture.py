"""Verify a checkpoint and a doubling window, including their exact ScriptNums."""

from pathlib import Path

from fourthgraph.bsv.script import SECP256K1_FIELD as FIELD, encode_num
from fourthgraph.compiler.doubling_window import DoublingWindowBuilder
from fourthgraph.compiler.wordsets import signed_remainder
from .formula_fixture import check_outputs
from .point_add_fixture import affine, affine_add, homogeneous


GENERATOR = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)


def double_coordinates(coords):
    x, y, z = coords
    square = y * y
    tz = 21 * z * z
    triple = 3 * tz
    values = (2 * x * y * (square - triple),
              square * (square + 2 * triple) - triple * tz,
              8 * y**3 * z)
    return tuple(signed_remainder(value, FIELD) for value in values)


class DoublingWindowFixture:
    name = "doubling-window"
    entry = "double-with-checkpoint"
    implementations = (name,)

    @staticmethod
    def source(implementation):
        if implementation != DoublingWindowFixture.name:
            raise ValueError("doubling-window has one frozen caller")
        return (Path(__file__).with_name("fixtures") / "doubling-window.fth").read_bytes()

    @staticmethod
    def builder(source):
        return DoublingWindowBuilder(source.decode())

    @staticmethod
    def vectors():
        points = [None, GENERATOR, (GENERATOR[0], -GENERATOR[1] % FIELD)]
        multiple = GENERATOR
        for _ in range(5):
            multiple = affine_add(multiple, GENERATOR)
            points.append(multiple)
        for point in points:
            for z, shifts in ((1, (0, 0, 0)), (-3, (-2, 1, 0)), (17, (1, -2, 3)),
                              (1 - FIELD, (0, -1, -2))):
                coords = tuple(value + shift * FIELD for value, shift in zip(homogeneous(point, z), shifts, strict=True))
                first = double_coordinates(coords)
                final = first
                group = affine_add(point, point)
                if affine(first) != group:
                    raise ValueError("doubling checkpoint differs from the affine oracle")
                for _ in range(9):
                    final = double_coordinates(final)
                    group = affine_add(group, group)
                if affine(final) != group:
                    raise ValueError("doubling window differs from the affine oracle")
                yield (FIELD, *coords), (FIELD, *final, *first)

    @staticmethod
    def wrong(operands):
        other = affine_add(affine(operands[1:]), GENERATOR)
        return FIELD, *homogeneous(other, 7)

    def check(self, script):
        # This fixture's numeric field input is required at absolute stack bottom.
        return check_outputs(self.vectors(), script, encode_num, preserve_caller=False)
