"""BSV Script component for opening an arbitrary subset in a fixed inventory."""

from inventory_tree import multi_path
from shared.script import asm, number, push


def multipath_script(width, count):
    """Consume sibling hashes and a sorted list of index+digest records, leave root.

    The caller authenticates the resulting root and the selected records. Width
    is fixed by the lock. An FF sentinel follows the remaining selection, so a
    subtree can inspect its next index even after all selected records are used.
    """
    if (type(width) is not int or width < 1 or width > 128 or width & (width - 1)
            or type(count) is not int or not 1 <= count <= width):
        raise ValueError("expected a power-of-two width through 128 and a positive count within it")

    def visit(start, end):
        # [remaining siblings, records] -> [remaining siblings, remaining records, digest].
        test = (asm("OP_DUP OP_1 OP_SPLIT OP_DROP") + push(b"\0")
                + asm("OP_CAT OP_BIN2NUM") + number(end) + asm("OP_LESSTHAN OP_IF"))
        if end == start + 1:
            index_byte = number(start) if 1 <= start <= 16 else push(bytes([start]))
            body = (asm("OP_1 OP_SPLIT OP_SWAP") + index_byte
                    + asm("OP_EQUALVERIFY 32 OP_SPLIT OP_SWAP"))
        else:
            middle = (start + end) // 2
            body = (visit(start, middle) + asm("OP_TOALTSTACK") + visit(middle, end)
                    + asm("OP_FROMALTSTACK OP_SWAP OP_CAT OP_1")
                    + asm("OP_SWAP OP_CAT OP_HASH256"))
        return test + body + asm("OP_ELSE OP_SWAP OP_SIZE 32 OP_NUMEQUALVERIFY OP_ENDIF")

    return (asm("OP_SIZE") + number(count * 33) + asm("OP_NUMEQUALVERIFY")
            + push(b"\xff") + asm("OP_CAT") + visit(0, width)
            + asm("OP_SWAP") + push(b"\xff") + asm("OP_EQUALVERIFY"))


def selection_witness(leaves, positions):
    positions = tuple(positions)
    siblings = multi_path(leaves, positions)
    records = b"".join(bytes([i]) + leaves[i].digest() for i in positions)
    return b"".join(map(push, reversed(siblings))) + push(records)
