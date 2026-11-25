"""Four-leaf externally approved inventory certificate (test-only issuance profile)."""

from dataclasses import dataclass
import json
from pathlib import Path
import subprocess

from inventory_tree import pair_digest
from shared.transaction import hash256
from statement import fixed


@dataclass(frozen=True)
class OriginStatement:
    anchor: bytes
    root: bytes
    opening: bytes

    def encode(self):
        return b"\x03" + self.anchor + self.root

    def digest(self):
        return hash256(self.encode())


def origin_statement(approved, order=(0, 1, 2, 3)):
    """The caller obtains approved leaves from authenticated creating transactions."""
    approved = tuple(fixed(digest, 32) for digest in approved)
    order = tuple(order)
    if len(approved) != 4 or len(set(approved)) != 4:
        raise ValueError("expected four distinct approved leaves")
    if any(type(i) is not int for i in order) or sorted(order) != [0, 1, 2, 3]:
        raise ValueError("expected a permutation of the four source leaves")
    leaves = tuple(approved[i] for i in order)
    root = pair_digest(pair_digest(*leaves[:2]), pair_digest(*leaves[2:]))
    raw = b"".join(approved)
    return OriginStatement(hash256(b"\x04" + raw), root, raw + bytes(order))


def prove_origin(tool: Path, params: Path, out: Path, approved, order=(0, 1, 2, 3)):
    statement = origin_statement(approved, order)
    subprocess.run([str(tool), "-mode", "prove", "-profile", "inventory-origin", "-dir", str(params),
                    "-statement", statement.encode().hex(), "-openings", statement.opening.hex(),
                    "-out", str(out)], check=True)
    artifact = json.loads(out.read_text())
    if artifact["statement"] != statement.encode().hex() or artifact["statement_digest"] != statement.digest().hex():
        raise ValueError("origin artifact belongs to another statement")
    return artifact


def direct_origin_script(approved_anchor):
    """[128 approved leaf-hash bytes, proposed root] -> bool, fixed approval order.

    The external approval has exactly the same meaning as in inventory-origin.
    This four-leaf Script replaces the test translation proof in that order.
    """
    from shared.script import asm, push

    anchor = fixed(approved_anchor, 32)
    pair = push(b"\x01") + asm("OP_SWAP OP_CAT OP_HASH256")
    return (
        asm("OP_TOALTSTACK OP_SIZE 128 OP_NUMEQUALVERIFY OP_DUP")
        + push(b"\x04") + asm("OP_SWAP OP_CAT OP_HASH256") + push(anchor) + asm("OP_EQUALVERIFY")
        + asm("64 OP_SPLIT") + pair + asm("OP_TOALTSTACK") + pair
        + asm("OP_FROMALTSTACK OP_CAT") + pair + asm("OP_FROMALTSTACK OP_EQUAL")
    )
