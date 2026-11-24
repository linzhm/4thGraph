"""SLH-DSA-SHA2-128s Script generator adapted from the Rúnar Python emitter.

Source: icellan/runar at 0159f4f2caeb2ecb26d22bf6e69e34b3950c4e32,
compilers/python/runar_compiler/codegen/slh_dsa.py.
Copyright (c) 2025 Rúnar Contributors. See LICENSE.runar for the MIT license.

This port emits bytes using the shared encoder and specializes SHA2-128s.
Entry stack: FIPS 205 internal message, signature, public key. Exit: boolean.
The generator's named stack positions are relative to this input suffix.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence

from shared.script import OPS, number, push


_BASIC_OPCODES = {
    "drop": OPS["OP_DROP"], "dup": OPS["OP_DUP"], "nip": OPS["OP_NIP"],
    "over": OPS["OP_OVER"], "pick": OPS["OP_PICK"], "roll": OPS["OP_ROLL"],
    "rot": OPS["OP_ROT"], "swap": OPS["OP_SWAP"],
}


def _make_stack_op(*, op: str, code: str = "", value: bytes = b"",
                   then: Sequence[bytes] = (), else_: Sequence[bytes] = ()) -> bytes:
    if op == "opcode":
        return bytes([OPS[code]])
    if op == "push":
        return value
    if op == "if":
        block = bytes([OPS["OP_IF"]]) + b"".join(then)
        if else_:
            block += bytes([OPS["OP_ELSE"]]) + b"".join(else_)
        return block + bytes([OPS["OP_ENDIF"]])
    # Depth metadata from the upstream representation is already encoded by
    # the immediately preceding number push, as required by PICK and ROLL.
    return bytes([_BASIC_OPCODES[op]])


def _raw_push(data: bytes) -> bytes:
    """Use minimal opcodes when the pushed bytes coincide with small integers."""
    if len(data) == 1:
        if 1 <= data[0] <= 16:
            return number(data[0])
        if data[0] == 0x81:
            return number(-1)
    return push(data)


# ===========================================================================
# 1. Parameter Sets (FIPS 205 Table 1, SHA2)
# ===========================================================================

class SLHCodegenParams:
    """SLH-DSA parameter set for codegen."""

    __slots__ = ("n", "h", "d", "hp", "a", "k", "len_", "len1", "len2")

    def __init__(self, n: int, h: int, d: int, hp: int, a: int, k: int,
                 len_: int, len1: int, len2: int) -> None:
        self.n = n
        self.h = h
        self.d = d
        self.hp = hp
        self.a = a
        self.k = k
        self.len_ = len_
        self.len1 = len1
        self.len2 = len2


def _slh_mk(n: int, h: int, d: int, a: int, k: int) -> SLHCodegenParams:
    len1 = 2 * n
    len2 = ((len1 * 15).bit_length() + 3) // 4
    return SLHCodegenParams(
        n=n, h=h, d=d, hp=h // d, a=a, k=k,
        len_=len1 + len2, len1=len1, len2=len2,
    )


_PARAMS = _slh_mk(16, 63, 7, 12, 14)


# ===========================================================================
# 1b. Fixed-length byte reversal helper
# ===========================================================================

def _emit_reverse_n(n: int) -> list[bytes]:
    """Generate an unrolled fixed-length byte reversal for *n* bytes."""
    if n <= 1:
        return []
    ops: list[bytes] = []
    # Phase 1: split into n individual bytes
    for _ in range(n - 1):
        ops.append(_make_stack_op(op="push", value=number(1)))
        ops.append(_make_stack_op(op="opcode", code="OP_SPLIT"))
    # Phase 2: concatenate in reverse order
    for _ in range(n - 1):
        ops.append(_make_stack_op(op="swap"))
        ops.append(_make_stack_op(op="opcode", code="OP_CAT"))
    return ops


# ===========================================================================
# 1c. Collect ops into array helper
# ===========================================================================

def _collect_ops(fn: Callable[[Callable[[bytes], None]], None]) -> list[bytes]:
    ops: list[bytes] = []
    fn(lambda op: ops.append(op))
    return ops


# ===========================================================================
# 2. Compressed ADRS (22 bytes)
# ===========================================================================
# [0] layer  [1..8] tree  [9] type  [10..13] keypair
# [14..17] chain/treeHeight  [18..21] hash/treeIndex

SLH_WOTS_HASH = 0
SLH_WOTS_PK = 1
SLH_TREE = 2
SLH_FORS_TREE = 3
SLH_FORS_ROOTS = 4


# ===========================================================================
# 2b. Runtime ADRS builders
# ===========================================================================

def _int4be(v: int) -> bytes:
    """Convert a compile-time integer to a 4-byte big-endian byte string."""
    return bytes([
        (v >> 24) & 0xFF,
        (v >> 16) & 0xFF,
        (v >> 8) & 0xFF,
        v & 0xFF,
    ])


def _emit_build_adrs18(
    emit: Callable,
    layer: int,
    adrs_type: int,
    chain: int,
    ta8_depth: int,
    kp4_depth: int,
) -> None:
    """Emit runtime 18-byte ADRS prefix.

    layer(1B) || PICK(treeAddr8)(8B) || type(1B) || PICK(keypair4)(4B) || chain(4B).

    Net stack effect: +1 (the 18-byte result on TOS).
    ta8_depth and kp4_depth are from TOS *before* this function pushes anything.
    """
    # Push layer byte (1B)
    emit(_make_stack_op(op="push", value=_raw_push(bytes([layer & 0xFF]))))
    # After push: ta8 at ta8_depth+1, kp4 at kp4_depth+1

    # PICK ta8: depth = ta8_depth + 1 (one extra item on stack)
    emit(_make_stack_op(op="push", value=number(ta8_depth + 1)))
    emit(_make_stack_op(op="pick"))
    emit(_make_stack_op(op="opcode", code="OP_CAT"))

    # Push type byte (1B)
    emit(_make_stack_op(op="push", value=_raw_push(bytes([adrs_type & 0xFF]))))
    emit(_make_stack_op(op="opcode", code="OP_CAT"))

    # keypair4
    if kp4_depth < 0:
        emit(_make_stack_op(op="push", value=_raw_push(bytes(4))))
    else:
        emit(_make_stack_op(op="push", value=number(kp4_depth + 1)))
        emit(_make_stack_op(op="pick"))
    emit(_make_stack_op(op="opcode", code="OP_CAT"))

    # Push chain (4B BE)
    emit(_make_stack_op(op="push", value=_raw_push(_int4be(chain))))
    emit(_make_stack_op(op="opcode", code="OP_CAT"))


def _emit_build_adrs(
    emit: Callable,
    layer: int,
    adrs_type: int,
    chain: int,
    ta8_depth: int,
    kp4_depth: int,
    hash_mode: str,
) -> None:
    """Emit a runtime 22-byte ADRS.

    hash_mode:
      - "zero"  -- append 4 zero bytes (hash=0)
      - "stack" -- TOS has a 4-byte BE hash value; consumed and appended

    For "zero": net stack effect = +1 (22B ADRS on TOS).
    For "stack": net stack effect = 0 (TOS hash4 replaced by 22B ADRS).
    """
    if hash_mode == "stack":
        emit(_make_stack_op(op="opcode", code="OP_TOALTSTACK"))
        adj_kp4 = kp4_depth - 1 if kp4_depth >= 0 else kp4_depth
        _emit_build_adrs18(emit, layer, adrs_type, chain, ta8_depth - 1, adj_kp4)
        emit(_make_stack_op(op="opcode", code="OP_FROMALTSTACK"))
        emit(_make_stack_op(op="opcode", code="OP_CAT"))
    else:
        # "zero"
        _emit_build_adrs18(emit, layer, adrs_type, chain, ta8_depth, kp4_depth)
        emit(_make_stack_op(op="push", value=_raw_push(bytes(4))))
        emit(_make_stack_op(op="opcode", code="OP_CAT"))


# ===========================================================================
# 3. SLH Stack Tracker
# ===========================================================================

class SLHTracker:
    """Tracks named stack positions and emits StackOps."""

    def __init__(self, init: list[str], emit: Callable) -> None:
        self.nm: list[str] = list(init)
        self.e = emit

    def depth(self) -> int:
        return len(self.nm)

    def find_depth(self, name: str) -> int:
        for i in range(len(self.nm) - 1, -1, -1):
            if self.nm[i] == name:
                return len(self.nm) - 1 - i
        raise RuntimeError(f"SLHTracker: '{name}' not on stack {self.nm}")

    def has(self, name: str) -> bool:
        return name in self.nm

    def push_bytes(self, n: str, v: bytes) -> None:
        self.e(_make_stack_op(op="push", value=_raw_push(v)))
        self.nm.append(n)

    def push_int(self, n: str, v: int) -> None:
        self.e(_make_stack_op(op="push", value=number(v)))
        self.nm.append(n)

    def push_empty(self, n: str) -> None:
        self.e(_make_stack_op(op="opcode", code="OP_0"))
        self.nm.append(n)

    def dup(self, n: str) -> None:
        self.e(_make_stack_op(op="dup"))
        self.nm.append(n)

    def drop(self) -> None:
        self.e(_make_stack_op(op="drop"))
        if self.nm:
            self.nm.pop()

    def nip(self) -> None:
        self.e(_make_stack_op(op="nip"))
        L = len(self.nm)
        if L >= 2:
            self.nm[L - 2:L] = [self.nm[L - 1]]

    def over(self, n: str) -> None:
        self.e(_make_stack_op(op="over"))
        self.nm.append(n)

    def swap(self) -> None:
        self.e(_make_stack_op(op="swap"))
        L = len(self.nm)
        if L >= 2:
            self.nm[L - 1], self.nm[L - 2] = self.nm[L - 2], self.nm[L - 1]

    def rot(self) -> None:
        self.e(_make_stack_op(op="rot"))
        L = len(self.nm)
        if L >= 3:
            r = self.nm[L - 3]
            del self.nm[L - 3]
            self.nm.append(r)

    def op(self, code: str) -> None:
        self.e(_make_stack_op(op="opcode", code=code))

    def roll(self, d: int) -> None:
        if d == 0:
            return
        if d == 1:
            self.swap()
            return
        if d == 2:
            self.rot()
            return
        self.e(_make_stack_op(op="push", value=number(d)))
        self.nm.append("")
        self.e(_make_stack_op(op="opcode", code="OP_ROLL"))
        self.nm.pop()  # pop the push
        idx = len(self.nm) - 1 - d
        r = self.nm[idx]
        del self.nm[idx]
        self.nm.append(r)

    def pick(self, d: int, n: str) -> None:
        if d == 0:
            self.dup(n)
            return
        if d == 1:
            self.over(n)
            return
        self.e(_make_stack_op(op="push", value=number(d)))
        self.nm.append("")
        self.e(_make_stack_op(op="opcode", code="OP_PICK"))
        self.nm.pop()  # pop the push
        self.nm.append(n)

    def to_top(self, name: str) -> None:
        self.roll(self.find_depth(name))

    def copy_to_top(self, name: str, n: str) -> None:
        self.pick(self.find_depth(name), n)

    def to_alt(self) -> None:
        self.op("OP_TOALTSTACK")
        if self.nm:
            self.nm.pop()

    def from_alt(self, n: str) -> None:
        self.op("OP_FROMALTSTACK")
        self.nm.append(n)

    def split(self, left: str, right: str) -> None:
        self.op("OP_SPLIT")
        if len(self.nm) >= 1:
            self.nm.pop()
        if len(self.nm) >= 1:
            self.nm.pop()
        self.nm.append(left)
        self.nm.append(right)

    def cat(self, n: str) -> None:
        self.op("OP_CAT")
        if len(self.nm) >= 2:
            self.nm[-2:] = []
        self.nm.append(n)

    def sha256(self, n: str) -> None:
        self.op("OP_SHA256")
        if len(self.nm) >= 1:
            self.nm.pop()
        self.nm.append(n)

    def equal(self, n: str) -> None:
        self.op("OP_EQUAL")
        if len(self.nm) >= 2:
            self.nm[-2:] = []
        self.nm.append(n)

    def rename(self, n: str) -> None:
        if self.nm:
            self.nm[-1] = n

    def raw_block(
        self,
        consume: list[str],
        produce: str,
        fn: Callable[[Callable], None],
    ) -> None:
        """Emit raw opcodes; tracker only records net stack effect."""
        for _ in reversed(consume):
            if self.nm:
                self.nm.pop()
        fn(self.e)
        if produce:
            self.nm.append(produce)


# ===========================================================================
# 4. Tweakable Hash T(pkSeed, ADRS, M)
# ===========================================================================
# trunc_n(SHA-256(pkSeedPad(64) || ADRSc(22) || M))
# pkSeedPad on main stack, accessed via PICK.

def _emit_slh_t_raw(e: Callable, n: int, pk_seed_pad_depth: int) -> None:
    """Emit a raw tweakable hash with pkSeedPad on main stack via PICK.

    Stack in:  adrsC(1) msg(0), pkSeedPad at depth pk_seed_pad_depth from TOS
    Stack out: result(0)
    """
    e(_make_stack_op(op="opcode", code="OP_CAT"))
    pick_depth = pk_seed_pad_depth - 1
    e(_make_stack_op(op="push", value=number(pick_depth)))
    e(_make_stack_op(op="pick"))
    e(_make_stack_op(op="swap"))
    e(_make_stack_op(op="opcode", code="OP_CAT"))
    e(_make_stack_op(op="opcode", code="OP_SHA256"))
    if n < 32:
        e(_make_stack_op(op="push", value=number(n)))
        e(_make_stack_op(op="opcode", code="OP_SPLIT"))
        e(_make_stack_op(op="drop"))


# ===========================================================================
# 5. WOTS+ One Chain (tweakable hash, dynamic hashAddress)
# ===========================================================================

def _slh_chain_step_then(n: int, pk_seed_pad_depth: int) -> list[bytes]:
    """Return one conditional hash step (if-then body).

    Entry: sigElem(2) steps(1) hashAddr(0)
    Exit:  newSigElem(2) (steps-1)(1) (hashAddr+1)(0)
    """
    ops: list[bytes] = []
    # DUP hashAddr before consuming it in ADRS construction
    ops.append(_make_stack_op(op="dup"))
    # Convert copy to 4-byte big-endian
    ops.append(_make_stack_op(op="push", value=number(4)))
    ops.append(_make_stack_op(op="opcode", code="OP_NUM2BIN"))
    ops.extend(_emit_reverse_n(4))

    # Get prefix from alt: FROMALT; DUP; TOALT
    ops.append(_make_stack_op(op="opcode", code="OP_FROMALTSTACK"))
    ops.append(_make_stack_op(op="opcode", code="OP_DUP"))
    ops.append(_make_stack_op(op="opcode", code="OP_TOALTSTACK"))
    ops.append(_make_stack_op(op="swap"))
    ops.append(_make_stack_op(op="opcode", code="OP_CAT"))

    # Move sigElem to top: ROLL 3
    ops.append(_make_stack_op(op="push", value=number(3)))
    ops.append(_make_stack_op(op="roll"))
    ops.append(_make_stack_op(op="opcode", code="OP_CAT"))

    # pkSeedPad via PICK
    ops.append(_make_stack_op(op="push", value=number(pk_seed_pad_depth)))
    ops.append(_make_stack_op(op="pick"))
    ops.append(_make_stack_op(op="swap"))
    ops.append(_make_stack_op(op="opcode", code="OP_CAT"))
    ops.append(_make_stack_op(op="opcode", code="OP_SHA256"))
    if n < 32:
        ops.append(_make_stack_op(op="push", value=number(n)))
        ops.append(_make_stack_op(op="opcode", code="OP_SPLIT"))
        ops.append(_make_stack_op(op="drop"))
    # Rearrange
    ops.append(_make_stack_op(op="rot"))
    ops.append(_make_stack_op(op="opcode", code="OP_1SUB"))
    ops.append(_make_stack_op(op="rot"))
    ops.append(_make_stack_op(op="opcode", code="OP_1ADD"))
    return ops


def _emit_slh_one_chain(
    emit: Callable,
    n: int,
    layer: int,
    chain_idx: int,
    pk_seed_pad_depth: int,
    ta8_depth: int,
    kp4_depth: int,
) -> None:
    """Emit one WOTS+ chain with tweakable hashing (raw opcodes).

    Input:  sig(3) csum(2) endptAcc(1) digit(0)
    Output: sigRest(2) newCsum(1) newEndptAcc(0)
    """
    # steps = 15 - digit
    emit(_make_stack_op(op="push", value=number(15)))
    emit(_make_stack_op(op="swap"))
    emit(_make_stack_op(op="opcode", code="OP_SUB"))

    # Save steps_copy, endptAcc, csum to alt
    emit(_make_stack_op(op="opcode", code="OP_DUP"))
    emit(_make_stack_op(op="opcode", code="OP_TOALTSTACK"))
    emit(_make_stack_op(op="swap"))
    emit(_make_stack_op(op="opcode", code="OP_TOALTSTACK"))
    emit(_make_stack_op(op="swap"))
    emit(_make_stack_op(op="opcode", code="OP_TOALTSTACK"))

    # Split n-byte sig element
    emit(_make_stack_op(op="swap"))
    emit(_make_stack_op(op="push", value=number(n)))
    emit(_make_stack_op(op="opcode", code="OP_SPLIT"))
    emit(_make_stack_op(op="opcode", code="OP_TOALTSTACK"))
    emit(_make_stack_op(op="swap"))

    # Compute hashAddr = 15 - steps (= digit)
    emit(_make_stack_op(op="opcode", code="OP_DUP"))
    emit(_make_stack_op(op="push", value=number(15)))
    emit(_make_stack_op(op="swap"))
    emit(_make_stack_op(op="opcode", code="OP_SUB"))

    psp_d_chain = pk_seed_pad_depth - 1
    ta8_d_chain = ta8_depth - 1
    kp4_d_chain = kp4_depth - 1

    # Build 18-byte ADRS prefix
    _emit_build_adrs18(emit, layer, SLH_WOTS_HASH, chain_idx, ta8_d_chain, kp4_d_chain)
    emit(_make_stack_op(op="opcode", code="OP_TOALTSTACK"))

    # Build then-ops for chain step
    then_ops = _slh_chain_step_then(n, psp_d_chain)

    # 15 unrolled conditional hash iterations
    for _ in range(15):
        emit(_make_stack_op(op="over"))
        emit(_make_stack_op(op="opcode", code="OP_0NOTEQUAL"))
        emit(_make_stack_op(op="if", then=then_ops))

    emit(_make_stack_op(op="drop"))
    emit(_make_stack_op(op="drop"))

    # Drop prefix from alt
    emit(_make_stack_op(op="opcode", code="OP_FROMALTSTACK"))
    emit(_make_stack_op(op="drop"))

    # Restore from alt (LIFO)
    emit(_make_stack_op(op="opcode", code="OP_FROMALTSTACK"))  # sigRest
    emit(_make_stack_op(op="opcode", code="OP_FROMALTSTACK"))  # csum
    emit(_make_stack_op(op="opcode", code="OP_FROMALTSTACK"))  # endptAcc
    emit(_make_stack_op(op="opcode", code="OP_FROMALTSTACK"))  # steps_copy

    # csum += steps_copy
    emit(_make_stack_op(op="rot"))
    emit(_make_stack_op(op="opcode", code="OP_ADD"))

    # Cat endpoint to endptAcc
    emit(_make_stack_op(op="swap"))
    emit(_make_stack_op(op="push", value=number(3)))
    emit(_make_stack_op(op="roll"))
    emit(_make_stack_op(op="opcode", code="OP_CAT"))


# ===========================================================================
# Full WOTS+ Processing (all len chains)
# ===========================================================================

def _emit_slh_wots_all(emit: Callable, p: SLHCodegenParams, layer: int) -> None:
    """Process all WOTS+ chains.

    Input:  psp(4) ta8(3) kp4(2) wotsSig(1) msg(0)
    Output: psp(3) ta8(2) kp4(1) wotsPk(0)
    """
    n = p.n
    len1 = p.len1
    len2 = p.len2

    emit(_make_stack_op(op="swap"))
    emit(_make_stack_op(op="push", value=number(0)))
    emit(_make_stack_op(op="opcode", code="OP_0"))
    emit(_make_stack_op(op="push", value=number(3)))
    emit(_make_stack_op(op="roll"))

    for byte_idx in range(n):
        if byte_idx < n - 1:
            emit(_make_stack_op(op="push", value=number(1)))
            emit(_make_stack_op(op="opcode", code="OP_SPLIT"))
            emit(_make_stack_op(op="swap"))
        # Unsigned byte conversion
        emit(_make_stack_op(op="push", value=number(0)))
        emit(_make_stack_op(op="push", value=number(1)))
        emit(_make_stack_op(op="opcode", code="OP_NUM2BIN"))
        emit(_make_stack_op(op="opcode", code="OP_CAT"))
        emit(_make_stack_op(op="opcode", code="OP_BIN2NUM"))
        # High/low nibbles
        emit(_make_stack_op(op="opcode", code="OP_DUP"))
        emit(_make_stack_op(op="push", value=number(16)))
        emit(_make_stack_op(op="opcode", code="OP_DIV"))
        emit(_make_stack_op(op="swap"))
        emit(_make_stack_op(op="push", value=number(16)))
        emit(_make_stack_op(op="opcode", code="OP_MOD"))

        if byte_idx < n - 1:
            emit(_make_stack_op(op="opcode", code="OP_TOALTSTACK"))  # loNib -> alt
            emit(_make_stack_op(op="swap"))
            emit(_make_stack_op(op="opcode", code="OP_TOALTSTACK"))  # msgRest -> alt
        else:
            emit(_make_stack_op(op="opcode", code="OP_TOALTSTACK"))  # loNib -> alt

        # First chain call (hiNib)
        _emit_slh_one_chain(emit, n, layer, byte_idx * 2, 6, 5, 4)

        if byte_idx < n - 1:
            emit(_make_stack_op(op="opcode", code="OP_FROMALTSTACK"))  # msgRest
            emit(_make_stack_op(op="opcode", code="OP_FROMALTSTACK"))  # loNib
            emit(_make_stack_op(op="swap"))
            emit(_make_stack_op(op="opcode", code="OP_TOALTSTACK"))   # msgRest -> alt
        else:
            emit(_make_stack_op(op="opcode", code="OP_FROMALTSTACK"))  # loNib

        # Second chain call (loNib)
        _emit_slh_one_chain(emit, n, layer, byte_idx * 2 + 1, 6, 5, 4)

        if byte_idx < n - 1:
            emit(_make_stack_op(op="opcode", code="OP_FROMALTSTACK"))  # msgRest

    # Checksum digits
    emit(_make_stack_op(op="swap"))

    emit(_make_stack_op(op="opcode", code="OP_DUP"))
    emit(_make_stack_op(op="push", value=number(16)))
    emit(_make_stack_op(op="opcode", code="OP_MOD"))
    emit(_make_stack_op(op="opcode", code="OP_TOALTSTACK"))

    emit(_make_stack_op(op="opcode", code="OP_DUP"))
    emit(_make_stack_op(op="push", value=number(16)))
    emit(_make_stack_op(op="opcode", code="OP_DIV"))
    emit(_make_stack_op(op="push", value=number(16)))
    emit(_make_stack_op(op="opcode", code="OP_MOD"))
    emit(_make_stack_op(op="opcode", code="OP_TOALTSTACK"))

    emit(_make_stack_op(op="push", value=number(256)))
    emit(_make_stack_op(op="opcode", code="OP_DIV"))
    emit(_make_stack_op(op="push", value=number(16)))
    emit(_make_stack_op(op="opcode", code="OP_MOD"))
    emit(_make_stack_op(op="opcode", code="OP_TOALTSTACK"))

    for ci in range(len2):
        emit(_make_stack_op(op="opcode", code="OP_TOALTSTACK"))  # endptAcc -> alt
        emit(_make_stack_op(op="push", value=number(0)))
        emit(_make_stack_op(op="opcode", code="OP_FROMALTSTACK"))  # endptAcc
        emit(_make_stack_op(op="opcode", code="OP_FROMALTSTACK"))  # digit

        _emit_slh_one_chain(emit, n, layer, len1 + ci, 6, 5, 4)

        emit(_make_stack_op(op="swap"))
        emit(_make_stack_op(op="drop"))

    emit(_make_stack_op(op="swap"))
    emit(_make_stack_op(op="drop"))

    # Compress -> wotsPk. ta8 at depth 2, kp4 PICKed from depth 1.
    # FIPS 205 Alg. 8 lines 8-11: setTypeAndClear(WOTS_PK) zeroes ADRS bytes
    # 20-31, but the key pair address MUST then be restored. Emitting a zero
    # key-pair address here was half of issue #137.
    _emit_build_adrs(emit, layer, SLH_WOTS_PK, 0, 2, 1, "zero")
    emit(_make_stack_op(op="swap"))
    _emit_slh_t_raw(emit, n, 4)


# ===========================================================================
# 6. Merkle Auth Path Verification
# ===========================================================================

def _emit_slh_merkle(emit: Callable, p: SLHCodegenParams, layer: int) -> None:
    """Merkle auth path verification.

    Input:  psp(5) ta8(4) kp4(3) leafIdx(2) authPath(hp*n)(1) node(n)(0)
    Output: psp(3) ta8(2) kp4(1) root(0)
    """
    n = p.n
    hp = p.hp

    emit(_make_stack_op(op="push", value=number(2)))
    emit(_make_stack_op(op="roll"))
    emit(_make_stack_op(op="opcode", code="OP_TOALTSTACK"))

    for j in range(hp):
        emit(_make_stack_op(op="opcode", code="OP_TOALTSTACK"))  # node -> alt
        emit(_make_stack_op(op="push", value=number(n)))
        emit(_make_stack_op(op="opcode", code="OP_SPLIT"))
        emit(_make_stack_op(op="swap"))
        emit(_make_stack_op(op="opcode", code="OP_FROMALTSTACK"))  # node

        emit(_make_stack_op(op="opcode", code="OP_FROMALTSTACK"))
        emit(_make_stack_op(op="opcode", code="OP_DUP"))
        emit(_make_stack_op(op="opcode", code="OP_TOALTSTACK"))

        if j > 0:
            emit(_make_stack_op(op="push", value=number(1 << j)))
            emit(_make_stack_op(op="opcode", code="OP_DIV"))
        emit(_make_stack_op(op="push", value=number(2)))
        emit(_make_stack_op(op="opcode", code="OP_MOD"))

        def _mk_tweak_hash(e: Callable, j_val: int = j) -> None:
            e(_make_stack_op(op="opcode", code="OP_FROMALTSTACK"))
            e(_make_stack_op(op="opcode", code="OP_DUP"))
            e(_make_stack_op(op="opcode", code="OP_TOALTSTACK"))
            if j_val + 1 > 0:
                e(_make_stack_op(op="push", value=number(1 << (j_val + 1))))
                e(_make_stack_op(op="opcode", code="OP_DIV"))
            e(_make_stack_op(op="push", value=number(4)))
            e(_make_stack_op(op="opcode", code="OP_NUM2BIN"))
            for op_ in _emit_reverse_n(4):
                e(op_)
            _emit_build_adrs(e, layer, SLH_TREE, j_val + 1, 4, -1, "stack")
            e(_make_stack_op(op="swap"))
            _emit_slh_t_raw(e, n, 5)

        mk_tweak_ops = _collect_ops(lambda e: _mk_tweak_hash(e, j))

        then_branch = [_make_stack_op(op="opcode", code="OP_CAT")] + mk_tweak_ops
        else_branch = [_make_stack_op(op="swap"), _make_stack_op(op="opcode", code="OP_CAT")] + mk_tweak_ops

        emit(_make_stack_op(op="if", then=then_branch, else_=else_branch))

    emit(_make_stack_op(op="opcode", code="OP_FROMALTSTACK"))
    emit(_make_stack_op(op="drop"))
    emit(_make_stack_op(op="swap"))
    emit(_make_stack_op(op="drop"))


# ===========================================================================
# 7. FORS Verification
# ===========================================================================

def _emit_slh_fors(emit: Callable, p: SLHCodegenParams) -> None:
    """FORS verification.

    Input:  psp(4) ta8(3) kp4(2) forsSig(1) md(0)
    Output: psp(3) ta8(2) kp4(1) forsPk(0)
    """
    n = p.n
    a = p.a
    k = p.k

    emit(_make_stack_op(op="opcode", code="OP_TOALTSTACK"))  # md -> alt
    emit(_make_stack_op(op="opcode", code="OP_0"))
    emit(_make_stack_op(op="opcode", code="OP_TOALTSTACK"))  # rootAcc -> alt

    for i in range(k):
        # Get md
        emit(_make_stack_op(op="opcode", code="OP_FROMALTSTACK"))  # rootAcc
        emit(_make_stack_op(op="opcode", code="OP_FROMALTSTACK"))  # md
        emit(_make_stack_op(op="opcode", code="OP_DUP"))
        emit(_make_stack_op(op="opcode", code="OP_TOALTSTACK"))    # md back
        emit(_make_stack_op(op="swap"))
        emit(_make_stack_op(op="opcode", code="OP_TOALTSTACK"))    # rootAcc back

        # Extract idx
        bit_start = i * a
        byte_start = bit_start // 8
        bit_offset = bit_start % 8
        # Take the smallest byte window that covers the index, then extract its
        # `a` bits in big-endian order.
        take = (bit_offset + a + 7) // 8

        if byte_start > 0:
            emit(_make_stack_op(op="push", value=number(byte_start)))
            emit(_make_stack_op(op="opcode", code="OP_SPLIT"))
            emit(_make_stack_op(op="nip"))
        emit(_make_stack_op(op="push", value=number(take)))
        emit(_make_stack_op(op="opcode", code="OP_SPLIT"))
        emit(_make_stack_op(op="drop"))
        if take > 1:
            for op_ in _emit_reverse_n(take):
                emit(op_)
        emit(_make_stack_op(op="push", value=number(0)))
        emit(_make_stack_op(op="push", value=number(1)))
        emit(_make_stack_op(op="opcode", code="OP_NUM2BIN"))
        emit(_make_stack_op(op="opcode", code="OP_CAT"))
        emit(_make_stack_op(op="opcode", code="OP_BIN2NUM"))
        total_bits = take * 8
        right_shift = total_bits - bit_offset - a
        if right_shift > 0:
            emit(_make_stack_op(op="push", value=number(1 << right_shift)))
            emit(_make_stack_op(op="opcode", code="OP_DIV"))
        emit(_make_stack_op(op="push", value=number(1 << a)))
        emit(_make_stack_op(op="opcode", code="OP_MOD"))

        # Save idx to alt
        emit(_make_stack_op(op="opcode", code="OP_TOALTSTACK"))

        # Split sk(n) from sigRem
        emit(_make_stack_op(op="push", value=number(n)))
        emit(_make_stack_op(op="opcode", code="OP_SPLIT"))
        emit(_make_stack_op(op="swap"))

        # Leaf hash
        emit(_make_stack_op(op="opcode", code="OP_FROMALTSTACK"))
        emit(_make_stack_op(op="opcode", code="OP_DUP"))
        emit(_make_stack_op(op="opcode", code="OP_TOALTSTACK"))

        if i > 0:
            emit(_make_stack_op(op="push", value=number(i * (1 << a))))
            emit(_make_stack_op(op="opcode", code="OP_ADD"))
        emit(_make_stack_op(op="push", value=number(4)))
        emit(_make_stack_op(op="opcode", code="OP_NUM2BIN"))
        for op_ in _emit_reverse_n(4):
            emit(op_)

        _emit_build_adrs(emit, 0, SLH_FORS_TREE, 0, 4, 3, "stack")
        emit(_make_stack_op(op="swap"))
        _emit_slh_t_raw(emit, n, 5)

        # Auth path walk: a levels
        for j in range(a):
            emit(_make_stack_op(op="opcode", code="OP_TOALTSTACK"))  # node -> alt
            emit(_make_stack_op(op="push", value=number(n)))
            emit(_make_stack_op(op="opcode", code="OP_SPLIT"))
            emit(_make_stack_op(op="swap"))
            emit(_make_stack_op(op="opcode", code="OP_FROMALTSTACK"))  # node

            emit(_make_stack_op(op="opcode", code="OP_FROMALTSTACK"))
            emit(_make_stack_op(op="opcode", code="OP_DUP"))
            emit(_make_stack_op(op="opcode", code="OP_TOALTSTACK"))

            if j > 0:
                emit(_make_stack_op(op="push", value=number(1 << j)))
                emit(_make_stack_op(op="opcode", code="OP_DIV"))
            emit(_make_stack_op(op="push", value=number(2)))
            emit(_make_stack_op(op="opcode", code="OP_MOD"))

            def _mk_fors_auth_hash(e: Callable, i_val: int = i, j_val: int = j) -> None:
                e(_make_stack_op(op="opcode", code="OP_FROMALTSTACK"))
                e(_make_stack_op(op="opcode", code="OP_DUP"))
                e(_make_stack_op(op="opcode", code="OP_TOALTSTACK"))
                if j_val + 1 > 0:
                    e(_make_stack_op(op="push", value=number(1 << (j_val + 1))))
                    e(_make_stack_op(op="opcode", code="OP_DIV"))
                base = i_val * (1 << (a - j_val - 1))
                if base > 0:
                    e(_make_stack_op(op="push", value=number(base)))
                    e(_make_stack_op(op="opcode", code="OP_ADD"))
                e(_make_stack_op(op="push", value=number(4)))
                e(_make_stack_op(op="opcode", code="OP_NUM2BIN"))
                for op_ in _emit_reverse_n(4):
                    e(op_)
                _emit_build_adrs(e, 0, SLH_FORS_TREE, j_val + 1, 4, 3, "stack")
                e(_make_stack_op(op="swap"))
                _emit_slh_t_raw(e, n, 5)

            mk_fors_ops = _collect_ops(lambda e: _mk_fors_auth_hash(e, i, j))

            then_branch = [_make_stack_op(op="opcode", code="OP_CAT")] + mk_fors_ops
            else_branch = [_make_stack_op(op="swap"), _make_stack_op(op="opcode", code="OP_CAT")] + mk_fors_ops

            emit(_make_stack_op(op="if", then=then_branch, else_=else_branch))

        # Drop idx from alt
        emit(_make_stack_op(op="opcode", code="OP_FROMALTSTACK"))
        emit(_make_stack_op(op="drop"))

        # Append treeRoot to rootAcc
        emit(_make_stack_op(op="opcode", code="OP_FROMALTSTACK"))  # rootAcc
        emit(_make_stack_op(op="swap"))
        emit(_make_stack_op(op="opcode", code="OP_CAT"))
        emit(_make_stack_op(op="opcode", code="OP_TOALTSTACK"))  # rootAcc -> alt

    # Drop empty sigRest
    emit(_make_stack_op(op="drop"))

    emit(_make_stack_op(op="opcode", code="OP_FROMALTSTACK"))  # rootAcc
    emit(_make_stack_op(op="opcode", code="OP_FROMALTSTACK"))  # md
    emit(_make_stack_op(op="drop"))

    # Compress
    _emit_build_adrs(emit, 0, SLH_FORS_ROOTS, 0, 2, 1, "zero")
    emit(_make_stack_op(op="swap"))
    _emit_slh_t_raw(emit, n, 4)


# ===========================================================================
# 8. Hmsg -- Message Digest (MGF1-SHA-256)
# ===========================================================================

def _emit_slh_hmsg(emit: Callable, out_len: int) -> None:
    """Emit message digest computation.

    FIPS 205 Section 11.2.1:
        H_msg(R, PK.seed, PK.root, M) =
          MGF1-SHA-256(R || PK.seed || SHA-256(R || PK.seed || PK.root || M), m)
    The ``R || PK.seed`` prefix on the MGF1 seed is mandatory -- it mitigates
    multi-target long-message second-preimage attacks. Omitting it was half of
    issue #137 (the other half was the WOTS_PK key-pair address).

    Input:  R(5) pkSeed(4) R(3) pkSeed(2) pkRoot(1) msg(0)
            (R and pkSeed are supplied twice: once for the inner SHA-256 and
             once for the MGF1 seed prefix)
    Output: digest(out_len bytes)
    """
    # CAT: R || pkSeed || pkRoot || msg, then SHA-256 -> inner(32B)
    emit(_make_stack_op(op="opcode", code="OP_CAT"))
    emit(_make_stack_op(op="opcode", code="OP_CAT"))
    emit(_make_stack_op(op="opcode", code="OP_CAT"))
    emit(_make_stack_op(op="opcode", code="OP_SHA256"))
    # Prepend the mandatory R || PK.seed prefix -> seed(2n+32 B)
    emit(_make_stack_op(op="opcode", code="OP_CAT"))
    emit(_make_stack_op(op="opcode", code="OP_CAT"))

    # SHA2-128s needs 30 bytes, so MGF1 computes only its counter-zero block.
    if not 0 < out_len < 32:
        raise ValueError("SHA2-128s H_msg must fit in one SHA-256 block")
    emit(_make_stack_op(op="push", value=_raw_push(bytes(4))))
    emit(_make_stack_op(op="opcode", code="OP_CAT"))
    emit(_make_stack_op(op="opcode", code="OP_SHA256"))
    emit(_make_stack_op(op="push", value=number(out_len)))
    emit(_make_stack_op(op="opcode", code="OP_SPLIT"))
    emit(_make_stack_op(op="drop"))


# ===========================================================================
# 9. Main Entry -- emit_verify_slh_dsa
# ===========================================================================

def emit_verify_slh_dsa(emit: Callable[[bytes], None]) -> None:
    """Emit the full SLH-DSA verification script.

    Input:  msg(2) sig(1) pubkey(0)  [pubkey on top]
    Output: boolean
    """
    p = _PARAMS

    n = p.n
    d = p.d
    hp = p.hp
    k = p.k
    a = p.a
    ln = p.len_
    fors_sig_len = k * (1 + a) * n
    xmss_sig_len = (ln + hp) * n
    md_len = (k * a + 7) // 8
    tree_idx_len = (p.h - hp + 7) // 8
    leaf_idx_len = (hp + 7) // 8
    digest_len = md_len + tree_idx_len + leaf_idx_len

    t = SLHTracker(["msg", "sig", "pubkey"], emit)

    # ---- 0. BUG-011: enforce exact signature length on-chain ----
    # Each parameter set has a canonical sig length: n + k*(1+a)*n + d*(len+hp)*n.
    # Without this guard the d xmss-layer split loop silently dropped trailing
    # bytes past layer d-1.
    expected_sig_len = n + fors_sig_len + d * xmss_sig_len
    t.to_top("sig")

    def _emit_size_check(e: Callable) -> None:
        e(_make_stack_op(op="opcode", code="OP_SIZE"))
        e(_make_stack_op(op="push", value=number(expected_sig_len)))
        e(_make_stack_op(op="opcode", code="OP_EQUALVERIFY"))

    t.raw_block(["sig"], "sig", _emit_size_check)

    # ---- 1. Parse pubkey -> pkSeed, pkRoot ----
    t.to_top("pubkey")
    t.push_int("", n)
    t.split("pkSeed", "pkRoot")

    # Build pkSeedPad
    t.copy_to_top("pkSeed", "_psp")
    if 64 - n > 0:
        t.push_bytes("", bytes(64 - n))
        t.cat("_pkSeedPad")
    else:
        t.rename("_pkSeedPad")

    # ---- 2. Parse R from sig ----
    t.to_top("sig")
    t.push_int("", n)
    t.split("R", "sigRest")

    # ---- 3. Compute Hmsg(R, pkSeed, pkRoot, msg) ----
    # FIPS 205 Section 11.2.1 needs R and PK.seed TWICE: once inside the
    # inner SHA-256, once as the MGF1 seed prefix. See #137.
    t.copy_to_top("R", "_R2")
    t.copy_to_top("pkSeed", "_pks2")
    t.copy_to_top("R", "_R")
    t.copy_to_top("pkSeed", "_pks")
    t.copy_to_top("pkRoot", "_pkr")
    t.copy_to_top("msg", "_msg")
    t.raw_block(["_R2", "_pks2", "_R", "_pks", "_pkr", "_msg"], "digest",
                lambda e: _emit_slh_hmsg(e, digest_len))

    # ---- 4. Extract md, treeIdx, leafIdx ----
    t.to_top("digest")
    t.push_int("", md_len)
    t.split("md", "_drest")

    t.to_top("_drest")
    t.push_int("", tree_idx_len)
    t.split("_treeBytes", "_leafBytes")

    # Convert _treeBytes -> treeIdx
    t.to_top("_treeBytes")
    def _convert_tree(e: Callable) -> None:
        if tree_idx_len > 1:
            for op_ in _emit_reverse_n(tree_idx_len):
                e(op_)
        e(_make_stack_op(op="push", value=number(0)))
        e(_make_stack_op(op="push", value=number(1)))
        e(_make_stack_op(op="opcode", code="OP_NUM2BIN"))
        e(_make_stack_op(op="opcode", code="OP_CAT"))
        e(_make_stack_op(op="opcode", code="OP_BIN2NUM"))
        modulus = 1 << (p.h - hp)
        e(_make_stack_op(op="push", value=number(modulus)))
        e(_make_stack_op(op="opcode", code="OP_MOD"))
    t.raw_block(["_treeBytes"], "treeIdx", _convert_tree)

    # Convert _leafBytes -> leafIdx
    t.to_top("_leafBytes")
    def _convert_leaf(e: Callable) -> None:
        if leaf_idx_len > 1:
            for op_ in _emit_reverse_n(leaf_idx_len):
                e(op_)
        e(_make_stack_op(op="push", value=number(0)))
        e(_make_stack_op(op="push", value=number(1)))
        e(_make_stack_op(op="opcode", code="OP_NUM2BIN"))
        e(_make_stack_op(op="opcode", code="OP_CAT"))
        e(_make_stack_op(op="opcode", code="OP_BIN2NUM"))
        e(_make_stack_op(op="push", value=number(1 << hp)))
        e(_make_stack_op(op="opcode", code="OP_MOD"))
    t.raw_block(["_leafBytes"], "leafIdx", _convert_leaf)

    # ---- 4b. Compute treeAddr8 and keypair4 ----
    t.copy_to_top("treeIdx", "_ti8")
    def _tree_addr(e: Callable) -> None:
        e(_make_stack_op(op="push", value=number(8)))
        e(_make_stack_op(op="opcode", code="OP_NUM2BIN"))
        for op_ in _emit_reverse_n(8):
            e(op_)
    t.raw_block(["_ti8"], "treeAddr8", _tree_addr)

    t.copy_to_top("leafIdx", "_li4")
    def _keypair_addr(e: Callable) -> None:
        e(_make_stack_op(op="push", value=number(4)))
        e(_make_stack_op(op="opcode", code="OP_NUM2BIN"))
        for op_ in _emit_reverse_n(4):
            e(op_)
    t.raw_block(["_li4"], "keypair4", _keypair_addr)

    # ---- 5. Parse FORS sig ----
    t.to_top("sigRest")
    t.push_int("", fors_sig_len)
    t.split("forsSig", "htSigRest")

    # ---- 6. FORS -> forsPk ----
    t.copy_to_top("_pkSeedPad", "_psp")
    t.copy_to_top("treeAddr8", "_ta")
    t.copy_to_top("keypair4", "_kp")
    t.to_top("forsSig")
    t.to_top("md")
    def _fors(e: Callable) -> None:
        _emit_slh_fors(e, p)
        e(_make_stack_op(op="opcode", code="OP_TOALTSTACK"))
        e(_make_stack_op(op="drop"))
        e(_make_stack_op(op="drop"))
        e(_make_stack_op(op="drop"))
        e(_make_stack_op(op="opcode", code="OP_FROMALTSTACK"))
    t.raw_block(["_psp", "_ta", "_kp", "forsSig", "md"], "forsPk", _fors)

    # ---- 7. Hypertree: d layers ----
    for layer in range(d):
        t.to_top("htSigRest")
        t.push_int("", xmss_sig_len)
        t.split(f"xsig{layer}", "htSigRest")

        t.to_top(f"xsig{layer}")
        t.push_int("", ln * n)
        t.split(f"wsig{layer}", f"auth{layer}")

        cur_msg = "forsPk" if layer == 0 else f"root{layer - 1}"
        t.copy_to_top("_pkSeedPad", "_psp")
        t.copy_to_top("treeAddr8", "_ta")
        t.copy_to_top("keypair4", "_kp")
        wsig_name = f"wsig{layer}"
        t.to_top(wsig_name)
        t.to_top(cur_msg)
        wpk_name = f"wpk{layer}"

        def _wots(e: Callable, layer_val: int = layer) -> None:
            _emit_slh_wots_all(e, p, layer_val)
            e(_make_stack_op(op="opcode", code="OP_TOALTSTACK"))
            e(_make_stack_op(op="drop"))
            e(_make_stack_op(op="drop"))
            e(_make_stack_op(op="drop"))
            e(_make_stack_op(op="opcode", code="OP_FROMALTSTACK"))
        t.raw_block(["_psp", "_ta", "_kp", wsig_name, cur_msg], wpk_name, _wots)

        # Merkle
        t.copy_to_top("_pkSeedPad", "_psp")
        t.copy_to_top("treeAddr8", "_ta")
        t.copy_to_top("keypair4", "_kp")
        t.to_top("leafIdx")
        auth_name = f"auth{layer}"
        t.to_top(auth_name)
        t.to_top(wpk_name)
        root_name = f"root{layer}"

        def _merkle(e: Callable, layer_val: int = layer) -> None:
            _emit_slh_merkle(e, p, layer_val)
            e(_make_stack_op(op="opcode", code="OP_TOALTSTACK"))
            e(_make_stack_op(op="drop"))
            e(_make_stack_op(op="drop"))
            e(_make_stack_op(op="drop"))
            e(_make_stack_op(op="opcode", code="OP_FROMALTSTACK"))
        t.raw_block(["_psp", "_ta", "_kp", "leafIdx", auth_name, wpk_name], root_name, _merkle)

        # Update leafIdx, treeIdx, treeAddr8, keypair4 for next layer
        if layer < d - 1:
            t.to_top("treeIdx")
            t.dup("_tic")
            def _new_leaf(e: Callable) -> None:
                e(_make_stack_op(op="push", value=number(1 << hp)))
                e(_make_stack_op(op="opcode", code="OP_MOD"))
            t.raw_block(["_tic"], "leafIdx", _new_leaf)
            t.swap()
            def _new_tree(e: Callable) -> None:
                e(_make_stack_op(op="push", value=number(1 << hp)))
                e(_make_stack_op(op="opcode", code="OP_DIV"))
            t.raw_block(["treeIdx"], "treeIdx", _new_tree)

            t.to_top("treeAddr8")
            t.drop()
            t.copy_to_top("treeIdx", "_ti8")
            t.raw_block(["_ti8"], "treeAddr8", _tree_addr)

            t.to_top("keypair4")
            t.drop()
            t.copy_to_top("leafIdx", "_li4")
            t.raw_block(["_li4"], "keypair4", _keypair_addr)

    # ---- 8. Compare root to pkRoot ----
    t.to_top(f"root{d - 1}")
    t.to_top("pkRoot")
    t.equal("_result")

    # ---- 9. Cleanup ----
    t.to_top("_result")
    t.to_alt()

    leftover = ["msg", "R", "pkSeed", "htSigRest", "treeIdx", "leafIdx",
                "_pkSeedPad", "treeAddr8", "keypair4"]
    for nm in leftover:
        if t.has(nm):
            t.to_top(nm)
            t.drop()
    while t.depth() > 0:
        t.drop()

    t.from_alt("_result")
