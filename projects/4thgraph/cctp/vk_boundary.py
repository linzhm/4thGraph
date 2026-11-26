"""Compile and instantiate three CCTP Groth16 layouts over one Forth source."""

from dataclasses import dataclass
from hashlib import sha256
from importlib import import_module
from pathlib import Path

from forth_verifier import Groth16Words
from public_inputs import verification_key_point
from verifier import prepared_lines, unlocking_fields, unlocking_script

from shared.pushtx import PUBLIC, binding_der
from shared.script import asm, number, push
from shared.transaction import Input, Output, Transaction, hash256, preimage_all

frontend = import_module("projects.4thgraph.compiler")
SOURCE = Path(__file__).with_name("vk-boundary.fth")
VERSION = 2
MSM_VALUE, PAIRING_VALUE, STATE_VALUE, TERMINAL_VALUE = 30_000, 70_000, 25_000, 75_000
CLAIM_WIDTHS = (48, 48, 16, 16)
PROOF_WIDTHS = (48,) * 20
CLAIM_BYTES, PROOF_BYTES = sum(CLAIM_WIDTHS), sum(PROOF_WIDTHS)
INDEX0, INDEX1 = bytes(4), b"\x01" + bytes(3)
VERSION_BYTES, FLAG_BYTES = VERSION.to_bytes(4, "little"), b"\x41\0\0\0"
PREVOUTS_HASH, CURRENT_OUTPOINT, OUTPUTS_HASH = 4, 68, 118


class BoundaryWords(Groth16Words):
    def vocabulary(self, primitive):
        words = super().vocabulary(primitive)
        words["use-certified-public-claim"] = primitive(
            ("public-claim",), ("gamma-term",), None,
            lambda _, claim: (self.certified_claim(claim),), "checked Groth16 stage claim",
        )
        return words

    def certified_claim(self, claim):
        _, _, x, y = claim
        lines = prepared_lines(self.key.gamma)
        finite = None
        if any(intercept == (0, 0) for step in lines for _, intercept in step):
            # The MSM stage enforces (0, 0) for infinity and checks the exact
            # affine point otherwise. Both layouts authenticate its encoding.
            finite = self.program.add(self.program.nonzero(x), self.program.nonzero(y))
        return lines, self.g1.negate((x, y)), finite


def compile_entry(key, entry):
    words = BoundaryWords(key)
    vocabulary = words.vocabulary(frontend.Primitive)
    types = frontend.TYPES | {kind for word in vocabulary.values() for kind in (*word.takes, *word.gives)}
    compiler = frontend.SourceCompiler(SOURCE.read_text(), source_path=SOURCE, vocabulary=vocabulary, stack_types=types)
    word = compiler.words[entry]
    if word.takes or word.gives:
        raise ValueError(f"{entry} must have an empty compile-time stack effect")
    intrinsics = set(vocabulary.values())
    if entry != "groth16-pairing":
        # Only the pairing stage's wrapper authenticates this input.
        intrinsics.remove(vocabulary["use-certified-public-claim"])
    stack = []
    for instruction, token in frontend.expanded(word.body):
        if isinstance(instruction, frontend.Literal) and type(instruction.value) is int:
            stack.append(instruction.value)
        elif isinstance(instruction, frontend.Shuffle):
            arity, order, _ = frontend.SHUFFLES[instruction.name]
            operands = stack[-arity:]
            stack[-arity:] = [operands[i] for i in order]
        elif instruction in intrinsics:
            start = len(stack) - len(instruction.takes)
            stack[start:] = instruction.run(None, *stack[start:])
        else:
            raise token.error(f"{token.text!r} is outside the Groth16 Script word set")
    if stack:
        raise AssertionError("Groth16 entry left compile-time values")
    return words.program.compile(reuse_constants=True, stage_constants_on_use=True)[0]


def field(offset, width):
    prefix = number(offset) + asm("OP_SPLIT OP_NIP") if offset else b""
    return prefix + number(width) + asm("OP_SPLIT OP_DROP")


def begin():
    return (asm("OP_SIZE") + number(158) + asm("OP_NUMEQUALVERIFY OP_DUP OP_TOALTSTACK OP_DUP")
            + field(0, 4) + push(VERSION_BYTES) + asm("OP_EQUALVERIFY")
            + field(154, 4) + push(FLAG_BYTES) + asm("OP_EQUALVERIFY"))


def context_field(offset, width):
    return asm("OP_FROMALTSTACK OP_DUP OP_TOALTSTACK") + field(offset, width)


def check_field(offset, width=32):
    return context_field(offset, width) + asm("OP_EQUALVERIFY")


def finish():
    return (asm("OP_FROMALTSTACK OP_HASH256") + binding_der() + push(FLAG_BYTES[:1])
            + asm("OP_CAT") + push(PUBLIC) + asm("OP_CODESEPARATOR OP_CHECKSIG"))


def check_slot(index):
    return push(index) + check_field(CURRENT_OUTPOINT + 32, 4)


def root_id():
    return context_field(CURRENT_OUTPOINT, 32)


def check_siblings():
    return (root_id() + asm("OP_DUP") + push(INDEX0) + asm("OP_CAT OP_SWAP") + push(INDEX1)
            + asm("OP_CAT OP_CAT OP_HASH256") + check_field(PREVOUTS_HASH))


def check_predecessor():
    # raw predecessor is atop the stack. Its first input must be the actual
    # root's MSM slot. The final transaction spends its vout 0 and root vout 1.
    return (asm("OP_DUP") + field(0, 5) + push(VERSION_BYTES + b"\x01") + asm("OP_EQUALVERIFY OP_DUP")
            + field(5, 36) + root_id() + push(INDEX0) + asm("OP_CAT OP_EQUALVERIFY OP_HASH256")
            + push(INDEX0) + asm("OP_CAT") + context_field(CURRENT_OUTPOINT, 36)
            + asm("OP_CAT OP_HASH256") + check_field(PREVOUTS_HASH))


def size(width):
    return asm("OP_SIZE") + number(width) + asm("OP_NUMEQUALVERIFY")


def commitment_script(domain, pairing):
    # Preserve the two packets. The MSM side receives the proof hash, the
    # pairing side computes it from exactly the bytes it will consume.
    return (size(CLAIM_BYTES) + asm("OP_2DUP OP_SWAP") + size(PROOF_BYTES if pairing else 32)
            + (asm("OP_SHA256") if pairing else b"") + asm("OP_SWAP OP_CAT")
            + push(domain) + asm("OP_SWAP OP_CAT") + root_id() + asm("OP_CAT OP_HASH256"))


def terminal(digest):
    return Output(TERMINAL_VALUE, push(digest) + asm("OP_DROP OP_1"))


def check_terminal():
    suffix = asm("OP_DROP OP_1")
    prefix = terminal(bytes(32)).serialize()[:-(32 + len(suffix))]
    return (push(prefix) + asm("OP_SWAP OP_CAT") + push(suffix) + asm("OP_CAT OP_HASH256")
            + check_field(OUTPUTS_HASH))


def state_guard():
    # State script prefix supplies root and digest above the pushed preimage.
    return (asm("OP_ROT") + begin() + check_slot(INDEX0) + asm("OP_DUP") + check_terminal()
            + asm("OP_DROP") + context_field(CURRENT_OUTPOINT, 36) + asm("OP_SWAP") + push(INDEX1)
            + asm("OP_CAT OP_CAT OP_HASH256") + check_field(PREVOUTS_HASH) + finish())


STATE_GUARD = state_guard()


def state_output(root, digest):
    return Output(STATE_VALUE, push(root) + push(digest) + STATE_GUARD)


def check_state_output():
    prefix = state_output(bytes(32), bytes(32)).serialize()[:-(65 + len(STATE_GUARD))]
    return (root_id() + push(prefix) + asm("OP_SWAP OP_CAT")
            + push(b"\x20") + asm("OP_CAT OP_SWAP OP_CAT") + push(STATE_GUARD)
            + asm("OP_CAT OP_HASH256") + check_field(OUTPUTS_HASH))


def unpack(widths):
    decode = push(b"\0") + asm("OP_CAT OP_BIN2NUM")
    return b"".join(number(width) + asm("OP_SPLIT OP_SWAP") + decode + asm("OP_SWAP")
                    for width in widths[:-1]) + decode


def msm_lock(code, domain, serial):
    topology = (context_field(CURRENT_OUTPOINT, 36) + asm("OP_HASH256") + check_field(PREVOUTS_HASH)
                if serial else check_siblings())
    output = check_state_output() if serial else check_terminal()
    return (begin() + check_slot(INDEX0) + topology + commitment_script(domain, False) + output
            + asm("OP_NIP") + unpack(CLAIM_WIDTHS) + code + asm("OP_VERIFY") + finish())


def pairing_lock(code, domain, serial):
    topology = check_predecessor() if serial else check_siblings()
    return (begin() + check_slot(INDEX1) + topology + commitment_script(domain, True) + check_terminal()
            + asm("OP_TOALTSTACK") + unpack(PROOF_WIDTHS) + asm("OP_FROMALTSTACK") + unpack(CLAIM_WIDTHS)
            + code + asm("OP_VERIFY") + finish())


@dataclass(frozen=True)
class Witness:
    claim: bytes
    proof: bytes
    fused: bytes

    @classmethod
    def from_proof(cls, key, signals, proof):
        high, low = signals
        x, y = verification_key_point(key.ic, signals) or (0, 0)
        claim = b"".join(value.to_bytes(width, "little")
                         for value, width in zip((y, x, high, low), CLAIM_WIDTHS, strict=True))
        fields = unlocking_fields(key, signals, proof, projective_g1=True, projective_g2=True)
        packet = b"".join(value.to_bytes(width, "little")
                          for value, width in zip(reversed(fields), PROOF_WIDTHS, strict=True))
        fused = unlocking_script((x, y, *fields)) + number(high) + number(low)
        return cls(claim, packet, fused)

    def commitment(self, domain, root):
        return hash256(domain + sha256(self.proof).digest() + self.claim + root)


def preimage(tx, index, parent):
    return push(preimage_all(tx, index, parent.outputs[tx.inputs[index].vout].value))


@dataclass(frozen=True)
class Layouts:
    fused: bytes
    msm: bytes
    pairing: bytes
    domain: bytes

    @classmethod
    def compile(cls, key):
        fused, msm, pairing = (compile_entry(key, entry) for entry in
                               ("groth16-verify", "groth16-msm", "groth16-pairing"))
        # The two arithmetic scripts commit to the VK and accepted relation.
        domain = sha256(b"4thGraph CCTP Groth16 VK boundary v1\0"
                        + sha256(msm).digest() + sha256(pairing).digest()).digest()
        return cls(fused, msm, pairing, domain)

    def outputs(self, mode):
        if mode == "fused":
            return (Output(MSM_VALUE + PAIRING_VALUE, self.fused),)
        if mode not in ("atomic", "serial"):
            raise ValueError(f"unknown layout: {mode}")
        serial = mode == "serial"
        return (Output(MSM_VALUE, msm_lock(self.msm, self.domain, serial)),
                Output(PAIRING_VALUE, pairing_lock(self.pairing, self.domain, serial)))

    def spend(self, mode, root, witness):
        if root.outputs != self.outputs(mode):
            raise ValueError("deployment outputs disagree with the compiled layout")
        rid = root.txid_wire()
        if mode == "fused":
            return (Transaction((Input(rid, 0, witness.fused),), (Output(TERMINAL_VALUE, asm("OP_1")),)),)
        digest = witness.commitment(self.domain, rid)
        claim = push(witness.claim)
        msm = push(sha256(witness.proof).digest()) + claim
        pairing = push(witness.proof) + claim
        if mode == "atomic":
            tx = Transaction((Input(rid, 0), Input(rid, 1)), (terminal(digest),))
            return (tx.with_script(0, msm + preimage(tx, 0, root))
                    .with_script(1, pairing + preimage(tx, 1, root)),)
        stage = Transaction((Input(rid, 0),), (state_output(rid, digest),))
        stage = stage.with_script(0, msm + preimage(stage, 0, root))
        tx = Transaction((Input(stage.txid_wire(), 0), Input(rid, 1)), (terminal(digest),))
        return stage, (tx.with_script(0, preimage(tx, 0, stage))
                       .with_script(1, pairing + push(stage.serialize()) + preimage(tx, 1, root)))
