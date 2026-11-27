"""Compile Lamport Forth locks and construct their OTDA reconstruction layouts."""
from functools import cache
from hashlib import sha256
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "src"))
from fourthgraph.bsv.otda_reconstruction import Reconstruction
from fourthgraph.bsv.pushtx import N, R, PUBLIC, ORDINARY_CODE, COMPANION_CODE
from fourthgraph.bsv.pushtx import authorization_checks, binding_der, check_binding
from fourthgraph.bsv.script import asm, push
from fourthgraph.compiler.script_builder import ScriptBuilder, build_word
from fixed_template import v020_forth_pattern
from lamport import KEY_BYTES, SIGNATURE_BYTES, require_bytes


@cache
def _payment_compiler():
    source = Path(__file__).resolve().parents[1] / 'forth' / 'payment-lock.fth'
    return ScriptBuilder.from_file(source, vocabulary={
        'lamport-key-zero': build_word('bytes cell', 'bytes', lambda key, i: key[64*i:64*i+32]),
        'lamport-key-one': build_word('bytes cell', 'bytes', lambda key, i: key[64*i+32:64*i+64]),
        'lamport-bit-index': build_word('cell', 'cell', lambda i: i % 8),
        'lamport-binding-der': build_word('script', 'script', lambda code: code + binding_der()),
        'lamport-binding-key': build_word('', 'bytes', lambda: PUBLIC),
        'lamport-authorize': build_word('script cell', 'script', lambda code, compact_types:
            code + authorization_checks(ORDINARY_CODE, COMPANION_CODE, compact_types=bool(compact_types))),
        'lamport-bind': build_word('script cell', 'script', lambda code, compact:
            code + check_binding(COMPANION_CODE, compact=bool(compact))),
    })


def binding():
    return _payment_compiler().emit('lamport-legacy-binding', b'')


def verifier(key):
    """Input S,H; output empty stack. Retains any earlier altstack entries."""
    require_bytes(key, KEY_BYTES, 'public key')
    return _payment_compiler().emit('lamport-full-verifier', b'', key)


def _committed_verifier(key):
    """Rebuild the ordered public-key pairs and check their SHA-256 commitment."""
    require_bytes(key, KEY_BYTES, 'public key')
    return _payment_compiler().emit('lamport-committed-verifier', b'', sha256(key).digest())


def _v1_script(key, *, transaction=True):
    """Witness: [158-byte BIP143 ALL preimage OR 32-byte digest, 8192-byte signature]."""
    require_bytes(key, KEY_BYTES, 'public key')
    entry = 'lamport-legacy-lock' if transaction else 'lamport-detached-lock'
    return _payment_compiler().emit(entry, b'', key)


def legacy_locking_script(key):
    """The original two-push BIP143 ALL template, preserved byte-for-byte."""
    return _v1_script(key)


def locking_script(key, *, transaction=True):
    """Universal lock witness: preimage, packed signature, companion selector."""
    if not transaction:
        return _v1_script(key, transaction=False)
    return _payment_lock(SIGNATURE_BYTES, verifier(key))


def committed_locking_script(key):
    """Build the shorter payment lock with a commitment to the Lamport key."""
    return _payment_lock(KEY_BYTES, _committed_verifier(key))


def forth_committed_locking_script(key):
    """Build the experimental Forth-compiled committed-key payment lock."""
    return _payment_lock(KEY_BYTES, _forth_committed_verifier(key))


def compact_forth_committed_locking_script(key):
    """Build the Forth committed-key lock with the compact transaction binding."""
    return _bind_commitment(key, compact_forth_pattern())


def v020_forth_committed_locking_script(key):
    """Build the v0.2.0 candidate from its pinned lock layout."""
    return _bind_commitment(key, v020_forth_pattern())


def subset_locking_script(key):
    from subset import KEY_BYTES as SUBSET_KEY_BYTES

    return _bind_commitment(key, subset_forth_pattern(), key_bytes=SUBSET_KEY_BYTES)


def _bind_commitment(key, pattern, *, key_bytes=KEY_BYTES):
    require_bytes(key, key_bytes, 'public key')
    prefix, suffix = pattern.fixed_parts
    return prefix + sha256(key).digest() + suffix


@cache
def compact_forth_pattern():
    """Build the literal lock parts and the program that reconstructs them."""
    return compile_forth_pattern()


def compile_forth_pattern(*, packed=False):
    from forth_verifier import committed_verifier_parts

    return _commitment_pattern(committed_verifier_parts(packed=packed), KEY_BYTES, compact_types=packed)


@cache
def subset_forth_pattern():
    from forth_verifier import subset_verifier_parts
    from subset import KEY_BYTES as SUBSET_KEY_BYTES

    return _commitment_pattern(subset_verifier_parts(), SUBSET_KEY_BYTES, compact_types=True)


def _commitment_pattern(parts, proof_bytes, *, compact_types):
    start, one_byte, finish = parts
    prefix = _payment_guard(proof_bytes, compact_types=compact_types) + start
    commitment_push = finish + b'\x20'  # Direct push of the 32-byte commitment.
    suffix = asm('OP_EQUALVERIFY') + _payment_binding(compact=True)
    # Rebuild the 32 identical fragments without executing their contents.
    program = (push(prefix) + push(one_byte) + asm('OP_DUP OP_CAT') * 5
               + asm('OP_CAT') + push(commitment_push) + asm('OP_CAT') + push(suffix))
    return Reconstruction(program, (prefix + one_byte * 32 + commitment_push, suffix), (32,))


def _forth_committed_verifier(key):
    from forth_verifier import committed_verifier_code

    require_bytes(key, KEY_BYTES, 'public key')
    return committed_verifier_code() + push(sha256(key).digest()) + asm('OP_EQUALVERIFY')


def _payment_guard(proof_bytes, *, compact_types=False):
    return _payment_compiler().emit('lamport-payment-guard', b'', proof_bytes, int(compact_types))


def _payment_binding(*, compact=False):
    return _payment_compiler().emit('lamport-payment-binding', b'', int(compact))


def _payment_lock(proof_bytes, verifier_code):
    return _payment_compiler().emit('lamport-payment-lock', b'', verifier_code, proof_bytes)
