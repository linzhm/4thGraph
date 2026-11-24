"""Deterministic fixtures. The included seed derivation is public and test-only."""

from dataclasses import replace
from hashlib import sha256
import json

from payment import authorization, sign_spend
from script import COMPANION_CODE, locking_script
from shared.evaluate import evaluate
from shared.script import number, push
from shared.transaction import (
    ANYONECANPAY,
    CHRONICLE,
    SIGHASH_ALL,
    SIGHASH_NONE,
    SIGHASH_SINGLE,
    SIGHASH_TYPES,
    Input,
    Output,
    Transaction,
    hash256,
    preimage_forkid,
)
from wots import public_key, sign_digest


def fixture_seeds(label=b"forkid-all"):
    prefix = b"BSV-Script-Lab/WOTS+/TEST-ONLY/" + label
    return sha256(prefix + b"/secret").digest(), sha256(prefix + b"/public").digest()


def funding_transaction(key):
    return Transaction((Input(b"\x62" * 32, 0),), (Output(10_000, locking_script(key)),))


def mode_fixture(flag, *, paired=True, version=2):
    seeds = fixture_seeds(bytes([flag, paired]))
    key = public_key(*seeds)
    parent = funding_transaction(key)
    other = Transaction((Input(b"\x44" * 32, 0),), (Output(1_000, b"\x51"),))
    outputs = (Output(500, b"\x51"), Output(10_400, b"\x51"))
    if not paired:
        outputs = (Output(10_900, b"\x51"),)
    tx = Transaction((Input(other.txid_wire(), 0), Input(parent.txid_wire(), 0)), outputs, version=version)
    signed = sign_spend(tx, 1, parent.serialize(), key, lambda digest: sign_digest(*seeds, digest), sighash=flag)
    return seeds, (other, parent), signed


def mode_cases():
    """Yield (name, spend, funding transactions, input index, expected result)."""
    for flag in sorted(SIGHASH_TYPES):
        _, parents, signed = mode_fixture(flag)
        other, parent = parents
        base = flag & 31
        prefix = f"{flag:02x}_"
        yield prefix + "paired", signed, parents, 1, True

        paired_output = replace(signed, outputs=(signed.outputs[0], Output(10_399, b"\x51")))
        yield prefix + "paired_output", paired_output, parents, 1, base == SIGHASH_NONE
        other_output = replace(signed, outputs=(Output(499, b"\x51"), signed.outputs[1]))
        yield prefix + "other_output", other_output, parents, 1, base != SIGHASH_ALL
        other_sequence = replace(signed, inputs=(replace(signed.inputs[0], sequence=1), signed.inputs[1]))
        yield prefix + "other_sequence", other_sequence, parents, 1, bool(flag & ANYONECANPAY) or base != SIGHASH_ALL
        new_parent = replace(other, locktime=1)
        other_outpoint = replace(signed, inputs=(replace(signed.inputs[0], txid=new_parent.txid_wire()), signed.inputs[1]))
        yield prefix + "other_outpoint", other_outpoint, (new_parent, parent), 1, bool(flag & ANYONECANPAY)
        own_sequence = replace(signed, inputs=(signed.inputs[0], replace(signed.inputs[1], sequence=1)))
        yield prefix + "own_sequence", own_sequence, parents, 1, False
        yield prefix + "locktime", replace(signed, locktime=1), parents, 1, False

        if base != SIGHASH_SINGLE:
            continue
        moved_pair = replace(signed, inputs=tuple(reversed(signed.inputs)), outputs=tuple(reversed(signed.outputs)))
        yield prefix + "moved_pair", moved_pair, tuple(reversed(parents)), 0, flag == (0x40 | ANYONECANPAY | SIGHASH_SINGLE)

        seeds, parents, signed = mode_fixture(flag, paired=False)
        yield prefix + "unpaired", signed, parents, 1, True
        other_output = replace(signed, outputs=(Output(10_899, b"\x51"),))
        yield prefix + "unpaired_other_output", other_output, parents, 1, True
        own_sequence = replace(signed, inputs=(signed.inputs[0], replace(signed.inputs[1], sequence=1)))
        yield prefix + "unpaired_own_sequence", own_sequence, parents, 1, False
        now_paired = replace(signed, outputs=(Output(500, b"\x51"), Output(10_400, b"\x51")))
        yield prefix + "added_paired_output", now_paired, parents, 1, False

        if flag & CHRONICLE:
            # A legitimate companion-bound signature cannot enable the fallback
            # for a transaction that already has a same-index output.
            preimage = preimage_forkid(now_paired, 1, 10_000, COMPANION_CODE, flag & ~CHRONICLE)
            forced_companion = push(preimage) + push(sign_digest(*seeds, hash256(preimage))) + number(1)
            yield prefix + "companion_paired_preimage", now_paired.with_script(1, forced_companion), parents, 1, False
            unlock = signed.inputs[1].script
            yield prefix + "companion_wrong_selector", signed.with_script(1, unlock[:-1] + number(0)), parents, 1, False


def malformed_cases():
    seeds, parents, signed = mode_fixture(0x41)
    preimage, signature, _ = evaluate(signed.inputs[1].script)[0]

    def witness(preimage, signature, selector=0):
        return signed.with_script(1, push(preimage) + push(signature) + number(selector))

    yield "short_signature", witness(preimage, signature[:-1]), parents, 1, False
    yield "long_signature", witness(preimage, signature + b"\x00"), parents, 1, False
    yield "changed_checksum_chain", witness(preimage, signature[:-1] + bytes([signature[-1] ^ 1])), parents, 1, False
    yield "other_key", witness(preimage, sign_digest(*fixture_seeds(b"other"), hash256(preimage))), parents, 1, False
    yield "other_digest", witness(preimage, sign_digest(*seeds, sha256(b"other digest").digest())), parents, 1, False
    yield "extra_argument", signed.with_script(1, push(b"extra") + signed.inputs[1].script), parents, 1, False
    yield "missing_argument", signed.with_script(1, push(signature) + number(0)), parents, 1, False
    yield "invalid_selector", witness(preimage, signature, 2), parents, 1, False
    yield "noncanonical_selector", signed.with_script(1, signed.inputs[1].script[:-1] + push(b"\x00")), parents, 1, False

    preimages = {
        "short_preimage": preimage[:-1],
        "long_preimage": preimage + b"\x00",
        "unsupported_flag": preimage[:-4] + b"\x01\x00\x00\x00",
        "nonzero_high_flag": preimage[:-1] + b"\x01",
        "bad_script_code": preimage[:105] + bytes([preimage[105] ^ 1]) + preimage[106:],
        "wrong_previous_amount": authorization(signed, 1, 10_001).preimage,
    }
    for name, candidate in preimages.items():
        yield name, witness(candidate, sign_digest(*seeds, hash256(candidate))), parents, 1, False


def vector_document():
    def vector(flag, paired):
        seeds, parents, spend = mode_fixture(flag, paired=paired)
        lock = parents[1].outputs[0].script
        unlock = spend.inputs[1].script
        preimage, signature, selector = evaluate(unlock)[0]
        return {
            "sighash": f"0x{flag:02x}",
            "paired_output": paired,
            "companion": bool(selector),
            "secret_seed_test_only": seeds[0].hex(),
            "public_key": public_key(*seeds).hex(),
            "previous_amount": 10_000,
            "input_index": 1,
            "preimage": preimage.hex(),
            "digest": hash256(preimage).hex(),
            "signature_sha256": sha256(signature).hexdigest(),
            "locking_bytes": len(lock),
            "locking_sha256": sha256(lock).hexdigest(),
            "unlocking_bytes": len(unlock),
            "unlocking_sha256": sha256(unlock).hexdigest(),
            "funding_txid": parents[1].txid(),
            "spend_txid": spend.txid(),
        }

    paired = [vector(flag, True) for flag in sorted(SIGHASH_TYPES)]
    unpaired = [vector(flag, False) for flag in sorted(SIGHASH_TYPES) if flag & 31 == SIGHASH_SINGLE]
    return {"format": "wots-plus-payment-v1", "vectors": paired + unpaired}


if __name__ == "__main__":
    print(json.dumps(vector_document(), indent=2))
