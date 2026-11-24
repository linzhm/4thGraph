"""Reproducible public vectors and clearly scoped local timing measurements."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import platform
from statistics import median
from time import perf_counter_ns
from lamport import generate_keypair, public_key, sign_digest, verify_digest
from fixtures import fixture, mode_fixture
from script import locking_script, binding
from payment import authorization
from engines import chain_valid, development_valid
from shared.script import push
from shared.transaction import SIGHASH_TYPES, hash256

ROOT = Path(__file__).resolve().parents[1]


def instructions(raw):
    i = 0
    result = []
    while i < len(raw):
        op = raw[i]; i += 1; data = None
        if op <= 78:
            n = op
            if op >= 76:
                size = 1 << (op-76)
                n = int.from_bytes(raw[i:i+size],'little'); i += size
            data = raw[i:i+n]; i += n
        result.append((op,data))
    return result


def vector():
    secret,key,lock,parent,tx,pre,sig = fixture()
    unlock = push(pre)+push(sig)
    return {
        'warning': 'PUBLIC TEST KEY: never fund; deterministic repository-specific vector, not an official standard vector',
        'secret_derivation': 'concat SHA256(ASCII("BSV-Script-Lab/Lamport/TEST-ONLY/fixture-v1") || uint16be(i)), i=0..511',
        'bit_order': 'byte order, LSB-first within each byte; key order x[0][0], x[0][1], ...',
        'public_key_hex': key.hex(), 'preimage_hex': pre.hex(), 'digest_hex': hash256(pre).hex(),
        'signature_hex': sig.hex(), 'locking_script_sha256': sha256(lock).hexdigest(),
        'funding_txid': parent.txid(), 'signed_txid': tx.with_script(0,unlock).txid(),
        'sizes': sizes(),
    }


def sizes():
    _,key,lock,_,tx,pre,sig = fixture()
    digest_lock = locking_script(key,transaction=False)
    ops = instructions(lock)
    return {
        'secret_key_bytes':16384, 'public_key_bytes':len(key), 'signature_bytes':len(sig),
        'digest_verifier_bytes_including_key':len(digest_lock),
        'locking_script_bytes_including_key':len(lock),
        'locking_non_key_bytes_including_push_headers':len(lock)-len(key),
        'binding_tail_bytes':len(binding()),
        'unlocking_script_bytes':len(push(pre)+push(sig)),
        'total_lock_and_unlock_bytes':len(lock)+len(push(pre)+push(sig)),
        'signed_one_input_one_OP_TRUE_output_tx_bytes':len(tx.with_script(0,push(pre)+push(sig)).serialize()),
        'locking_instructions_including_pushes_and_both_branches':len(ops),
        'locking_non_push_opcodes_including_both_branches':sum(data is None and not 0x4f<=op<=0x60 for op,data in ops),
        'sha256_opcodes':sum(op==0xa8 and data is None for op,data in ops),
        'hash256_opcodes':sum(op==0xaa and data is None for op,data in ops),
        'checksig_opcodes':sum(op==0xac and data is None for op,data in ops),
    }


def universal_vector():
    rows = []
    for flag in sorted(SIGHASH_TYPES):
        for paired in ((True, False) if flag & 31 == 3 else (True,)):
            _,parents,tx = mode_fixture(flag,paired=paired)
            previous = parents[1].outputs[0]
            auth = authorization(tx,1,previous.value,flag)
            unlock = tx.inputs[1].script
            rows.append({
                'sighash': f'{flag:02x}', 'paired': paired, 'companion': auth.companion,
                'locking_bytes': len(previous.script), 'locking_sha256': sha256(previous.script).hexdigest(),
                'preimage_hex': auth.preimage.hex(), 'digest_hex': auth.digest().hex(),
                'unlocking_bytes': len(unlock), 'unlocking_sha256': sha256(unlock).hexdigest(),
                'funding_txid': parents[1].txid(), 'signed_txid': tx.txid(),
            })
    return {'warning': 'Public test keys. Reproduce via fixtures.mode_fixture; never fund.', 'cases': rows}


def universal_sizes():
    _,parents,tx = mode_fixture(0x41)
    lock = parents[1].outputs[0].script
    ops = instructions(lock)
    unlock_bytes = len(tx.inputs[1].script)
    return {
        'locking_script_bytes_including_key': len(lock),
        'locking_non_key_bytes_including_push_headers': len(lock)-16384,
        'forkid_ordinary_unlocking_script_bytes': unlock_bytes,
        'forkid_ordinary_total_lock_and_unlock_bytes': len(lock)+unlock_bytes,
        'unpaired_otda_single_unlocking_script_bytes': len(mode_fixture(0x63,paired=False)[2].inputs[1].script),
        'locking_instructions_including_pushes_and_both_branches': len(ops),
        'sha256_opcodes': sum(op==0xa8 and data is None for op,data in ops),
        'hash256_opcodes': sum(op==0xaa and data is None for op,data in ops),
        'native_signature_opcodes': sum(op in (0xac,0xad) and data is None for op,data in ops),
    }


def stack_profile():
    # Observe the development interpreter's actual stack for the public vector.
    # This is payload accounting, not the node's allocator/resource accounting.
    import sys
    from shared.evaluate import evaluate
    from engines import native_checker
    _,_,lock,_,tx,pre,sig = fixture()
    peaks = dict(main_items=0, alt_items=0, combined_items=0, combined_payload_bytes=0)
    def trace(frame, event, arg):
        if frame.f_code is evaluate.__code__ and event == 'line':
            main=frame.f_locals.get('stack',[]); alt=frame.f_locals.get('alt',[])
            peaks['main_items']=max(peaks['main_items'],len(main))
            peaks['alt_items']=max(peaks['alt_items'],len(alt))
            peaks['combined_items']=max(peaks['combined_items'],len(main)+len(alt))
            peaks['combined_payload_bytes']=max(peaks['combined_payload_bytes'],sum(map(len,main))+sum(map(len,alt)))
        return trace
    previous = sys.gettrace()
    try:
        sys.settrace(trace)
        assert evaluate(lock,[pre,sig],native_checker(tx,0,10000)) == ([b'\x01'],[])
    finally:
        sys.settrace(previous)
    return peaks


def benchmark(iterations=30):
    secret,key,lock,parent,tx,pre,sig = fixture()
    digest = hash256(pre)
    signed = tx.with_script(0,push(pre)+push(sig))
    _,universal_parents,universal = mode_fixture(0x41)
    _,companion_parents,companion = mode_fixture(0xe3,paired=False)
    assert chain_valid(universal,universal_parents) and chain_valid(companion,companion_parents)
    def measure(fn):
        for _ in range(3): fn()
        values=[]
        for _ in range(iterations):
            start=perf_counter_ns(); fn(); values.append((perf_counter_ns()-start)/1e6)
        return {'median_ms':round(median(values),6),'min_ms':round(min(values),6),'max_ms':round(max(values),6)}
    return {'scope':'Local wall-clock, warmup=3; includes Python adapter overhead; not miner throughput or network fee',
            'platform':platform.platform(),'machine':platform.machine(),'python':platform.python_version(),'iterations':iterations,
            'legacy_sizes':sizes(), 'universal_sizes':universal_sizes(),
            'development_stack_peaks_for_legacy_fixture':stack_profile(),
            'timings':{name:measure(fn) for name,fn in {
                'keygen_including_public_hashes':generate_keypair,
                'sign_digest_stateless':lambda:sign_digest(secret,digest),
                'verify_digest':lambda:verify_digest(key,digest,sig),
                'generate_locking_script':lambda:locking_script(key),
                'development_full_script_with_python_ecdsa':lambda:development_valid(signed,parent,0),
                'chain_gang_legacy_all_transaction':lambda:chain_valid(signed,[parent]),
                'chain_gang_universal_all_transaction':lambda:chain_valid(universal,universal_parents),
                'chain_gang_universal_companion_transaction':lambda:chain_valid(companion,companion_parents),
            }.items()}}


if __name__ == '__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--write-vector',action='store_true')
    parser.add_argument('--benchmark',action='store_true')
    args=parser.parse_args()
    if args.write_vector:
        (ROOT/'template/vector.json').write_text(json.dumps(vector(),indent=2)+'\n')
        (ROOT/'template/universal-vectors.json').write_text(json.dumps(universal_vector(),indent=2)+'\n')
    print(json.dumps(benchmark() if args.benchmark else universal_sizes(),indent=2))
