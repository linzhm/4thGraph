"""Public, deterministic TEST ONLY fixtures; never fund these keys."""
from hashlib import sha256
from dataclasses import replace
from lamport import public_key, sign_digest
from script import legacy_locking_script
from shared.transaction import Transaction, Input, Output, preimage_all, hash256
from shared.script import push


INVALID_PREVOUT_CASES = frozenset({'outpoint_index', 'outpoint_hash', 'other_outpoint'})


def test_secret(label=b'fixture-v1'):
    return b''.join(sha256(b'BSV-Script-Lab/Lamport/TEST-ONLY/'+label+i.to_bytes(2,'big')).digest() for i in range(512))


def fixture():
    secret = test_secret()
    key = public_key(secret)
    lock = legacy_locking_script(key)
    parent = Transaction((Input(b'\x22'*32, 0),), (Output(10000, lock),))
    tx = Transaction((Input(parent.txid_wire(), 0),), (Output(9900, b'\x51'),))
    pre = preimage_all(tx, 0, 10000)
    sig = sign_digest(secret, hash256(pre))
    return secret, key, lock, parent, tx, pre, sig


def cases():
    """Each case is (label, transaction, parent-per-input, input-index, expected)."""
    secret, key, lock, parent, tx, pre, sig = fixture()
    unlock = push(pre)+push(sig)
    signed = tx.with_script(0, unlock)
    yield 'valid', signed, [parent], 0, True
    changes = {
        'output_amount': replace(tx, outputs=(Output(9899,b'\x51'),)),
        'output_script': replace(tx, outputs=(Output(9900,b'\x00'),)),
        'locktime': replace(tx, locktime=1),
        'version': replace(tx, version=1),
        'sequence': replace(tx, inputs=(replace(tx.inputs[0],sequence=1),)),
        'outpoint_index': replace(tx, inputs=(replace(tx.inputs[0],vout=1),)),
        'outpoint_hash': replace(tx, inputs=(replace(tx.inputs[0],txid=b'\x33'*32),)),
    }
    for label, changed in changes.items():
        # Use real previous script/value even when the outpoint is deliberately wrong.
        yield label, changed.with_script(0,unlock), [parent], 0, False
        fake = preimage_all(changed,0,10000)
        yield 'supplied_'+label, tx.with_script(0,push(fake)+push(sign_digest(secret,hash256(fake)))), [parent], 0, False
    for label, bad in [('short_pre',pre[:-1]),('long_pre',pre+b'\0'),('wrong_flag',pre[:-4]+b'\x42\0\0\0'),
                       ('wrong_script_code',pre[:105]+b'\xad'+pre[106:]),
                       ('wrong_amount',preimage_all(tx,0,10001))]:
        yield label, tx.with_script(0,push(bad)+push(sign_digest(secret,hash256(bad)))), [parent], 0, False
    for label, bad in [('short_sig',sig[:-1]),('long_sig',sig+b'\0'),('wrong_sig',bytes([sig[0]^1])+sig[1:]),
                       ('swapped_blocks',sig[32:64]+sig[:32]+sig[64:]),
                       ('wrong_key',sign_digest(test_secret(b'other'),hash256(pre))),
                       ('wrong_digest',sign_digest(secret,sha256(b'wrong').digest()))]:
        yield label, tx.with_script(0,push(pre)+push(bad)), [parent], 0, False
    yield 'extra_item', tx.with_script(0,push(b'extra')+unlock), [parent], 0, False
    yield 'missing_item', tx.with_script(0,push(sig)), [parent], 0, False
    other = Transaction((Input(b'\x44'*32,0),),(Output(1000,b'\x51'),))
    multi = Transaction((Input(other.txid_wire(),0),Input(parent.txid_wire(),0)),(Output(500,b'\x51'),Output(10400,b'\x51')))
    p = preimage_all(multi,1,10000)
    multi = multi.with_script(1,push(p)+push(sign_digest(secret,hash256(p))))
    yield 'multi_input',multi,[other,parent],1,True
    yield 'output_order',replace(multi,outputs=tuple(reversed(multi.outputs))),[other,parent],1,False
    yield 'other_sequence',replace(multi,inputs=(replace(multi.inputs[0],sequence=1),multi.inputs[1])),[other,parent],1,False
    yield 'other_outpoint',replace(multi,inputs=(replace(multi.inputs[0],txid=b'\x77'*32),multi.inputs[1])),[other,parent],1,False


def mode_fixture(flag, *, paired=True, version=2, lock_factory=None):
    from script import locking_script
    from payment import sign_spend

    secret = test_secret(b'universal/' + bytes([flag, paired]))
    key = public_key(secret)
    lock_factory = lock_factory or locking_script
    parent = Transaction((Input(b'\x62'*32, 0),), (Output(10000, lock_factory(key)),))
    other = Transaction((Input(b'\x44'*32, 0),), (Output(1000, b'\x51'),))
    outputs = (Output(500, b'\x51'), Output(10400, b'\x51')) if paired else (Output(10900, b'\x51'),)
    tx = Transaction((Input(other.txid_wire(), 0), Input(parent.txid_wire(), 0)), outputs, version=version)
    signed = sign_spend(tx, 1, parent.serialize(), key, lambda digest: sign_digest(secret, digest), sighash=flag)
    return secret, (other, parent), signed


def mode_cases():
    from payment import authorization
    from script import COMPANION_CODE
    from shared.script import number
    from shared.transaction import ANYONECANPAY, CHRONICLE, SIGHASH_TYPES, preimage_forkid

    for flag in sorted(SIGHASH_TYPES):
        secret, parents, signed = mode_fixture(flag)
        other,parent = parents
        base = flag & 31
        prefix = f'{flag:02x}_'
        yield prefix+'paired', signed, parents, 1, True
        changed = replace(signed, outputs=(signed.outputs[0], Output(10399, b'\x51')))
        yield prefix+'paired_output', changed, parents, 1, base == 2
        changed = replace(signed, outputs=(Output(499, b'\x51'), signed.outputs[1]))
        yield prefix+'other_output', changed, parents, 1, base != 1
        changed = replace(signed, inputs=(replace(signed.inputs[0], sequence=1), signed.inputs[1]))
        yield prefix+'other_sequence', changed, parents, 1, bool(flag & ANYONECANPAY) or base != 1
        new_other = replace(other, locktime=1)
        changed = replace(signed, inputs=(replace(signed.inputs[0], txid=new_other.txid_wire()), signed.inputs[1]))
        yield prefix+'other_outpoint', changed, (new_other,parent), 1, bool(flag & ANYONECANPAY)
        changed = replace(signed, inputs=(signed.inputs[0], replace(signed.inputs[1], sequence=1)))
        yield prefix+'own_sequence', changed, parents, 1, False
        yield prefix+'locktime', replace(signed, locktime=1), parents, 1, False
        if base != 3:
            continue
        moved = replace(signed, inputs=tuple(reversed(signed.inputs)), outputs=tuple(reversed(signed.outputs)))
        yield prefix+'moved_pair', moved, tuple(reversed(parents)), 0, flag == 0xc3
        secret, parents, signed = mode_fixture(flag, paired=False)
        yield prefix+'unpaired', signed, parents, 1, True
        changed = replace(signed, outputs=(Output(10899, b'\x51'),))
        yield prefix+'unpaired_other_output', changed, parents, 1, True
        changed = replace(signed, inputs=(signed.inputs[0], replace(signed.inputs[1], sequence=1)))
        yield prefix+'unpaired_own_sequence', changed, parents, 1, False
        changed = replace(signed, outputs=(Output(500, b'\x51'),Output(10400,b'\x51')))
        yield prefix+'added_paired_output', changed, parents, 1, False
        if not flag & CHRONICLE:
            continue
        # A genuine BIP143 binding for a paired transaction must still fail
        # the constant-digest leg. Also test a false selector with a valid OTS.
        pre = preimage_forkid(changed, 1, 10000, COMPANION_CODE, flag & ~CHRONICLE)
        forged = changed.with_script(1, push(pre)+push(sign_digest(secret,hash256(pre)))+number(1))
        yield prefix+'companion_paired_preimage', forged, parents, 1, False
        auth = authorization(signed, 1, 10000, flag)
        wrong_mode = signed.with_script(1, push(auth.preimage)+push(sign_digest(secret,auth.digest()))+number(0))
        yield prefix+'companion_wrong_selector', wrong_mode, parents, 1, False
    secret,parents,signed = mode_fixture(0x41)
    unlock = signed.inputs[1].script
    yield 'noncanonical_selector',signed.with_script(1,unlock[:-1]+push(b'\0')),parents,1,False
    pre = authorization(signed,1,10000).preimage
    for label, candidate, selector in (
        ('unsupported_type', pre[:-4]+b'\x01\0\0\0', 0),
        ('nonzero_high_type', pre[:-1]+b'\x01', 0),
        ('short_preimage', pre[:-1], 0),
        ('bad_script_code', pre[:105]+b'\x51'+pre[106:], 0),
        ('bad_selector', pre, 2),
        ('wrong_algorithm', pre[:-4]+b'\x61\0\0\0', 0),
    ):
        unlock = push(candidate)+push(sign_digest(secret,hash256(candidate)))+number(selector)
        yield label,signed.with_script(1,unlock),parents,1,False
