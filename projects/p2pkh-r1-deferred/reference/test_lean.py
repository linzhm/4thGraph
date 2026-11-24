"""Replay output commitments against Calhooon/bsv-script-lean's bsvs CLI."""
import argparse
from dataclasses import replace
import json
from pathlib import Path
import subprocess

from deferred import activation_preimages, recognize
from shared.script import OPS, asm, push
from test_deferred import fixture


def cases():
    _, _, _, parent, unsigned = fixture()
    index = 1
    previous = parent.outputs[index]
    target = unsigned.outputs[index]
    wrapped = replace(target, script=asm('OP_IF') + target.script + asm('OP_ELSE OP_1 OP_ENDIF'))
    changed = replace(unsigned, outputs=(unsigned.outputs[0], wrapped, unsigned.outputs[2]))
    missing = replace(unsigned, outputs=unsigned.outputs[:1])

    for flag, version, height in ((0x43, 1, 2), (0x61, 2, 4)):
        tx = replace(unsigned, version=version)
        good = with_witness(tx, previous.value, index, flag)
        redirected = replace(changed, version=version)
        yield f'{flag:#x} canonical target', parent, good, index, height, True, True
        yield (f'{flag:#x} target wrapped in OP_IF', parent,
               with_witness(redirected, previous.value, index, flag), index, height, False, True)
        yield (f'{flag:#x} altered target, stale witness', parent,
               redirected.with_script(index, good.inputs[index].script), index, height, False, True)
        if version == 1:
            missing_tx = with_witness(replace(missing, version=version), previous.value, index, flag)
            yield 'missing same-index output', parent, missing_tx, index, height, False, False

    drop = asm('OP_1 OP_DROP')
    valid_witness = good.inputs[index].script
    yield 'OP_DROP of temporary value', parent, good.with_script(index, drop + valid_witness), index, height, True, True
    yield ('OP_DROP of required preimage', parent, good.with_script(index, valid_witness + asm('OP_DROP')),
           index, height, False, False)
    conditional = asm('OP_0 OP_IF') + push(target.script) + asm('OP_ENDIF')
    yield ('inactive OP_IF in unlocking script', parent, good.with_script(index, conditional + valid_witness),
           index, height, True, True)

    # Alter only the advertised script hash in a fixture funding output.
    offset = 22
    altered = previous.script[:offset] + bytes([previous.script[offset] ^ 1]) + previous.script[offset + 1:]
    prevout = replace(previous, script=altered)
    if recognize(prevout) is not None:
        raise AssertionError('wallet accepted an inconsistent script hash')
    changed_parent = replace(parent, outputs=(parent.outputs[0], prevout, parent.outputs[2]))
    tx = replace(tx, inputs=tuple(replace(i, txid=changed_parent.txid_wire()) for i in tx.inputs))
    activated = with_witness(tx, previous.value, index, flag)
    yield 'modified public fingerprint', changed_parent, activated, index, height, True, True


def with_witness(tx, value, index, flag):
    preimage, auxiliary = activation_preimages(tx, index, value, flag)
    return tx.with_script(index, (push(auxiliary) if auxiliary else b'') + push(preimage))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('bsvs', type=Path, help='Path to the built bsvs executable')
    binary = parser.parse_args().bsvs.resolve(strict=True)
    for label, parent, tx, index, height, valid, reached_guard in cases():
        prevouts = [dict(txid=parent.txid(), vout=i.vout, script=parent.outputs[i.vout].script.hex(),
                         satoshis=parent.outputs[i.vout].value, height=1) for i in tx.inputs]
        result = json.loads(subprocess.check_output([
            str(binary), 'eval', '--tx', tx.serialize().hex(), '--prevouts', json.dumps(prevouts),
            '--config', 'sv-regtest', '--genesis-height', '1', '--chronicle-height', '3',
            '--spend-height', str(height), '--input', str(index), '--trace',
        ], text=True))
        verdict = 'valid' if valid else 'invalid'
        if result['gate']['verdict'] != 'valid' or result['verdict'] != verdict:
            raise AssertionError(f'{label}: {result["gate"]}, {result["verdict"]} {result["code"]}')
        steps = [step for phase in result['inputs'][0]['trace'] if phase['phase'] == 'scriptPubKey'
                 for step in phase['steps']]
        # Offset 166 is the OP_EQUALVERIFY immediately after the compact lock's TxOut hash.
        checks = [step for step in steps if step['pc'] == 166 and step['op'] == OPS['OP_EQUALVERIFY']]
        if any(step['exec'] for step in checks) != reached_guard:
            raise AssertionError(f'{label}: unexpected trace for the output commitment check')
        print(f'{label}: {verdict}, {result["code"]}, {result["spec"]}')


if __name__ == '__main__':
    main()
