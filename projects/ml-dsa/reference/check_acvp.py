"""Replay NIST ACVP external Pure ML-DSA-44 sigVer vectors in Python and Script."""

import argparse
import json
from pathlib import Path

from fips204 import verify
from script import verify_message_script
from shared.chain_gang import validate_at_heights
from shared.script import asm, push
from shared.transaction import Input, Output, Transaction


def script_verdict(key, message, context, signature):
    lock = asm('OP_DEPTH OP_2 OP_NUMEQUALVERIFY') + verify_message_script(key, len(message), context=context)
    funding = Transaction((Input(b'\x31' * 32, 0),), (Output(1000, lock),))
    spend = Transaction((Input(funding.txid_wire(), 0, push(message) + push(signature)),), (Output(900, b'\x51'),))
    try:
        validate_at_heights(spend, (funding,), spend_height=4, activation_height=3, utxo_heights=(3,))
    except ValueError as error:
        if 'Error evaluating the script' not in str(error):
            raise
        return False
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('prompt', type=Path)
    parser.add_argument('expected', type=Path)
    args = parser.parse_args()
    prompts = json.loads(args.prompt.read_text())
    expected = json.loads(args.expected.read_text())
    for data in (prompts, expected):
        if (data['algorithm'], data['mode'], data['revision']) != ('ML-DSA', 'sigVer', 'FIPS204'):
            raise ValueError('expected an ACVP FIPS 204 sigVer file')
    if prompts['vsId'] != expected['vsId']:
        raise ValueError('ACVP prompt and expected results use different vector sets')

    expected_by_group = {group['tgId']: group['tests'] for group in expected['testGroups']}
    count = 0
    mismatches = []
    for group in prompts['testGroups']:
        if (group['parameterSet'], group['signatureInterface'], group.get('preHash')) != ('ML-DSA-44', 'external', 'pure'):
            continue
        verdicts = {case['tcId']: case['testPassed'] for case in expected_by_group[group['tgId']]}
        if set(verdicts) != {case['tcId'] for case in group['tests']}:
            raise ValueError('ACVP prompt and expected case IDs differ')
        for case in group['tests']:
            key, message, context, signature = (bytes.fromhex(case[field])
                                                for field in ('pk', 'message', 'context', 'signature'))
            reference = verify(key, message, signature, context=context)
            actual = script_verdict(key, message, context, signature)
            if (reference, actual) != (verdicts[case['tcId']],) * 2:
                mismatches.append(case['tcId'])
            count += 1
    if not count:
        raise ValueError('no external Pure ML-DSA-44 vectors')
    print(f'ML-DSA-44: {count - len(mismatches)}/{count} ACVP results matched in Python and Script')
    if mismatches:
        print(f'Mismatched case IDs: {mismatches}')
    return bool(mismatches)


if __name__ == '__main__':
    raise SystemExit(main())
