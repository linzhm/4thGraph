"""Fund latest-template SM2 and native P2PKH payments on isolated regtest."""
import argparse
from dataclasses import replace
import os
from pathlib import Path

from assemble import TEMPLATE_PROFILES, TEMPLATE_VERSIONS
from benchmark_adapter import sm2_coin
from fourthgraph.benchmark.admission import submit_and_mine
from fourthgraph.benchmark.cases import native_coin, payment
from fourthgraph.benchmark.run import dump_json
from fourthgraph.benchmark.validation import Node, chain_metadata, chain_verdict
from fourthgraph.bsv.differential import require_chain_gang_pin
from fourthgraph.bsv.transaction import Input, Transaction
from p2pkh_sm2 import authorization

PRINCIPAL = 10_000_000
FEE = 150_000
CHANGE = 50_000


def mine_wallet_funding(node, coin):
    unsigned = Transaction((), (coin.output,))
    funded = node.call('fundrawtransaction', [unsigned.serialize().hex(),
                                              {'changePosition': 1, 'feeRate': 0.00002}])
    signed = node.call('signrawtransaction', [funded['hex']])
    if not signed['complete']:
        raise AssertionError('Wallet funding did not sign completely')
    tx = Transaction.parse(bytes.fromhex(signed['hex']))
    if tx.outputs[0] != coin.output or not submit_and_mine(node, tx)['mined']:
        raise AssertionError('Wallet funding did not create the intended confirmed UTXO')
    return tx


def verify(node, tx, parents, flags, fee):
    if Transaction.parse(tx.serialize()) != tx:
        raise AssertionError('Transaction did not round-trip')
    actual_fee = sum(parent.outputs[txin.vout].value for parent, txin in zip(parents, tx.inputs, strict=True))
    actual_fee -= sum(output.value for output in tx.outputs)
    if actual_fee != fee or not chain_verdict(tx, parents):
        raise AssertionError(f'Unexpected fee or Script verdict for {tx.txid()}')
    if node is not None and node.verdicts(tx, parents) != [True] * len(parents):
        raise AssertionError(f'BSV Node did not verify {tx.txid()}')
    return {'fee_sats': fee, 'sighashes': [f'{flag:02x}' for flag in flags],
            'unlock_bytes': [len(txin.script) for txin in tx.inputs],
            'verifyscript_checked': node is not None, 'chain_gang': True}


def deposit(node, script_node, label, incoming_flag, outputs):
    payer = native_coin(label + '/payer', sum(coin.output.value for coin in outputs) + FEE)
    funding = mine_wallet_funding(node, payer)
    leg = payment(((funding, 0, payer, incoming_flag),), outputs, None, fee=FEE)
    evidence = verify(script_node, leg.tx, leg.parents, leg.flags, FEE)
    result = submit_and_mine(node, leg.tx)
    if not result['mined']:
        raise AssertionError(f'P2PKH deposit did not mine: {result}')
    return leg.tx, {**evidence, **result}


def zero_fee_package(node, script_node, label, version, mode):
    customer = sm2_coin(label + '/customer', PRINCIPAL, version=version)
    sponsor = native_coin(label + '/sponsor', FEE)
    parent, incoming = deposit(node, script_node, label, mode, (customer,))
    sponsor_parent = mine_wallet_funding(node, sponsor)
    recipient = sm2_coin(label + '/recipient', PRINCIPAL, version=version)
    acp = mode | 0x80
    zero = payment(((parent, 0, customer, acp),), (recipient,), None, fee=0).tx
    zero_evidence = verify(script_node, zero, (parent,), (acp,), 0)

    native_input = Input(sponsor_parent.txid_wire(), 0)
    unsigned = replace(zero, inputs=(*zero.inputs, native_input))
    signed = sponsor.unlock(unsigned, 1, sponsor_parent, 0x41, None)
    before = authorization(zero, 0, PRINCIPAL, acp).preimage
    after = authorization(signed, 0, PRINCIPAL, acp).preimage
    if before != after or signed.inputs[0] != zero.inputs[0] or signed.outputs != zero.outputs:
        raise AssertionError('Late sponsorship changed the signed intent')
    parents = (parent, sponsor_parent)
    sponsored = verify(script_node, signed, parents, (acp, 0x41), FEE)

    ordinary = customer.unlock(replace(zero, inputs=(replace(zero.inputs[0], script=b''),)), 0, parent, mode, None)
    stale = replace(signed, inputs=(ordinary.inputs[0], signed.inputs[1]))
    if chain_verdict(stale, parents) or (
            script_node is not None and script_node.verdicts(stale, parents) != [False, True]):
        raise AssertionError('The appended input was accepted under ordinary ALL')
    unauthorized_change = replace(unsigned, outputs=(*unsigned.outputs, replace(sponsor.output, value=1_000)))
    unauthorized_change = sponsor.unlock(unauthorized_change, 1, sponsor_parent, 0x41, None)
    if chain_verdict(unauthorized_change, parents) or (
            script_node is not None and script_node.verdicts(unauthorized_change, parents) != [False, True]):
        raise AssertionError('ANYONECANPAY ALL allowed adding change after signing')

    return incoming, zero, zero_evidence, signed, {
        **sponsored, 'sponsor_funding_txid': sponsor_parent.txid(),
        'sm2_witness_preserved': True, 'ordinary_all_rejects_appended_input': True,
        'anyonecanpay_all_rejects_appended_change': True,
    }


def planned_sponsor(node, script_node, label, version, mode, *, exit_to_native):
    customer = sm2_coin(label + '/customer', PRINCIPAL, version=version)
    sponsor = native_coin(label + '/sponsor', FEE + CHANGE)
    parent, incoming = deposit(node, script_node, label, mode, (customer, sponsor))
    recipient = (native_coin(label + '/recipient', PRINCIPAL) if exit_to_native else
                 sm2_coin(label + '/recipient', PRINCIPAL, version=version))
    change = replace(sponsor, output=replace(sponsor.output, value=CHANGE))
    leg = payment(((parent, 0, customer, mode), (parent, 1, sponsor, 0x41)), (recipient, change), None, fee=FEE)
    result = verify(script_node, leg.tx, leg.parents, leg.flags, FEE)
    return incoming, {**result, **submit_and_mine(node, leg.tx),
                      'recipient_sats': PRINCIPAL, 'sponsor_change_sats': CHANGE}


def cpfp(node, script_node, label, version, mode):
    customer = sm2_coin(label + '/customer', PRINCIPAL, version=version)
    sponsor = native_coin(label + '/sponsor', FEE)
    parent, incoming = deposit(node, script_node, label, mode, (customer, sponsor))
    anchor = native_coin(label + '/anchor', CHANGE)
    recipient = sm2_coin(label + '/recipient', PRINCIPAL - CHANGE, version=version)
    zero = payment(((parent, 0, customer, mode),), (recipient, anchor), None, fee=0)
    zero_evidence = verify(script_node, zero.tx, zero.parents, zero.flags, 0)
    zero_admission = submit_and_mine(node, zero.tx)
    child = payment(((zero.tx, 1, anchor, 0x41), (parent, 1, sponsor, 0x41)), (anchor,), None, fee=FEE)
    child_evidence = verify(script_node, child.tx, child.parents, child.flags, FEE)
    child_admission = submit_and_mine(node, child.tx)
    parent_mined_with_child = (child_admission['mined'] and
                               zero.tx.txid() in node.call('getblock', [child_admission['block']])['tx'])
    return {
        'native_to_sm2_for_cpfp': incoming,
        'zero_fee_parent_with_native_output': {**zero_evidence, **zero_admission},
        'p2pkh_cpfp_child': {**child_evidence, **child_admission,
                            'parent_mined_with_child': parent_mined_with_child},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--template', type=int, choices=TEMPLATE_VERSIONS, default=TEMPLATE_VERSIONS[-1])
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    profile = os.environ.get('SCRIPT_LAB_REGTEST_PROFILE')
    if profile not in ('default', 'raised'):
        parser.error('run through tools/verify_node.sh --profile default or raised')
    node = Node(os.environ['REGTEST_URL'], os.environ['REGTEST_COOKIE'])
    if node.call('getblockcount', []) != 0 or node.call('getconnectioncount', []) != 0:
        raise ValueError('fee sponsorship requires a fresh peerless regtest node')
    require_chain_gang_pin(Path(__file__).with_name('requirements.txt'))
    node.call('generate', [101])
    # Default admission includes the node's own execution limits. Use the
    # raised profile separately for explicit positive and negative Script checks.
    script_node = node if profile == 'raised' else None

    cases = {}
    for name, flag in (('bip143', 0x41), ('otda', 0x61)):
        incoming, _, _, signed, sponsored = zero_fee_package(
            node, script_node, f'{name}/late', args.template, flag)
        # Probe zero-fee submission independently so a mempool entry cannot
        # compete for the UTXO used in the before-submission sponsorship case.
        _, zero, zero_evidence, replacement, replacement_evidence = zero_fee_package(
            node, script_node, f'{name}/probe', args.template, flag)
        zero_admission = submit_and_mine(node, zero)
        cases[name] = {
            'native_to_sm2_for_late_sponsor': incoming,
            'zero_fee_sm2_turnover': {**zero_evidence, **zero_admission},
            'sponsorship_after_zero_fee_submission': {**replacement_evidence, **submit_and_mine(node, replacement)},
            'late_p2pkh_sponsorship': {**sponsored, **submit_and_mine(node, signed)},
            **cpfp(node, script_node, f'{name}/cpfp', args.template, flag),
        }
        for output_type, exit_to_native in (('sm2', False), ('p2pkh', True)):
            funding, planned = planned_sponsor(node, script_node, f'{name}/planned/{output_type}',
                                               args.template, flag, exit_to_native=exit_to_native)
            cases[name][f'native_to_sm2_for_planned_{output_type}'] = funding
            cases[name][f'{output_type}_payment_with_planned_p2pkh_change'] = planned
    dump_json(args.report, {'template': TEMPLATE_PROFILES[args.template], 'policy_profile': profile,
                            'bsv_node_version': '1.2.3', 'chain_gang_commit': chain_metadata()['commit'],
                            'min_mining_fee_sat_per_byte': 0.5, 'cases': cases})
    for mode, outcomes in cases.items():
        for name in ('late_p2pkh_sponsorship', 'sm2_payment_with_planned_p2pkh_change',
                     'p2pkh_payment_with_planned_p2pkh_change'):
            if not outcomes[name]['mined']:
                raise AssertionError(f'{profile}/{mode}/{name} did not mine: {outcomes[name]}')
        for name in ('zero_fee_sm2_turnover', 'zero_fee_parent_with_native_output'):
            if not outcomes[name].get('still_in_mempool') or outcomes[name]['mined']:
                raise AssertionError(f'{profile}/{mode}/{name} should remain unconfirmed: {outcomes[name]}')
        replacement = outcomes['sponsorship_after_zero_fee_submission']
        if replacement['mempool'] or 'txn-mempool-conflict' not in replacement.get('rpc_message', ''):
            raise AssertionError(f'{profile}/{mode} did not reject the conflicting spend: {replacement}')
        child = outcomes['p2pkh_cpfp_child']
        if not child['parent_mined_with_child']:
            raise AssertionError(f'{profile}/{mode} did not mine the CPFP parent and child together: {child}')


if __name__ == '__main__':
    main()
