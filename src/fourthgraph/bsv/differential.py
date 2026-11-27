"""Evidence checks for complete-input differential tests."""

from importlib.metadata import PackageNotFoundError, distribution
import json
from pathlib import Path
import re


# These are the rejections expected by the Lamport and SM2 fixtures.
_NODE_SCRIPT_REJECTIONS = {
    'Script evaluated without error but finished with a false/empty top stack element',
    'Script failed an OP_CHECKSIGVERIFY operation',
    'Script failed an OP_EQUALVERIFY operation',
    'Script failed an OP_NUMEQUALVERIFY operation',
    'Script failed an OP_VERIFY operation',
}
_CHRONICLE_INACTIVE_REJECTION = 'Illegal use of SIGHASH_CHRONICLE'
# Exact wording of SCRIPT_ERR_SIG_PUSHONLY in BSV Node 1.2.3.
_NODE_PUSH_ONLY_REJECTION = 'Only non-push operators allowed in signatures'
_CHAIN_GANG_PUSH_ONLY_REJECTION = 'A provided data is not valid `Unlock script must be push-only`'
_CHAIN_GANG_SCRIPT_REJECTIONS = {
    f'Error evaluating the script `{reason}`'
    for reason in (
        'Top of stack is false',
        'OP_CHECKSIG NULLFAIL',
        'OP_CHECKSIGVERIFY failed',
        'OP_EQUALVERIFY operands are not equal',
        'Numbers are not equal',
        'OP_VERIFY failed',
    )
}
_CHAIN_GANG_PREVOUT_REJECTION = re.compile(
    r'A provided data is not valid `(?:Invalid Outpoint index [0-9]+|Unable to find hash [0-9a-f]{64})`'
)


def require_chain_gang_pin(requirements):
    """Require the installed tx-engine Git revision recorded in requirements."""
    requirements = Path(requirements)
    pins = [line.rsplit('@', 1)[-1].strip()
            for line in requirements.read_text(encoding='utf-8').splitlines()
            if line.startswith('tx-engine @ git+')]
    if len(pins) != 1 or re.fullmatch(r'[0-9a-f]{40}', pins[0]) is None:
        raise RuntimeError(f'expected one full tx-engine Git commit in {requirements}')
    pin = pins[0]

    try:
        source = distribution('tx-engine').read_text('direct_url.json')
        vcs = json.loads(source or '{}')['vcs_info']
        installed = vcs['commit_id'] if vcs['vcs'] == 'git' else None
    except (PackageNotFoundError, KeyError, TypeError, ValueError) as error:
        raise RuntimeError(f'tx-engine Git provenance unavailable. Install from {requirements}') from error

    if installed != pin:
        raise RuntimeError(f'tx-engine commit mismatch. Expected {pin}, got {installed}. Install from {requirements}')
    return pin


def chain_gang_valid(spend, funding, *, expect_bad_prevout=False, expect_push_only=False):
    """Validate parsed transactions and recognize only expected rejection reasons."""
    try:
        spend.validate(funding)
    except ValueError as error:
        reason = str(error)
        if expect_bad_prevout:
            expected = _CHAIN_GANG_PREVOUT_REJECTION.fullmatch(reason) is not None
        elif expect_push_only:
            expected = reason == _CHAIN_GANG_PUSH_ONLY_REJECTION
        else:
            expected = is_chain_gang_script_rejection(error)
        if not expected:
            raise
        return False
    return True


def is_chain_gang_script_rejection(error):
    return isinstance(error, ValueError) and str(error) in _CHAIN_GANG_SCRIPT_REJECTIONS


def node_script_valid(response, flags, *, chronicle_active=True, expect_push_only=False):
    """Check one verifyscript result, including its flags and rejection reason."""
    if response.get('error') is not None:
        raise AssertionError(f'verifyscript RPC error: {response["error"]}')
    result, = response['result']
    if result.get('flags') != flags:
        raise AssertionError(f'verifyscript returned unexpected flags: {result}')
    status = result.get('result')
    if status == 'ok':
        return True
    if expect_push_only:
        reasons = {_NODE_PUSH_ONLY_REJECTION}
    else:
        reasons = _NODE_SCRIPT_REJECTIONS if chronicle_active else {_CHRONICLE_INACTIVE_REJECTION}
    if status == 'error' and result.get('description') in reasons:
        return False
    raise AssertionError(f'verifyscript returned an unexpected outcome: {result}')
