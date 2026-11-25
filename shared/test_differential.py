"""Regression checks for differential test evidence."""

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch

from .differential import chain_gang_valid, node_script_valid, require_chain_gang_pin


class DifferentialTests(unittest.TestCase):
    def test_node_counts_only_expected_script_or_activation_rejections(self):
        flags = 19

        def reply(status, description=None, *, reported_flags=flags):
            return {'result': [{'result': status, 'description': description, 'flags': reported_flags}],
                    'error': None}

        self.assertTrue(node_script_valid(reply('ok'), flags))
        self.assertFalse(node_script_valid(reply('error', 'Script failed an OP_VERIFY operation'), flags))
        self.assertFalse(node_script_valid(reply('error', 'Illegal use of SIGHASH_CHRONICLE'),
                                           flags, chronicle_active=False))
        unexpected = (
            reply('error'),
            reply('error', 'Unknown error'),
            reply('timeout', 'Script failed an OP_VERIFY operation'),
            reply('error', 'Illegal use of SIGHASH_CHRONICLE'),
            reply('ok', reported_flags=flags ^ 1),
            {'error': {'code': -22, 'message': 'TX decode failed'}},
        )
        for response in unexpected:
            with self.subTest(response=response):
                with self.assertRaises(AssertionError):
                    node_script_valid(response, flags)
        with self.assertRaises(AssertionError):
            node_script_valid(reply('error', 'Script failed an OP_VERIFY operation'),
                              flags, chronicle_active=False)

    def test_chain_gang_requires_the_expected_kind_of_rejection(self):
        spend = Mock()
        funding = [object()]
        self.assertTrue(chain_gang_valid(spend, funding))
        spend.validate.assert_called_once_with(funding)

        spend.validate.side_effect = ValueError('Error evaluating the script `OP_VERIFY failed`')
        self.assertFalse(chain_gang_valid(spend, funding))
        with self.assertRaises(ValueError):
            chain_gang_valid(spend, funding, expect_bad_prevout=True)

        spend.validate.side_effect = ValueError('A provided data is not valid `Invalid Outpoint index 1`')
        self.assertFalse(chain_gang_valid(spend, funding, expect_bad_prevout=True))
        with self.assertRaises(ValueError):
            chain_gang_valid(spend, funding)

        for error in (
            ValueError('Error evaluating the script `Cannot pop bool, len too long 33`'),
            ValueError('The operation timed out'),
            RuntimeError('interpreter unavailable'),
        ):
            with self.subTest(error=error):
                spend.validate.side_effect = error
                with self.assertRaises(type(error)) as caught:
                    chain_gang_valid(spend, funding)
                self.assertIs(caught.exception, error)

    def test_engine_provenance_must_match_requirements(self):
        pin = 'a' * 40
        with TemporaryDirectory() as directory, patch('shared.differential.distribution') as package:
            requirements = Path(directory) / 'requirements.txt'
            requirements.write_text(f'tx-engine @ git+https://example.invalid/chain-gang.git@{pin}\n',
                                    encoding='utf-8')
            metadata = package.return_value.read_text
            metadata.return_value = json.dumps({'vcs_info': {'vcs': 'git', 'commit_id': pin}})
            self.assertEqual(require_chain_gang_pin(requirements), pin)
            metadata.assert_called_once_with('direct_url.json')
            metadata.return_value = json.dumps({'vcs_info': {'vcs': 'git', 'commit_id': 'b' * 40}})
            with self.assertRaisesRegex(RuntimeError, 'commit mismatch'):
                require_chain_gang_pin(requirements)
            for missing in (None, '{}', 'not JSON'):
                with self.subTest(metadata=missing):
                    metadata.return_value = missing
                    with self.assertRaisesRegex(RuntimeError, 'provenance unavailable'):
                        require_chain_gang_pin(requirements)
