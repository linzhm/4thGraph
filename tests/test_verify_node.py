"""Check the Linux regtest launcher's archive validation and RPC wiring."""

import os
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
import unittest


LAUNCHER = (Path(__file__).resolve().parents[1] / 'tools/verify_node.sh').resolve()


def write_stub(directory, name, body):
    executable = directory / name
    executable.write_text('#!/bin/bash\nset -eu\n' + body, encoding='ascii')
    executable.chmod(0o755)


class VerifyNodeTests(unittest.TestCase):
    def run_launcher(self, directory, *, rpc_port=None, chronicle_height=None, test_exit=0):
        temporary = directory / 'node-temp'
        temporary.mkdir()
        env = dict(os.environ, PATH=f"{directory}:{os.environ['PATH']}", LC_ALL='C',
                   TMPDIR=str(temporary), VERIFY_NODE_TEST_TRACE=str(directory),
                   VERIFY_NODE_TEST_EXIT=str(test_exit), REGTEST_URL='http://127.0.0.1:1')
        env.pop('REGTEST_RPC_PORT', None)
        env.pop('REGTEST_CHRONICLE_HEIGHT', None)
        if rpc_port is not None:
            env['REGTEST_RPC_PORT'] = rpc_port
        if chronicle_height is not None:
            env['REGTEST_CHRONICLE_HEIGHT'] = chronicle_height
        result = subprocess.run(['bash', str(LAUNCHER), 'test_fixture'], env=env, cwd=directory,
                                capture_output=True, timeout=10)
        self.assertEqual(list(temporary.iterdir()), [])
        return result

    def test_mismatched_archive_is_never_extracted(self):
        with TemporaryDirectory() as tmp:
            directory = Path(tmp)
            write_stub(directory, 'curl', 'printf %s "test archive bytes" > "${!#}"\n')
            write_stub(directory, 'tar', 'touch "$VERIFY_NODE_TEST_TRACE/extracted"\nexit 99\n')
            result = self.run_launcher(directory)
            self.assertEqual(result.returncode, 1)
            self.assertIn(b'FAILED', result.stdout)
            self.assertFalse((directory / 'extracted').exists())

    def test_invalid_ports_fail_before_download(self):
        for port in ('0', '65536', '-1', 'not-a-port'):
            with self.subTest(port=port), TemporaryDirectory() as tmp:
                directory = Path(tmp)
                write_stub(directory, 'curl', 'touch "$VERIFY_NODE_TEST_TRACE/downloaded"\n')
                result = self.run_launcher(directory, rpc_port=port)
                self.assertEqual(result.returncode, 2)
                self.assertIn(b'REGTEST_RPC_PORT', result.stderr)
                self.assertFalse((directory / 'downloaded').exists())

    def test_invalid_chronicle_heights_fail_before_download(self):
        for height in ('1', '2147483648', '-1', 'not-a-height'):
            with self.subTest(height=height), TemporaryDirectory() as tmp:
                directory = Path(tmp)
                write_stub(directory, 'curl', 'touch "$VERIFY_NODE_TEST_TRACE/downloaded"\n')
                result = self.run_launcher(directory, chronicle_height=height)
                self.assertEqual(result.returncode, 2)
                self.assertIn(b'REGTEST_CHRONICLE_HEIGHT', result.stderr)
                self.assertFalse((directory / 'downloaded').exists())

    def test_selected_configuration_reaches_node_and_tests(self):
        cases = ((None, 18443, None, 2, 0), ('18461', 18461, '01000', 1000, 0), ('01861', 1861, None, 2, 7))
        for override, port, chronicle_height, expected_height, test_exit in cases:
            with self.subTest(override=override, test_exit=test_exit), TemporaryDirectory() as tmp:
                directory = Path(tmp)
                write_stub(directory, 'curl', 'printf %s "test archive bytes" > "${!#}"\n')
                write_stub(directory, 'sha256sum', 'cat >/dev/null\n')
                write_stub(directory, 'tar', '''bin=bitcoin-sv-1.2.3/bin
mkdir -p "$bin"
cp "$VERIFY_NODE_TEST_TRACE/bitcoind" "$VERIFY_NODE_TEST_TRACE/bitcoin-cli" "$bin"
''')
                write_stub(directory, 'bitcoind', '''printf '%s\n' "$@" > "$VERIFY_NODE_TEST_TRACE/node-args"
for arg in "$@"; do
    if [[ "$arg" == -datadir=* ]]; then
        data="${arg#*=}"
    fi
done
mkdir "$data/regtest"
printf %s fixture-cookie > "$data/regtest/.cookie"
while :; do sleep 0.1; done
''')
                write_stub(directory, 'bitcoin-cli', '''printf '%s\n' "$@" > "$VERIFY_NODE_TEST_TRACE/cli-args"
''')
                write_stub(directory, 'python', '''test -s "$REGTEST_COOKIE"
printf '%s\n' "$REGTEST_URL" > "$VERIFY_NODE_TEST_TRACE/test-url"
printf '%s\n' "$SCRIPT_LAB_CHRONICLE_HEIGHT" > "$VERIFY_NODE_TEST_TRACE/test-height"
printf '%s\n' "$@" > "$VERIFY_NODE_TEST_TRACE/test-args"
exit "$VERIFY_NODE_TEST_EXIT"
''')
                result = self.run_launcher(directory, rpc_port=override,
                                           chronicle_height=chronicle_height, test_exit=test_exit)
                self.assertEqual(result.returncode, test_exit, result.stderr)
                self.assertIn(f'-rpcport={port}', (directory / 'node-args').read_text().splitlines())
                self.assertIn(f'-chronicleactivationheight={expected_height}',
                              (directory / 'node-args').read_text().splitlines())
                cli_args = (directory / 'cli-args').read_text().splitlines()
                self.assertIn('-rpcconnect=127.0.0.1', cli_args)
                self.assertIn(f'-rpcport={port}', cli_args)
                self.assertIn('getblockcount', cli_args)
                self.assertEqual((directory / 'test-url').read_text().strip(), f'http://127.0.0.1:{port}')
                self.assertEqual((directory / 'test-height').read_text().strip(), str(expected_height))
                self.assertEqual((directory / 'test-args').read_text().splitlines(),
                                 ['-m', 'unittest', '-v', 'test_fixture'])
