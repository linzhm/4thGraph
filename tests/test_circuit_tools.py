"""Check that a proof build can serve independent witness requests."""

from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Barrier
from types import SimpleNamespace
import unittest

from fourthgraph.verification.circuit_tools import CircuitFixture


class CircuitToolsTests(unittest.TestCase):
    def test_parallel_witness_requests_use_separate_files(self):
        with TemporaryDirectory() as directory:
            fixture = CircuitFixture.__new__(CircuitFixture)
            fixture.directory = Path(directory)
            fixture.key = SimpleNamespace(current_wire=3, assignment=lambda raw: tuple(json.loads(raw)))
            ready = Barrier(2, timeout=5)
            requests = [(7, (11, 13)), (19, (23, 29))]

            def run(package, executable, *args, cwd):
                if args[:2] == ("wtns", "calculate"):
                    ready.wait()
                if args[:2] == ("wtns", "export"):
                    values = json.loads((cwd / "input.json").read_text())
                    public = tuple(int(values[name]) for name in ("current", "bindLo", "bindHi"))
                    (cwd / "proof.json").write_text(json.dumps((1, 0, 0, *public)))

            fixture.run = run
            with ThreadPoolExecutor(max_workers=2) as pool:
                futures = [pool.submit(fixture.prove, current=current, binding=binding)
                           for current, binding in requests]
                self.assertEqual([future.result()[3:] for future in futures],
                                 [(current, *binding) for current, binding in requests])
            self.assertFalse(tuple(fixture.directory.iterdir()))
