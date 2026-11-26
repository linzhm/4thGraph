"""Benchmark the short lock from funding through the canonical R1 spend."""
from pathlib import Path
import runpy

from deferred import activate_input, funding_output_from_owner_hash
from p2pkh_r1 import recognize
from fourthgraph.benchmark.cases import Coin, Template

R1_PATH = Path(__file__).resolve().parents[2] / "p2pkh-r1/reference/benchmark_adapter.py"
r1_coin = runpy.run_path(str(R1_PATH))["r1_coin"]


def deferred_coin(label, value):
    target = r1_coin(label, value, compiled="scheduled", compress="paired")
    funding = funding_output_from_owner_hash(value, recognize(target.output.script))

    def unlock(tx, index, parent, flag, _scratch):
        return activate_input(tx, index, parent.serialize(), sighash=flag)

    return Coin(funding, unlock, activated=target)


TEMPLATES = {"hash-only": Template(deferred_coin, deferred=True)}
