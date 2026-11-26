"""Compare Lamport payment templates with separate one-time test keys."""
from functools import partial

from fixtures import test_secret
from lamport import OneTimeSigner
from payment import sign_spend
from script import committed_locking_script, forth_committed_locking_script, locking_script
from fourthgraph.benchmark.cases import Coin, Template
from fourthgraph.bsv.transaction import Output
from fourthgraph.bsv.one_time_signer import durable_signer


def coin(label, value, *, factory=locking_script):
    signer = OneTimeSigner(test_secret(label.encode()))

    def unlock(tx, index, parent, flag, scratch):
        sign = durable_signer(scratch / "one-time-keys.db", 'lamport-ots-sha256', signer.public_key, signer.sign)
        return sign_spend(tx, index, parent.serialize(), signer.public_key, sign, sighash=flag)

    return Coin(Output(value, factory(signer.public_key)), unlock)


TEMPLATES = {
    "full-key": Template(coin),
    "committed-key": Template(partial(coin, factory=committed_locking_script)),
    "committed-key-forth": Template(partial(coin, factory=forth_committed_locking_script)),
}
