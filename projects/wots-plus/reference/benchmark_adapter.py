"""Compare the standard and cached-constants WOTS+ payment templates."""
from payment import sign_spend
from script import locking_script
from wots import OneTimeSigner
from shared.benchmark_cases import Coin, Template, seed
from shared.transaction import Output
from shared.one_time_signer import durable_signer


def coin(label, value, *, cached=False):
    signer = OneTimeSigner(seed(label + "/secret"), seed(label + "/public"))
    public = signer.public_key

    def unlock(tx, index, parent, flag, scratch):
        sign = durable_signer(scratch / "one-time-keys.db", 'wots-plus-sha256', public, signer)
        return sign_spend(tx, index, parent.serialize(), public, sign, sighash=flag)

    return Coin(Output(value, locking_script(public, cached_constants=cached)), unlock)


TEMPLATES = {"canonical": Template(coin),
             "cached-constants": Template(lambda label, value: coin(label, value, cached=True)),
             "cached-steps": Template(lambda label, value: coin(label, value, cached="steps"))}
