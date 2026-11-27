"""Deterministic Schnorr workloads for the unified transaction benchmark."""

from functools import partial

from coincurve import PrivateKey

from bip340 import ORDER
from payment import lock_for_public_key, sign_spend
from schnorr_script import TEMPLATE_DIRS, TEMPLATE_VERSION
from fourthgraph.benchmark.cases import Coin, Template, seed
from fourthgraph.bsv.transaction import CHRONICLE, Output


def schnorr_coin(label, value, *, version=TEMPLATE_VERSION):
    # Public test-only key and auxiliary randomness. Wallets pass an external signer.
    scalar = 1 + int.from_bytes(seed(label), "big") % (ORDER - 1)
    key = PrivateKey.from_int(scalar)
    public_key = key.public_key_xonly.format()

    def signer(message):
        return key.sign_schnorr(message, aux_randomness=bytes(32))

    def unlock(tx, index, parent, flag, _scratch):
        return sign_spend(tx, index, parent.serialize(), public_key, signer,
                          sighash=flag, chronicle_active=bool(flag & CHRONICLE))

    return Coin(Output(value, lock_for_public_key(public_key, version=version)), unlock)


TEMPLATES = {version: Template(partial(schnorr_coin, version=version)) for version in TEMPLATE_DIRS}
