"""P-256 benchmark fixtures using the normal wallet signer callback."""

from test_payment import fixture_signature, signer
from p2pkh_r1 import locking_script_from_owner_hash
from tx_engine import Tx
from wallet import sign_spend
from shared.benchmark_cases import Coin, Template, seed
from shared.transaction import Output

ORDER = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551


def r1_coin(label, value, *, compiled=False, compress=False):
    scalar = 1 + int.from_bytes(seed(label), "big") % (ORDER - 1)
    key, public, owner = signer(scalar)
    lock = locking_script_from_owner_hash(owner, compiled_curve=compiled)

    def unlock(tx, index, parent, flag, scratch):
        witness = sign_spend(
            Tx.parse(tx.serialize()), index, Tx.parse(parent.serialize()), flag, public,
            lambda digest: fixture_signature(key, digest), scratch / "r1-history.db",
            compress_otda=compress,
        )
        return tx.with_script(index, witness.raw_serialize())

    return Coin(Output(value, lock), unlock)


TEMPLATES = {
    "canonical": Template(r1_coin),
    "compiled-literal": Template(lambda label, value: r1_coin(label, value, compiled=True)),
    "compiled-reconstructed": Template(
        lambda label, value: r1_coin(label, value, compiled=True, compress=True),
    ),
    "compiled-shared-kernels": Template(
        lambda label, value: r1_coin(label, value, compiled=True, compress="shared-kernels"),
    ),
}


def components(_samples):
    from specialize import specialized_lock

    return {"compiled_output_bytes": len(locking_script_from_owner_hash(bytes(20), compiled_curve=True)),
            "mode_specific_experiment_output_bytes": {
                family: len(specialized_lock(bytes(20), family)) for family in ("forkid", "otda")
            }}
