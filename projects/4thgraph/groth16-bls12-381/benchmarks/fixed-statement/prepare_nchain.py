"""Build an nChain fixed-statement verifier for 4thGraph's real test proof."""
from pathlib import Path
from argparse import ArgumentParser
import json
from tx_engine import Context
from elliptic_curves.instantiations.bls12_381.bls12_381 import (
    BLS12_381 as curve, ProofBls12381, VerifyingKeyBls12381,
)
from src.zkscript.groth16.bls12_381.bls12_381 import bls12_381
from src.zkscript.script_types.locking_keys.groth16 import Groth16LockingKeyWithPrecomputedMsm
from src.zkscript.script_types.unlocking_keys.groth16 import Groth16UnlockingKeyWithPrecomputedMsm
from src.zkscript.util.utility_scripts import nums_to_script
from tx_engine import Script

parser = ArgumentParser(description=__doc__)
parser.add_argument('fixture', type=Path)
parser.add_argument('output', type=Path)
args = parser.parse_args()
fixture = args.fixture
args.output.mkdir(parents=True, exist_ok=True)
data = json.loads(fixture.read_text())
key = data["verification_key"]
def g1(p):
    if int(p[2]) == 0:
        return curve.g1_curve.infinity()
    return curve.g1_curve(*(curve.g1_field.from_list([int(c)]) for c in p[:2]), False)
def g2(p):
    return curve.g2_curve(*(curve.g2_field.from_list(list(map(int,c))) for c in p[:2]), False)
alpha, beta = g1(key["vk_alpha_1"]), g2(key["vk_beta_2"])
vk = VerifyingKeyBls12381(alpha, beta, g2(key["vk_gamma_2"]), g2(key["vk_delta_2"]), list(map(g1,key["IC"])))
cache = vk.prepare()
pvk = vk.prepare_for_zkscript(cache)
locked = None
for name in ("wrap", "other"):
    case = data[name]
    p = case["proof"]
    proof = ProofBls12381(g1(p["pi_a"]), g2(p["pi_b"]), g1(p["pi_c"]))
    pp = proof.prepare_for_zkscript(cache, list(map(int,case["public"])))
    msm = vk.gamma_abc[0]
    for point, scalar in zip(vk.gamma_abc[1:],case["public"],strict=True):
        msm = msm + point.multiply(int(scalar))
    ul = Groth16UnlockingKeyWithPrecomputedMsm(
        A=pp.a, B=pp.b, C=pp.c,
        gradients_pairings=[pp.gradients_b, pp.gradients_minus_gamma, pp.gradients_minus_delta],
        inverse_miller_output=pp.inverse_miller_loop,
        precomputed_msm=msm.to_list(), has_precomputed_gradients=True,
    ).to_unlocking_script(bls12_381, True).raw_serialize()
    msm_push = nums_to_script(msm.to_list())
    suffix = msm_push.raw_serialize()
    assert ul.endswith(suffix)
    ul = ul[:-len(suffix)]
    if locked is None:
        nkey = Groth16LockingKeyWithPrecomputedMsm(
            alpha_beta=curve.pairing([alpha],[beta]).to_list(),
            minus_gamma=pvk.minus_gamma, minus_delta=pvk.minus_delta,
            gradients_pairings=[pvk.gradients_minus_gamma,pvk.gradients_minus_delta],
            has_precomputed_gradients=False,
        )
        locked = msm_push + bls12_381.groth16_verifier_with_precomputed_msm(
            nkey, modulo_threshold=1600, check_constant=True, clean_constant=True,
        )
        (args.output / 'nchain-fixed-lock.hex').write_text(locked.raw_serialize().hex())
    unlock = Script.parse(b'\xfd'+len(ul).to_bytes(2,'little')+ul)
    assert unlock.raw_serialize()==ul
    accepted = Context(script=unlock + locked).evaluate()
    assert accepted == (name == "wrap"), (name, accepted)
    print(name, len(locked.raw_serialize()), len(ul), accepted)
    (args.output / f'nchain-fixed-{name}.hex').write_text(ul.hex())
