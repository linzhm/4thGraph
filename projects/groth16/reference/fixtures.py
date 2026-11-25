"""Deterministic Groth16 setup and proofs for a two-constraint test circuit.

The toxic waste and prover randomness below are public and test-only.
"""

from functools import cache

from shared.script import asm
from shared.transaction import Input, Output, Transaction

from field import R
from verifier import Curve, Host, Proof, VerificationKey

G1 = (
    0x17F1D3A73197D7942695638C4FA9AC0FC3688C4F9774B905A14E3A3F171BAC586C55E83FF97A1AEFFB3AF00ADB22C6BB,
    0x08B3F481E3AAA0F1A09E30ED741D8AE4FCF5E095D5D00AF600DB18CB2C04B3EDD03CC744A2888AE40CAA232946C5E7E1,
)
G2 = (
    (
        0x024AA2B2F08F0A91260805272DC51051C6E47AD4FA403B02B4510B647AE3D1770BAC0326A805BBEFD48056C8C121BDB8,
        0x13E02B6052719F607DACD3A088274F65596BD0D09920B61AB5DA61BBDC7F5049334CF11213945D57E5AC7D055D042B7E,
    ),
    (
        0x0CE5D527727D6E118CC9CDC6DA2E351AADFD9BAA8CBDD3A76D429A695160D12C923AC9CC3BACA289E193548608B82801,
        0x0606C4A02EA734CC32ACD2B02BC28B99CB3E287E85A763AF267492AB572E99AB3F370D275CEC1DA1AAA9075FF05F79BE,
    ),
)


@cache
def fixture(a=7, b=11, offset=5):
    """Allocate [1, output, offset, a, b, product] in the R1CS."""
    alpha, beta, gamma, delta, tau = 23, 31, 37, 41, 47
    random_r, random_s = 53, 59
    product = a * b % R
    output = (product + offset) % R
    assignment = (1, output, offset, a, b, product)

    # Interpolate each R1CS column at tau from evaluations at rows 1 and 2.
    row1, row2 = 2 - tau, tau - 1
    a_columns = (0, 0, row2, row1, 0, row2)
    b_columns = (row2, 0, 0, 0, row1, 0)
    c_columns = (0, row2, 0, 0, 0, row1)
    combined = tuple(
        beta * u + alpha * v + w
        for u, v, w in zip(a_columns, b_columns, c_columns, strict=True)
    )
    g1, g2 = Curve(Host()), Curve(Host(), twist=True)
    gamma_inverse = pow(gamma, -1, R)
    delta_inverse = pow(delta, -1, R)
    key = VerificationKey(
        g1.mul_host(G1, alpha), g2.mul_host(G2, beta),
        g2.mul_host(G2, gamma), g2.mul_host(G2, delta),
        tuple(g1.mul_host(G1, term * gamma_inverse % R) for term in combined[:3]),
    )

    def evaluate(columns):
        return sum(term * value for term, value in zip(columns, assignment, strict=True)) % R

    u, v, w = map(evaluate, (a_columns, b_columns, c_columns))
    # This circuit's quotient polynomial H is constant. Derive it from
    # the leading coefficient and check H(tau) * Z(tau) against the QAP.
    quotient = (product + offset - a) * (1 - b)
    correction = quotient * (tau - 1) * (tau - 2)
    assert correction % R == (u * v - w) % R
    a_scalar = (alpha + u + random_r * delta) % R
    b_scalar = (beta + v + random_s * delta) % R
    private_terms = sum(term * value for term, value in zip(combined[3:], assignment[3:], strict=True))
    c_scalar = (
        (private_terms + correction) * delta_inverse
        + random_s * a_scalar + random_r * b_scalar - random_r * random_s * delta
    ) % R
    proof = Proof(g1.mul_host(G1, a_scalar), g2.mul_host(G2, b_scalar), g1.mul_host(G1, c_scalar))
    return key, (output, offset), proof


def transactions(lock, unlock, version):
    funding = Transaction(
        (Input(bytes(32), 0xFFFFFFFF, b"\x01\x2a"),),
        (Output(10_000, lock),),
        version=1,
    )
    payment = Transaction(
        (Input(funding.txid_wire(), 0, unlock),), (Output(9_000, asm("OP_1")),), version=version,
    )
    return funding, payment
