"""Pure ML-DSA-44 reference verification for byte-aligned public messages."""

from hashlib import shake_128, shake_256
from hmac import compare_digest

from polynomial import DEGREE, MODULUS, inverse_ntt, ntt

PUBLIC_KEY_BYTES = 1_312
SIGNATURE_BYTES = 2_420
CHALLENGE_BYTES = 32
CHALLENGE_WEIGHT = 39
CHALLENGE_SIGN_BYTES = 8
# FIPS 204, Appendix C, Table 3, including the bytes reserved for signs.
SAMPLE_IN_BALL_BYTES = 221
RESPONSE_BITS = 18
GAMMA1 = 1 << 17
RESPONSE_NORM_LIMIT = GAMMA1 - 78

# FIPS 204, Table 1, category 2.
_K = _L = 4
_D = 13
_GAMMA2 = (MODULUS - 1) // 88
_OMEGA = 80
_T1_WIDTH, _W1_WIDTH = 10, 6


def _unpack(data, count, width):
    packed = int.from_bytes(data, "little")
    mask = (1 << width) - 1
    return [(packed >> (index * width)) & mask for index in range(count)]


def _pack(coefficients, width):
    packed = sum(value << (index * width) for index, value in enumerate(coefficients))
    return packed.to_bytes(len(coefficients) * width // 8, "little")


def _hints(encoded):
    """HintBitUnpack with per-polynomial index ordering and zero padding."""
    hints = []
    start = 0
    for end in encoded[_OMEGA:]:
        if not start <= end <= _OMEGA:
            return None
        indices = encoded[start:end]
        if any(left >= right for left, right in zip(indices, indices[1:])):
            return None
        hints.append(frozenset(indices))
        start = end
    if any(encoded[start:_OMEGA]):
        return None
    return hints


def _squeeze(xof, width):
    """Adapt hashlib's prefix-based XOF API to incremental squeeze blocks."""
    offset = 0
    while True:
        end = offset + width
        yield xof.digest(end)[offset:end]
        offset = end


def _matrix_entry(seed, row, column):
    # RejNTTPoly(ρ || IntegerToBytes(column,1) || IntegerToBytes(row,1)).
    coefficients = []
    for block in _squeeze(shake_128(seed + bytes((column, row))), 168):
        for offset in range(0, len(block), 3):
            candidate = int.from_bytes(block[offset:offset + 3], "little") & 0x7F_FFFF
            if candidate < MODULUS:
                coefficients.append(candidate)
                if len(coefficients) == DEGREE:
                    return coefficients


def sample_challenge(challenge):
    """SampleInBall from SHAKE256, with the first 64 bits as sign bits."""
    if not isinstance(challenge, bytes) or len(challenge) != CHALLENGE_BYTES:
        raise ValueError("ML-DSA-44 challenge must be 32 bytes")
    stream = shake_256(challenge).digest(SAMPLE_IN_BALL_BYTES)
    signs = int.from_bytes(stream[:CHALLENGE_SIGN_BYTES], "little")
    draws = iter(stream[CHALLENGE_SIGN_BYTES:])
    polynomial = [0] * DEGREE
    for index in range(DEGREE - CHALLENGE_WEIGHT, DEGREE):
        sample = next((value for value in draws if value <= index), None)
        if sample is None:
            raise ValueError("SampleInBall exhausted its SHAKE stream")
        polynomial[index] = polynomial[sample]
        polynomial[sample] = 1 - 2 * (signs & 1)
        signs >>= 1
    return polynomial


def _use_hint(coefficient, hint):
    modulus = 2 * _GAMMA2
    low = coefficient % modulus
    if low > _GAMMA2:
        low -= modulus
    if coefficient - low == MODULUS - 1:
        high = 0
        low -= 1
    else:
        high = (coefficient - low) // modulus
    if hint:
        high = (high + (1 if low > 0 else -1)) % ((MODULUS - 1) // modulus)
    return high


def verification_key_rows(public_key):
    """Return the NTT-domain rows [-NTT(t1*2^d), A_hat] for a fixed key."""
    if not isinstance(public_key, bytes) or len(public_key) != PUBLIC_KEY_BYTES:
        raise ValueError("ML-DSA-44 public key must be 1,312 bytes")
    seed = public_key[:32]
    t1 = _unpack(public_key[32:], _K * DEGREE, _T1_WIDTH)
    for row in range(_K):
        scaled_t1 = [value << _D for value in t1[row * DEGREE:(row + 1) * DEGREE]]
        scaled_t1_ntt = [(-value) % MODULUS for value in ntt(scaled_t1)]
        yield [scaled_t1_ntt, *(_matrix_entry(seed, row, column) for column in range(_L))]


def verification_equation(public_key, challenge_polynomial, response_polynomials):
    """Reconstruct the rows of A*z - c*t1*2^d in coefficient order."""
    inputs_ntt = [ntt(polynomial) for polynomial in (challenge_polynomial, *response_polynomials)]
    for row in verification_key_rows(public_key):
        product = [0] * DEGREE
        for fixed, values in zip(row, inputs_ntt, strict=True):
            for index, (left, right) in enumerate(zip(fixed, values, strict=True)):
                product[index] += left * right
        yield inverse_ntt([value % MODULUS for value in product])


def verify(public_key, message, signature, *, context=b""):
    """Verify a FIPS 204 Pure ML-DSA-44 signature over byte strings."""
    if not all(isinstance(value, bytes) for value in (public_key, message, signature, context)):
        return False
    if len(public_key) != PUBLIC_KEY_BYTES or len(signature) != SIGNATURE_BYTES or len(context) > 255:
        return False

    challenge = signature[:CHALLENGE_BYTES]
    hint_offset = CHALLENGE_BYTES + _L * DEGREE * RESPONSE_BITS // 8
    hints = _hints(signature[hint_offset:])
    if hints is None:
        return False
    z = [GAMMA1 - value for value in _unpack(signature[CHALLENGE_BYTES:hint_offset], _L * DEGREE, RESPONSE_BITS)]
    if any(abs(coefficient) >= RESPONSE_NORM_LIMIT for coefficient in z):
        return False

    public_hash = shake_256(public_key).digest(64)
    mu = shake_256(public_hash + bytes((0, len(context))) + context + message).digest(64)
    response = [z[column * DEGREE:(column + 1) * DEGREE] for column in range(_L)]
    try:
        challenge_polynomial = sample_challenge(challenge)
    except ValueError:
        return False
    equation = verification_equation(public_key, challenge_polynomial, response)
    encoded_high_bits = bytearray()
    for row, hint_positions in zip(equation, hints, strict=True):
        high_bits = [
            _use_hint(value, index in hint_positions)
            for index, value in enumerate(row)
        ]
        encoded_high_bits += _pack(high_bits, _W1_WIDTH)
    expected = shake_256(mu + encoded_high_bits).digest(CHALLENGE_BYTES)
    return compare_digest(challenge, expected)
