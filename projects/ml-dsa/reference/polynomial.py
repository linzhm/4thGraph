"""FIPS 204 Algorithms 41–43 for 256 coefficients in Z_q."""

from functools import cache

DEGREE = 256
MODULUS = 8_380_417
ROOT_OF_UNITY = 1_753


@cache
def twiddle(index):
    reversal = int(f"{index:08b}"[::-1], 2)
    return pow(ROOT_OF_UNITY, reversal, MODULUS)


def ntt(polynomial):
    coefficients = list(polynomial)
    index = 0
    for width in (128, 64, 32, 16, 8, 4, 2, 1):
        for start in range(0, DEGREE, 2 * width):
            index += 1
            zeta = twiddle(index)
            for left in range(start, start + width):
                right = left + width
                term = zeta * coefficients[right]
                coefficients[right] = (coefficients[left] - term) % MODULUS
                coefficients[left] = (coefficients[left] + term) % MODULUS
    return coefficients


def inverse_ntt(polynomial):
    coefficients = list(polynomial)
    index = DEGREE
    for width in (1, 2, 4, 8, 16, 32, 64, 128):
        for start in range(0, DEGREE, 2 * width):
            index -= 1
            zeta = -twiddle(index)
            for left in range(start, start + width):
                right = left + width
                old_left = coefficients[left]
                coefficients[left] = (old_left + coefficients[right]) % MODULUS
                coefficients[right] = (zeta * (old_left - coefficients[right])) % MODULUS
    scale = pow(DEGREE, -1, MODULUS)
    return [(scale * coefficient) % MODULUS for coefficient in coefficients]
