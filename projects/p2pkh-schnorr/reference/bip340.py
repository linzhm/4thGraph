"""Public-data BIP340 verification and witness coordinate recovery."""

from hashlib import sha256

FIELD = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
GENERATOR = (
    0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
    0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8,
)
CHALLENGE_TAG = sha256(b"BIP0340/challenge").digest() * 2


def to_bytes(value):
    return value.to_bytes(32, "big")


def lift_x(raw):
    """Recover the unique finite point with the supplied x and even y."""
    if not isinstance(raw, bytes) or len(raw) != 32:
        return None
    x = int.from_bytes(raw, "big")
    if x >= FIELD:
        return None
    square = (x ** 3 + 7) % FIELD
    y = pow(square, (FIELD + 1) // 4, FIELD)
    if y * y % FIELD != square:
        return None
    return x, FIELD - y if y & 1 else y


def _add(left, right):
    if left is None or right is None:
        return right if left is None else left
    x1, y1 = left
    x2, y2 = right
    if x1 == x2:
        if (y1 + y2) % FIELD == 0:
            return None
        slope = 3 * x1 * x1 * pow(2 * y1, -1, FIELD) % FIELD
    else:
        slope = (y2 - y1) * pow((x2 - x1) % FIELD, -1, FIELD) % FIELD
    x = (slope * slope - x1 - x2) % FIELD
    return x, (slope * (x1 - x) - y1) % FIELD


def _multiply(scalar, point):
    result = None
    for bit in bin(scalar)[2:]:
        result = _add(result, result)
        if bit == "1":
            result = _add(result, point)
    return result


def verify(public_key, message, signature):
    """Verify a raw 64-byte BIP340 signature over a bytes message."""
    point = lift_x(public_key)
    if point is None or not isinstance(message, bytes) or not isinstance(signature, bytes) or len(signature) != 64:
        return False
    r, s = int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
    if r >= FIELD or s >= ORDER:
        return False
    challenge = int.from_bytes(sha256(CHALLENGE_TAG + signature[:32] + public_key + message).digest(), "big") % ORDER
    nonce = _add(_multiply(s, GENERATOR), _multiply(ORDER - challenge, point))
    return nonce is not None and nonce[0] == r and nonce[1] % 2 == 0
