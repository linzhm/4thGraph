"""Import BLS12-381 snarkjs artifacts into the Script verifier."""

from field import Q, R, PrimeField, Tower
from verifier import Proof, VerificationKey, check_point_host

TOWER = Tower(PrimeField())


def scalar(value, limit):
    if type(value) is str and value.isascii() and value.isdecimal() and len(value) <= len(str(limit)):
        value = int(value)
    if type(value) is not int or not 0 <= value < limit:
        raise ValueError("noncanonical field element")
    return value


def sqrt_fp(value):
    root = pow(value, (Q + 1) // 4, Q)
    return root if root * root % Q == value % Q else None


def sqrt_fp2(value):
    real, imag = value
    if imag == 0:
        root = sqrt_fp(real)
        if root is not None:
            return root, 0
        root = sqrt_fp(-real % Q)
        if root is not None:
            return 0, root
        raise ValueError("non-square in Fp2")
    norm = sqrt_fp((real * real + imag * imag) % Q)
    if norm is not None:
        for sign in (norm, -norm):
            half = (real + sign) * ((Q + 1) // 2) % Q
            root = sqrt_fp(half)
            if root:
                other = imag * pow(2 * root, -1, Q) % Q
                result = root, other
                if TOWER.normalize(TOWER.mul2(result, result)) == value:
                    return result
    raise ValueError("non-square in Fp2")


def compressed(data, twist):
    width = 96 if twist else 48
    if len(data) != width * 2:
        raise ValueError("incorrect compressed point size")
    raw = bytearray(bytes.fromhex(data))
    if len(raw) != width or not raw[0] & 0x80:
        raise ValueError("invalid compression flag")
    infinity, sort = bool(raw[0] & 0x40), bool(raw[0] & 0x20)
    raw[0] &= 0x1F
    if infinity:
        if sort or any(raw):
            raise ValueError("noncanonical infinity encoding")
        return None
    first = scalar(int.from_bytes(raw[:48], "big"), Q)
    if twist:
        x = scalar(int.from_bytes(raw[48:], "big"), Q), first
        cube = TOWER.mul2(TOWER.mul2(x, x), x)
        y = sqrt_fp2(TOWER.normalize(TOWER.add(cube, (4, 4))))
        sign_coordinate = y[1] or y[0]
        if (sign_coordinate > (Q - 1) // 2) != sort:
            y = tuple(-part % Q for part in y)
    else:
        x = first
        y = sqrt_fp((x**3 + 4) % Q)
        if y is None:
            raise ValueError("point has no curve ordinate")
        if (y > (Q - 1) // 2) != sort:
            y = -y % Q
    return x, y


def point(data, *, twist=False, allow_infinity=False):
    if isinstance(data, str):
        result = compressed(data, twist)
    else:
        if not isinstance(data, list) or len(data) != 3:
            raise ValueError("expected a snarkjs point with three coordinates")
        if twist:
            if any(not isinstance(pair, list) or len(pair) != 2 for pair in data):
                raise ValueError("expected Fp2 coordinates in real, imaginary order")
            x, y, z = (tuple(scalar(value, Q) for value in pair) for pair in data)
            affine_z = (1, 0)
        else:
            x, y, z = map(lambda value: scalar(value, Q), data)
            if (x, y, z) == (0, 1, 0) and allow_infinity:
                return None
            affine_z = 1
        if z != affine_z:
            raise ValueError("expected an affine point")
        result = (x, y)
    if result is not None or not allow_infinity:
        check_point_host(result, twist=twist)
    return result


def metadata(artifact):
    if artifact.get("protocol") != "groth16" or artifact.get("curve") not in ("bls12381", "bls12-381"):
        raise ValueError("expected Groth16 over BLS12-381")


def load_verification_key(key_json):
    metadata(key_json)
    count = key_json["nPublic"]
    if type(count) is not int or count < 0 or len(key_json["IC"]) != count + 1:
        raise ValueError("invalid verification key public signal count")
    return VerificationKey(
        point(key_json["vk_alpha_1"]),
        point(key_json["vk_beta_2"], twist=True),
        point(key_json["vk_gamma_2"], twist=True),
        point(key_json["vk_delta_2"], twist=True),
        tuple(point(item, allow_infinity=True) for item in key_json["IC"]),
    )


def load_artifacts(key_json, proof_json, signals_json):
    if "protocol" in proof_json or "curve" in proof_json:
        metadata(proof_json)
    signals = tuple(scalar(value, R) for value in signals_json)
    key = load_verification_key(key_json)
    if key_json["nPublic"] != len(signals):
        raise ValueError("public signal count does not match verification key")
    proof = Proof(point(proof_json["pi_a"]), point(proof_json["pi_b"], twist=True), point(proof_json["pi_c"]))
    return key, signals, proof
