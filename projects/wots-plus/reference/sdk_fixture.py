from script import locking_script
from wots import public_key, sign_digest


def cases():
    destination_key = public_key(bytes([6]) * 32, bytes([7]) * 32)
    for seed, profile, cache, length, sighash in (
        (1, "canonical", False, 42266, 0x41),
        (2, "cached-steps", "steps", 33956, 0x63),
        (3, "compact", "compact", 29217, 0x63),
        (4, "compact-v2", "compact-v2", 27070, 0x63),
        (5, "compact-v3", "compact-v3", 25965, 0x63),
        (6, "compact-v4", "compact-v4", 23296, 0x63),
        (7, "compact-v5", "compact-v5", 22494, 0x63),
        (8, "compact-v6", "compact-v6", 21982, 0x63),
        (9, "compact-v7", "compact-v7", 21774, 0x63),
        (10, "compact-v8", "compact-v8", 21540, 0x63),
        (11, "compact-v9", "compact-v9", 21332, 0x63),
        (12, "compact-v10", "compact-v10", 21320, 0x63),
    ):
        secret, public = bytes([seed]) * 32, bytes([seed + 9]) * 32
        yield dict(public_key=public_key(secret, public), signer=lambda digest: sign_digest(secret, public, digest),
                   profile=profile, bytes=length, sighash=sighash, compress_otda=sighash == 0x63,
                   destination=locking_script(destination_key, cached_constants=cache) if sighash == 0x63 else b"\x51")
