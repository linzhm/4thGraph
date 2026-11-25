from script import locking_script
from wots import public_key, sign_digest


def cases():
    destination = locking_script(public_key(bytes([6]) * 32, bytes([7]) * 32), cached_constants="steps")
    for seed, profile, length, sighash in ((1, "canonical", 42266, 0x41), (2, "cached-steps", 33956, 0x63)):
        secret, public = bytes([seed]) * 32, bytes([seed + 9]) * 32
        yield dict(public_key=public_key(secret, public), signer=lambda digest: sign_digest(secret, public, digest),
                   profile=profile, bytes=length, sighash=sighash, compress_otda=sighash == 0x63,
                   destination=destination if sighash == 0x63 else b"\x51")
