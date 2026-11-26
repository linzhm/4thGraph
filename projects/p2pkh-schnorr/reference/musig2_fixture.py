"""Two-party BIP327 fixture backed by coincurve's pinned libsecp256k1.

Deterministic public test keys and nonce seeds are for tests and benchmarks.
Wallets use separate signer implementations behind the existing BIP340 callback.
"""

from coincurve import PrivateKey, PublicKey, PublicKeyXOnly
from coincurve._libsecp256k1 import ffi, lib
from coincurve.context import GLOBAL_CONTEXT

from bip340 import ORDER
from shared.benchmark_cases import seed

CTX = GLOBAL_CONTEXT.ctx


def checked(operation, *args):
    if not operation(CTX, *args):
        raise ValueError(f"libsecp256k1 rejected {operation.__name__}")


def fixture_keys(label):
    keys = [PrivateKey.from_int(1 + int.from_bytes(seed(f"{label}/party/{i}"), "big") % (ORDER - 1))
            for i in range(2)]
    return tuple(sorted(keys, key=lambda key: key.public_key.format()))


class Policy:
    def __init__(self, public_keys):
        if len(public_keys) != 2 or public_keys[0] == public_keys[1]:
            raise ValueError("two distinct participant public keys required")
        self.keys = tuple(PublicKey(key) for key in public_keys)
        if tuple(key.format() for key in self.keys) != tuple(public_keys):
            raise ValueError("use compressed participant public keys")
        self.cache = ffi.new("secp256k1_musig_keyagg_cache *")
        xonly = ffi.new("secp256k1_xonly_pubkey *")
        checked(lib.secp256k1_musig_pubkey_agg, xonly, self.cache,
                [key.public_key for key in self.keys], 2)
        output = ffi.new("unsigned char[32]")
        checked(lib.secp256k1_xonly_pubkey_serialize, output, xonly)
        self.aggregate_x = bytes(ffi.buffer(output))


class FixtureNonce:
    def __init__(self, signer, policy, message, label):
        if len(message) != 32:
            raise ValueError("expected the 32-byte BSV digest")
        self._keypair = ffi.new("secp256k1_keypair *")
        checked(lib.secp256k1_keypair_create, self._keypair, signer.secret)
        self._secret = ffi.new("secp256k1_musig_secnonce *")
        pub = ffi.new("secp256k1_musig_pubnonce *")
        self.policy = policy
        self.message = message
        self.owner = signer.public_key.format()
        entropy = ffi.new("unsigned char[32]", seed(label + "/musig2-public-fixture-nonce"))
        checked(lib.secp256k1_musig_nonce_gen, self._secret, pub, entropy,
                signer.secret, signer.public_key.public_key, message, policy.cache, ffi.NULL)
        output = ffi.new("unsigned char[66]")
        checked(lib.secp256k1_musig_pubnonce_serialize, output, pub)
        self.public = bytes(ffi.buffer(output))

    def cancel(self):
        if self._secret is not None:
            ffi.buffer(self._secret)[:] = bytes(ffi.sizeof(self._secret[0]))
            self._secret = None

    def sign(self, signing_round, index):
        if self._secret is None:
            raise ValueError("nonce already consumed or canceled")
        if (signing_round.policy is not self.policy or signing_round.message != self.message
                or signing_round.policy.keys[index].format() != self.owner
                or signing_round.encoded_nonces[index] != self.public):
            raise ValueError("nonce does not belong to the signing session")
        partial = ffi.new("secp256k1_musig_partial_sig *")
        try:
            checked(lib.secp256k1_musig_partial_sign, partial, self._secret, self._keypair,
                    self.policy.cache, signing_round.session)
        finally:
            self.cancel()
        output = ffi.new("unsigned char[32]")
        checked(lib.secp256k1_musig_partial_sig_serialize, output, partial)
        return bytes(ffi.buffer(output))


class SigningRound:
    def __init__(self, policy, message, public_nonces):
        if len(message) != 32 or len(public_nonces) != 2 or any(len(nonce) != 66 for nonce in public_nonces):
            raise ValueError("a 32-byte digest and both public nonces are required")
        self.policy = policy
        self.message = message
        self.encoded_nonces = tuple(public_nonces)
        self.nonces = [ffi.new("secp256k1_musig_pubnonce *") for _ in public_nonces]
        for parsed, raw in zip(self.nonces, public_nonces, strict=True):
            checked(lib.secp256k1_musig_pubnonce_parse, parsed, raw)
        aggregate = ffi.new("secp256k1_musig_aggnonce *")
        checked(lib.secp256k1_musig_nonce_agg, aggregate, self.nonces, 2)
        self.session = ffi.new("secp256k1_musig_session *")
        checked(lib.secp256k1_musig_nonce_process, self.session, aggregate, message, policy.cache)

    def combine(self, shares):
        if len(shares) != 2 or any(len(share) != 32 for share in shares):
            raise ValueError("both 32-byte partial signatures are required")
        partials = [ffi.new("secp256k1_musig_partial_sig *") for _ in shares]
        for partial, share, nonce, key in zip(partials, shares, self.nonces, self.policy.keys, strict=True):
            checked(lib.secp256k1_musig_partial_sig_parse, partial, share)
            checked(lib.secp256k1_musig_partial_sig_verify, partial, nonce, key.public_key,
                    self.policy.cache, self.session)
        output = ffi.new("unsigned char[64]")
        checked(lib.secp256k1_musig_partial_sig_agg, output, self.session, partials, 2)
        signature = bytes(ffi.buffer(output))
        if not PublicKeyXOnly(self.policy.aggregate_x).verify(signature, self.message):
            raise ValueError("aggregate failed BIP340 verification")
        return signature


def fixture_sign(keys, policy, label, message):
    nonces = tuple(FixtureNonce(key, policy, message, f"{label}/{i}") for i, key in enumerate(keys))
    try:
        signing_round = SigningRound(policy, message, tuple(nonce.public for nonce in nonces))
        return signing_round.combine(tuple(nonce.sign(signing_round, i) for i, nonce in enumerate(nonces)))
    finally:
        for nonce in nonces:
            nonce.cancel()
