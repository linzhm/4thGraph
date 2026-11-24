"""GB/T 35275-2026 SignedData profile for direct SM2 payment signatures."""

from sm2 import N, USER_ID, be32, parse_public, verify


_DATA = bytes.fromhex('2a811ccf550601040201')
_SIGNED_DATA = bytes.fromhex('2a811ccf550601040202')
_SM3 = bytes.fromhex('2a811ccf55018311')
_SM2_SIGNATURE = bytes.fromhex('2a811ccf5501822d01')
_SM2_WITH_SM3 = bytes.fromhex('2a811ccf55018375')


class _DER:
    def __init__(self, data):
        self.data = data
        self.position = 0

    def next_is(self, tag):
        return self.position < len(self.data) and self.data[self.position] == tag

    def take(self, tag):
        start = self.position
        if not self.next_is(tag) or start + 2 > len(self.data):
            raise ValueError('unexpected or truncated SignedData DER field')
        length = self.data[start + 1]
        content = start + 2
        if length >= 128:
            width = length & 127
            encoded_length = self.data[content:content + width]
            if not width or len(encoded_length) != width or encoded_length[0] == 0:
                raise ValueError('invalid DER length')
            length = int.from_bytes(encoded_length, 'big')
            if length < 128:
                raise ValueError('non-minimal DER length')
            content += width
        end = content + length
        if end > len(self.data):
            raise ValueError('truncated DER content')
        self.position = end
        return self.data[content:end]

    def done(self):
        if self.position != len(self.data):
            raise ValueError('trailing or unsupported SignedData fields')


def _algorithm(fields, *allowed):
    algorithm = _DER(fields.take(0x30))
    if algorithm.take(0x06) not in allowed:
        raise ValueError('unexpected SignedData algorithm')
    if algorithm.next_is(0x05) and algorithm.take(0x05):
        raise ValueError('invalid DER NULL parameters')
    algorithm.done()


def _signature(der):
    outer = _DER(der)
    values = _DER(outer.take(0x30))
    outer.done()
    signature = bytearray()
    for _ in range(2):
        integer = values.take(0x02)
        if (not integer or len(integer) > 33 or integer[0] & 0x80
                or (len(integer) > 1 and integer[0] == 0 and integer[1] < 128)):
            raise ValueError('invalid DER SM2 scalar')
        scalar = int.from_bytes(integer, 'big')
        if not 1 <= scalar < N:
            raise ValueError('SM2 scalar outside the curve order')
        signature += be32(scalar)
    values.done()
    return bytes(signature)


def _direct_signature(envelope, message, signer_identifier):
    outer = _DER(envelope)
    content_info = _DER(outer.take(0x30))
    outer.done()
    if content_info.take(0x06) != _SIGNED_DATA:
        raise ValueError('expected SM2 SignedData content type')
    tagged = _DER(content_info.take(0xa0))
    content_info.done()
    signed_data = _DER(tagged.take(0x30))
    tagged.done()
    if signed_data.take(0x02) != b'\x01':
        raise ValueError('unsupported SignedData version')
    algorithms = _DER(signed_data.take(0x31))
    _algorithm(algorithms, _SM3)
    algorithms.done()
    encapsulated = _DER(signed_data.take(0x30))
    if encapsulated.take(0x06) != _DATA:
        raise ValueError('expected SM2 data content type')
    if encapsulated.next_is(0xa0):
        attached = _DER(encapsulated.take(0xa0))
        if attached.take(0x04) != message:
            raise ValueError('SignedData content differs from the approved transaction message')
        attached.done()
    encapsulated.done()

    # The caller pins the key and the identifier. Embedded certificates and
    # revocation lists never determine the wallet's authorization key.
    for tag in (0xa0, 0xa1):
        if signed_data.next_is(tag):
            signed_data.take(tag)
    signers = _DER(signed_data.take(0x31))
    signed_data.done()
    signer = _DER(signers.take(0x30))
    signers.done()
    if signer.take(0x02) != b'\x02':
        raise ValueError('expected GB/T 35275-2026 SignerInfo version 2')
    start = signer.position
    signer.take(0x80 if signer.next_is(0x80) else 0x30)
    if signer.data[start:signer.position] != signer_identifier:
        raise ValueError('SignedData signer identifier differs from the configured signer')
    _algorithm(signer, _SM3)
    if signer.next_is(0xa0):
        raise ValueError('signedAttrs signatures cannot authorize the existing payment template')
    _algorithm(signer, _SM2_SIGNATURE, _SM2_WITH_SM3)
    signature = _signature(signer.take(0x04))
    if signer.next_is(0xa1):
        signer.take(0xa1)
    signer.done()
    return signature


def signed_data_signer(signer, key, *, signer_identifier):
    """Adapt signer(message, user_id) returning SignedData to the wallet API.

    Configure the identifier as the complete DER sid field from trusted signer
    configuration. The single-signature payment profile requires a direct
    signature for the exact caller-supplied message and template user ID.
    """
    parse_public(key)
    if not isinstance(signer_identifier, bytes) or not signer_identifier:
        raise ValueError('expected a pinned DER signer identifier')

    def sign(message, user_id):
        if not isinstance(message, bytes) or len(message) != 32 or user_id != USER_ID:
            raise ValueError('expected the template transaction message and SM2 user ID')
        envelope = signer(message, user_id)
        if not isinstance(envelope, bytes):
            raise ValueError('expected a DER SignedData response')
        signature = _direct_signature(envelope, message, signer_identifier)
        if not verify(key, message, signature, user_id):
            raise ValueError('SignedData does not authorize the approved transaction message')
        return signature

    return sign
