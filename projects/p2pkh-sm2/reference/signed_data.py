"""SM2 SignedData verification and the direct payment adapter."""

from calendar import monthrange
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from hashlib import sha256
from itertools import groupby
from types import MappingProxyType

from asn1crypto.core import ObjectIdentifier
from asn1crypto.x509 import Certificate as ASN1Certificate, DirectoryString, Name as ASN1Name
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.x509 import CertificateRevocationList, DirectoryName, DistributionPoint
from cryptography.x509 import IssuingDistributionPoint, Name, ReasonFlags, Version
from cryptography.x509 import DuplicateExtension, ExtensionNotFound, UnrecognizedExtension, UnsupportedGeneralNameType
from cryptography.x509 import load_der_x509_certificate, load_der_x509_crl
from cryptography.x509.oid import CRLEntryExtensionOID, ExtensionOID

from certificate_path import _load_certificate, verify_revocation_paths
from sm2 import N, USER_ID, be32, message_digest, parse_public, sm3, verify, verify_digest


DATA_CONTENT_TYPE = '1.2.156.10197.6.1.4.2.1'
_DATA = ObjectIdentifier(DATA_CONTENT_TYPE).contents
_SIGNED_DATA = bytes.fromhex('2a811ccf550601040202')
_SM3 = bytes.fromhex('2a811ccf55018311')
_SM3_UNKEYED = bytes.fromhex('2a811ccf5501831101')
_SM2_SIGNATURE = bytes.fromhex('2a811ccf5501822d01')
_SM2_WITH_SM3 = bytes.fromhex('2a811ccf55018375')
# Complete DER encodings accepted for the optional envelope parameters field.
_DIGEST_ALGORITHM_PARAMETERS = {
    _SM3: (b'', b'\x05\x00'),
    _SM3_UNKEYED: (b'', b'\x05\x00'),
}
_SIGNATURE_ALGORITHM_PARAMETERS = {
    _SM2_SIGNATURE: (b'', b'\x05\x00'),
}
_EC_PUBLIC_KEY = bytes.fromhex('2a8648ce3d0201')
_CURVE_SM2 = bytes.fromhex('2a811ccf5501822d')
_SM2_X509_SIGNATURE_OIDS = frozenset(ObjectIdentifier(contents=oid).dotted
                                      for oid in (_SM2_SIGNATURE, _SM2_WITH_SM3))
_MESSAGE_DIGEST = ObjectIdentifier('1.2.840.113549.1.9.4').contents  # PKCS #9 messageDigest
_CONTENT_TYPE = ObjectIdentifier('1.2.840.113549.1.9.3').contents  # PKCS #9 contentType
_DIRECTORY_STRING_TAGS = frozenset((0x0c, 0x13, 0x14, 0x1c, 0x1e))
# Naming attribute types and character bounds from RFC 5280 Appendix A.1.
_DIRECTORY_NAME_TYPES = {
    bytes((0x55, 0x04, number)): (name, upper)
    for number, name, upper in (
        (3, 'commonName', 64), (4, 'surname', 32768), (7, 'localityName', 128),
        (8, 'stateOrProvinceName', 128), (10, 'organizationName', 64),
        (11, 'organizationalUnitName', 64), (12, 'title', 64), (41, 'name', 32768),
        (42, 'givenName', 32768), (43, 'initials', 32768), (44, 'generationQualifier', 32768),
        (65, 'pseudonym', 128),
    )
}
_ASCII_NAME_TYPES = {
    b'\x55\x04\x05': ('serialNumber', 0x13, 1, 64),
    b'\x55\x04\x06': ('countryName', 0x13, 2, 2),
    b'\x55\x04\x2e': ('dnQualifier', 0x13, 0, None),
    ObjectIdentifier('0.9.2342.19200300.100.1.25').contents: ('domainComponent', 0x16, 0, None),
    ObjectIdentifier('1.2.840.113549.1.9.1').contents: ('emailAddress', 0x16, 1, 255),
}
_UNICODE_STRINGS = {0x0c: ('UTF8String', 'utf-8'), 0x1c: ('UniversalString', 'utf-32-be'),
                    0x1e: ('BMPString', 'utf-16-be')}
_BASIC_CONSTRAINTS = bytes.fromhex('551d13')
_NAME_CONSTRAINTS = bytes.fromhex('551d1e')
_POLICY_MAPPINGS = bytes.fromhex('551d21')
_POLICY_CONSTRAINTS = bytes.fromhex('551d24')
_ISSUING_DISTRIBUTION_POINT = bytes.fromhex('551d1c')
_ANY_POLICY = bytes.fromhex('551d2000')
_IDENTIFICATION_NUMBERS = {ObjectIdentifier(f'1.2.156.10260.4.1.{number}').contents: f'1.2.156.10260.4.1.{number}'
                           for number in range(2, 6)}
_CERTIFICATE_EXTENSION_TYPES = frozenset((ExtensionOID.POLICY_MAPPINGS.dotted_string,
                                          *_IDENTIFICATION_NUMBERS.values()))
_NUMERIC_STRING = b' 0123456789'
_PRINTABLE_STRING = (b" '()+,-./:=?0123456789"
                     b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz')
# X.690 §10.2 forbids the constructed encoding of restricted character strings.
_CONSTRUCTED_CHARACTER_STRINGS = frozenset((
    0x2c,                          # UTF8String
    0x32, 0x33, 0x34, 0x35, 0x36,   # NumericString through IA5String
    0x39, 0x3a, 0x3b, 0x3c, 0x3e,   # GraphicString through UniversalString, then BMPString
))


class _DER:
    def __init__(self, data, *, budget=None):
        self.data = data
        self.position = 0
        self.budget = budget

    def next_is(self, tag):
        return self.position < len(self.data) and self.data[self.position] == tag

    def take(self, tag=None):
        start = self.position
        if start == len(self.data) or (tag is not None and not self.next_is(tag)):
            raise ValueError('unexpected or truncated SignedData DER field')
        first = self.data[start]
        length_at = start + 1
        if first in (0x00, 0x20):
            raise ValueError('invalid DER tag')
        if first & 0x1f == 0x1f:
            if length_at == len(self.data) or self.data[length_at] < 31 or self.data[length_at] == 0x80:
                raise ValueError('invalid DER tag')
            while length_at < len(self.data) and self.data[length_at] & 0x80:
                length_at += 1
            length_at += 1
        if length_at >= len(self.data):
            raise ValueError('unexpected or truncated SignedData DER field')
        length = self.data[length_at]
        content = length_at + 1
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

    def take_encoded(self, tag=None):
        start = self.position
        self.take(tag)
        return self.data[start:self.position]


class SignedDataLimitsExceeded(ValueError):
    """SignedData exceeded the verifier's local parsing budget."""


# Application resource limits for untrusted SignedData and open DER values.
_MAX_ENVELOPE_BYTES = 8 * 1024 * 1024
_MAX_DETACHED_BYTES = 64 * 1024 * 1024
_MAX_DER_NODES = 65_536
_MAX_DER_DEPTH = 32
_MAX_DER_WORK_BYTES = 64 * 1024 * 1024
_MAX_ATTRIBUTES = 1_024
_MAX_ATTRIBUTE_VALUES = 1_024


@dataclass
class _DERBudget:
    nodes: int = 0
    work: int = 0

    def charge(self, size):
        self.nodes += 1
        self.work += size
        if self.nodes > _MAX_DER_NODES:
            raise SignedDataLimitsExceeded('SignedData DER element limit exceeded')
        if self.work > _MAX_DER_WORK_BYTES:
            raise SignedDataLimitsExceeded('SignedData DER aggregate byte limit exceeded')


def _walk_der(encoded, *, defer_syntax=False, budget=None):
    """Yield TLVs with shared bounds and retain only the current ancestry."""
    stack = [_DER(memoryview(encoded))]
    if budget is None:
        budget = _DERBudget()
    while stack:
        fields = stack[-1]
        if fields.position == len(fields.data):
            stack.pop()
            continue
        start = fields.position
        tag = fields.data[start]
        try:
            value = fields.take()
        except ValueError:
            if not defer_syntax:
                raise
            # Leave field-specific diagnostics to the semantic parser.
            stack.pop()
            continue
        budget.charge(fields.position - start)
        if tag & 0x20 and len(stack) >= _MAX_DER_DEPTH:
            raise SignedDataLimitsExceeded('SignedData DER nesting limit exceeded')
        yield tag, value
        if tag & 0x20 and value:
            stack.append(_DER(value))


class MissingAttributeSchema(ValueError):
    """An AttributeValue's declared ASN.1 type is unavailable."""


class MissingExtensionSchema(ValueError):
    """An X.509 extension's declared ASN.1 type is unavailable."""


class AmbiguousCertificateIssuer(ValueError):
    """An indirect CRL entry needs an authenticated issuer DN selection."""


def _algorithm(fields, allowed_parameters):
    algorithm = _DER(fields.take(0x30))
    oid = algorithm.take(0x06)
    parameters = allowed_parameters.get(oid)
    if parameters is None:
        raise ValueError('unexpected SignedData algorithm')
    if algorithm.data[algorithm.position:] not in parameters:
        raise ValueError('unsupported SignedData algorithm parameters encoding')
    return oid


def _digest_algorithm(fields):
    return _algorithm(fields, _DIGEST_ALGORITHM_PARAMETERS)


def _minimal_integer(value):
    if len(value) < 2:
        return bool(value)
    return not (value[0] == 0 and value[1] < 0x80
                or value[0] == 0xff and value[1] >= 0x80)


def _check_certificate_serial(serial):
    if not _minimal_integer(serial) or serial[0] & 0x80 or not any(serial) or len(serial) > 20:
        raise ValueError('expected a positive certificate serial number of at most 20 octets')


def _signature(der):
    outer = _DER(der)
    values = _DER(outer.take(0x30))
    outer.done()
    signature = bytearray()
    for _ in range(2):
        integer = values.take(0x02)
        if not _minimal_integer(integer) or len(integer) > 33 or integer[0] & 0x80:
            raise ValueError('invalid DER SM2 scalar')
        scalar = int.from_bytes(integer, 'big')
        if not 1 <= scalar < N:
            raise ValueError('SM2 scalar outside the curve order')
        signature += be32(scalar)
    values.done()
    return bytes(signature)


def _check_issuer_and_serial_number(identifier):
    outer = _DER(identifier)
    fields = _DER(outer.take(0x30))
    outer.done()
    try:
        _check_name(fields.take(0x30))
    except ValueError as error:
        raise ValueError(f'invalid DER issuer Name: {error}') from error
    _check_certificate_serial(fields.take(0x02))
    fields.done()


def _check_name(encoded, *, field='issuer'):
    if not encoded:
        raise ValueError(f'empty DER {field} Name')
    name = _DER(encoded)
    while name.position < len(name.data):
        rdn = name.take(0x31)
        if not rdn:
            raise ValueError(f'empty DER {field} RDN')
        for member in _set_members(rdn, 0x30):
            attribute = _DER(_DER(member).take(0x30))
            oid = attribute.take(0x06)
            _check_oid(oid)
            value = attribute.take_encoded()
            _check_open_value(value)
            if oid in _DIRECTORY_NAME_TYPES:
                label, upper = _DIRECTORY_NAME_TYPES[oid]
                if value[0] not in _DIRECTORY_STRING_TAGS:
                    raise ValueError(f'{label} must be a DirectoryString')
                if not 1 <= len(DirectoryString.load(value, strict=True).native) <= upper:
                    raise ValueError(f'{label} must contain 1 to {upper} characters')
            if oid in _ASCII_NAME_TYPES:
                label, tag, minimum, maximum = _ASCII_NAME_TYPES[oid]
                if value[0] != tag:
                    string_type = 'PrintableString' if tag == 0x13 else 'IA5String'
                    raise ValueError(f'{label} must use {string_type}')
                size = len(_DER(value).take(tag))
                if size < minimum or (maximum is not None and size > maximum):
                    raise ValueError(f'{label} has an invalid character count')
            attribute.done()


def _set_members(content, tag=None, *, limit=None):
    fields = _DER(content)
    previous = b''
    count = 0
    while fields.position < len(content):
        count += 1
        if limit is not None and count > limit:
            raise SignedDataLimitsExceeded('SignedData attribute collection limit exceeded')
        encoded = fields.take_encoded(tag)
        if encoded < previous:
            raise ValueError('DER SET OF members out of order')
        yield encoded
        previous = encoded


def _check_oid(oid, name='attribute OID'):
    if (not oid or oid[-1] & 0x80
            or any(octet == 0x80 and (index == 0 or oid[index - 1] < 0x80)
                   for index, octet in enumerate(oid))):
        raise ValueError(f'invalid DER {name}')


def _check_bit_string(value):
    if not value or value[0] > 7:
        raise ValueError('invalid DER BIT STRING')
    unused = value[0]
    if unused and (len(value) == 1 or value[-1] & ((1 << unused) - 1)):
        raise ValueError('invalid DER BIT STRING')


def _check_open_value(encoded, *, budget=None):
    for tag, value in _walk_der(encoded, budget=budget):
        if tag == 0x21 or (tag == 0x01 and value not in (b'\x00', b'\xff')):
            raise ValueError('invalid DER BOOLEAN')
        if tag == 0x22 or (tag == 0x02 and not _minimal_integer(value)):
            raise ValueError('invalid DER INTEGER')
        if tag == 0x03:
            _check_bit_string(value)
        if tag == 0x23:
            raise ValueError('invalid DER BIT STRING')
        if tag == 0x24:
            raise ValueError('invalid DER OCTET STRING')
        if tag == 0x25 or (tag == 0x05 and value):
            raise ValueError('invalid DER NULL')
        if tag == 0x06:
            _check_oid(value)
        if tag == 0x26:
            raise ValueError('invalid DER attribute OID')
        if tag == 0x0d:
            _check_oid(value, 'RELATIVE-OID')
        if tag == 0x2d:
            raise ValueError('invalid DER RELATIVE-OID')
        if tag == 0x2a or (tag == 0x0a and not _minimal_integer(value)):
            raise ValueError('invalid DER ENUMERATED')
        if tag in (0x10, 0x11):
            raise ValueError('DER SEQUENCE and SET must be constructed')
        if tag in _CONSTRUCTED_CHARACTER_STRINGS:
            raise ValueError('DER character strings must be primitive')
        if tag in _UNICODE_STRINGS:
            label, encoding = _UNICODE_STRINGS[tag]
            try:
                decoded = bytes(value).decode(encoding)
            except UnicodeDecodeError as error:
                raise ValueError(f'invalid DER {label}') from error
            if tag == 0x1e and any(ord(character) > 0xffff for character in decoded):
                raise ValueError('invalid DER BMPString')
        if tag == 0x12 and any(octet not in _NUMERIC_STRING for octet in value):
            raise ValueError('invalid DER NumericString')
        if tag == 0x13 and any(octet not in _PRINTABLE_STRING for octet in value):
            raise ValueError('invalid DER PrintableString')
        if tag == 0x16 and not bytes(value).isascii():
            raise ValueError('invalid DER IA5String')
        if tag == 0x1a and any(not 0x20 <= octet <= 0x7e for octet in value):
            raise ValueError('invalid DER VisibleString')
        if tag in (0x17, 0x18):
            _check_der_time(tag, bytes(value))
        if tag in (0x37, 0x38):
            raise ValueError('DER times must be primitive')


def _check_schema_der(schema, encoded, label):
    try:
        value = schema.load(encoded, strict=True)
        if value.dump(force=True) != encoded:
            raise ValueError('value is not the canonical encoding of its ASN.1 type')
    except ValueError as error:
        raise ValueError(f'invalid DER value for {label}: {error}') from error


def _message_digest_octets(encoded):
    value = _DER(encoded)
    digest = value.take(0x04)
    value.done()
    if len(digest) != 32:
        raise ValueError('messageDigest must contain 32 SM3 octets')
    return digest


def _content_type_attribute_oid(values):
    if len(values) != 1:
        raise ValueError('contentType must have one OBJECT IDENTIFIER value')
    value = _DER(values[0])
    oid = value.take(0x06)
    value.done()
    _check_oid(oid, 'contentType OID')
    return oid


def _check_attribute_schema(oid, values, schemas):
    if oid == _MESSAGE_DIGEST:
        if len(values) != 1:
            raise ValueError('messageDigest must have one OCTET STRING value')
        _message_digest_octets(values[0])
        return
    if oid == _CONTENT_TYPE:
        _content_type_attribute_oid(values)

    identifier = ObjectIdentifier(contents=oid).dotted
    schema = schemas.get(identifier)
    if schema is None:
        if oid == _CONTENT_TYPE:
            return
        raise MissingAttributeSchema(f'missing ASN.1 schema for SignedData attribute {identifier}')
    for encoded in values:
        _check_schema_der(schema, encoded, f'SignedData attribute {identifier}')


def _attribute(encoded, schemas=None):
    attribute = _DER(_DER(encoded).take(0x30))
    oid = attribute.take(0x06)
    _check_oid(oid)
    values = tuple(_set_members(attribute.take(0x31), limit=_MAX_ATTRIBUTE_VALUES))
    for value in values:
        _check_open_value(value)
    attribute.done()
    if schemas is not None:
        _check_attribute_schema(oid, values, schemas)
    return oid, values


def _check_x509_signature(tbs, outer):
    inner = tbs.take_encoded(0x30)
    if inner != outer.take_encoded(0x30):
        raise ValueError('inner and outer signature algorithm identifiers differ')
    algorithm = _DER(_DER(inner).take(0x30))
    oid = algorithm.take(0x06)
    if oid in (_SM2_SIGNATURE, _SM2_WITH_SM3):
        if algorithm.position != len(algorithm.data):
            raise ValueError('SM2 certificate and CRL signature algorithm parameters must be absent')
        signature_bits = outer.take(0x03)
        if not signature_bits or signature_bits[0] != 0:
            raise ValueError('SM2 certificate and CRL signature BIT STRING must be octet-aligned')
        try:
            _signature(signature_bits[1:])
        except ValueError as error:
            raise ValueError(f'invalid X.509 SM2Signature: {error}') from error


def _check_der_time(tag, value, *, allow_fraction=True):
    digits, point, fraction = value[:-1].partition(b'.')
    utc = tag == 0x17
    if len(digits) != (12 if utc else 14) or value[-1:] != b'Z' or not digits.isdigit():
        raise ValueError('invalid DER time encoding, expected UTC with seconds')
    if point and (utc or not allow_fraction or not fraction.isdigit() or fraction.endswith(b'0')):
        raise ValueError('invalid DER time fraction')
    year_digits, clock = digits[:-10], digits[-10:]
    year = int(year_digits)
    if utc:
        year += 1900 if year >= 50 else 2000
    month, day, hour, minute, second = (int(clock[offset:offset + 2]) for offset in range(0, 10, 2))
    if not 1 <= month <= 12:
        raise ValueError('invalid DER calendar date')
    last_day = monthrange(year, month)[1]
    if not 1 <= day <= last_day:
        raise ValueError('invalid DER calendar date')
    if hour > 23 or minute > 59 or second > 60 or (second == 60 and (day, hour, minute) != (last_day, 23, 59)):
        raise ValueError('invalid DER clock time')
    return year, clock


def _check_x509_time(fields):
    tag = 0x17 if fields.next_is(0x17) else 0x18
    value = fields.take(tag)
    try:
        time = _check_der_time(tag, value, allow_fraction=False)
    except ValueError as error:
        raise ValueError(f'invalid X.509 time encoding: {error}') from error
    if tag == 0x18 and time[0] < 2050:
        raise ValueError('X.509 dates before 2050 must use UTCTime')
    return time


def _check_certificate_extension_value(oid, critical, encoded):
    if oid == _BASIC_CONSTRAINTS:
        constraints = _DER(_DER(encoded).take(0x30))
        if constraints.next_is(0x01) and constraints.take(0x01) == b'\x00':
            raise ValueError('basicConstraints cA FALSE must be omitted in DER')
    elif oid == _POLICY_MAPPINGS:
        mappings = _DER(_DER(encoded).take(0x30))
        if not mappings.data:
            raise ValueError('policyMappings must contain at least one mapping')
        while mappings.position < len(mappings.data):
            mapping = _DER(mappings.take(0x30))
            for _ in range(2):
                policy = mapping.take(0x06)
                _check_oid(policy, 'policy OID')
                if policy == _ANY_POLICY:
                    raise ValueError('policyMappings must not contain anyPolicy')
            mapping.done()
    elif oid == _NAME_CONSTRAINTS:
        constraints = _DER(_DER(encoded).take(0x30))
        for tag in (0xa0, 0xa1):
            if not constraints.next_is(tag):
                continue
            subtrees = _DER(constraints.take(tag))
            if not subtrees.data:
                raise ValueError('nameConstraints must contain at least one subtree in each present field')
            while subtrees.position < len(subtrees.data):
                subtree = _DER(subtrees.take(0x30))
                subtree.take()  # GeneralName base, parsed by the X.509 decoder.
                if subtree.next_is(0x80) or subtree.next_is(0x81):
                    raise ValueError('nameConstraints minimum and maximum must be omitted')
                subtree.done()
        constraints.done()
    elif oid == _POLICY_CONSTRAINTS:
        constraints = _DER(_DER(encoded).take(0x30))
        for tag in (0x80, 0x81):
            if constraints.next_is(tag):
                value = constraints.take(tag)
                if not _minimal_integer(value) or value[0] & 0x80:
                    raise ValueError('policyConstraints SkipCerts must be a nonnegative DER INTEGER')
        constraints.done()
    elif oid in _IDENTIFICATION_NUMBERS:
        if critical:
            raise ValueError('GB/T 20518 identification number extensions must be noncritical')
        value = _DER(encoded)
        if not value.next_is(0x13):
            raise ValueError('GB/T 20518 identification number extensions require PrintableString')
        value.take(0x13)
        value.done()


def _check_crl_extension_value(oid, _critical, encoded):
    if oid == _ISSUING_DISTRIBUTION_POINT:
        fields = _DER(_DER(encoded).take(0x30))
        if fields.next_is(0xa0):
            fields.take(0xa0)
        for tag in (0x81, 0x82, 0x83, 0x84, 0x85):
            if not fields.next_is(tag):
                continue
            value = fields.take(tag)
            if tag == 0x83:
                _check_bit_string(value)
            elif value != b'\xff':
                raise ValueError('issuingDistributionPoint BOOLEAN flags must be TRUE or omitted in DER')
        fields.done()


def _check_extensions(encoded, *, check_value=None, schemas=None, budget=None):
    outer = _DER(encoded)
    extensions = _DER(outer.take(0x30))
    outer.done()
    seen = set()
    while extensions.position < len(extensions.data):
        entry = _DER(extensions.take(0x30))
        oid = entry.take(0x06)
        _check_oid(oid, 'extension OID')
        if oid in seen:
            raise ValueError('duplicate X.509 extension OID')
        seen.add(oid)
        critical = entry.next_is(0x01)
        if critical and entry.take(0x01) != b'\xff':
            raise ValueError('X.509 extension critical must be TRUE or omitted')
        value = _DER(entry.take(0x04))
        encoded_value = value.take_encoded()
        _check_open_value(encoded_value, budget=budget)
        value.done()
        entry.done()
        if check_value is not None:
            check_value(oid, critical, encoded_value)
        if schemas is not None:
            identifier = ObjectIdentifier(contents=oid).dotted
            if identifier in schemas:
                _check_schema_der(schemas[identifier], encoded_value, f'X.509 extension {identifier}')
    if not seen:
        raise ValueError('empty X.509 Extensions')


def _require_extension_schemas(extensions, schemas, *, locally_decoded=()):
    if schemas is None:
        return
    for extension in extensions:
        if isinstance(extension.value, UnrecognizedExtension):
            identifier = extension.oid.dotted_string
            if identifier not in schemas and identifier not in locally_decoded:
                raise MissingExtensionSchema(f'missing ASN.1 schema for X.509 extension {identifier}')


def _check_certificate_profile(extensions, *, subject_present):
    fields = {extension.oid: extension for extension in extensions}
    authority_key = fields.get(ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
    subject_key = fields.get(ExtensionOID.SUBJECT_KEY_IDENTIFIER)
    for extension, name in ((authority_key, 'authorityKeyIdentifier'), (subject_key, 'subjectKeyIdentifier')):
        if extension is not None and extension.critical:
            raise ValueError(f'{name} must be noncritical')

    names = fields.get(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    if names is not None and not len(names.value):
        raise ValueError('subjectAltName must contain at least one name')
    if names is not None and any(not name.value for name in names.value):
        raise ValueError('subjectAltName must not contain an empty name')
    if not subject_present and (names is None or not names.critical):
        raise ValueError('empty certificate subject requires critical subjectAltName')

    for oid, name in ((ExtensionOID.ISSUER_ALTERNATIVE_NAME, 'issuerAltName'),
                      (ExtensionOID.CRL_DISTRIBUTION_POINTS, 'cRLDistributionPoints'),
                      (ExtensionOID.FRESHEST_CRL, 'freshestCRL')):
        extension = fields.get(oid)
        if extension is not None and not len(extension.value):
            raise ValueError(f'{name} must contain at least one entry')
    for oid, name in ((ExtensionOID.AUTHORITY_INFORMATION_ACCESS, 'authorityInfoAccess'),
                      (ExtensionOID.SUBJECT_INFORMATION_ACCESS, 'subjectInformationAccess')):
        extension = fields.get(oid)
        if extension is not None:
            if extension.critical:
                raise ValueError(f'{name} must be noncritical')
            if not len(extension.value):
                raise ValueError(f'{name} must contain at least one access description')

    basic = fields.get(ExtensionOID.BASIC_CONSTRAINTS)
    usage = fields.get(ExtensionOID.KEY_USAGE)
    is_ca = basic is not None and basic.value.ca
    can_sign_certificates = usage is not None and usage.value.key_cert_sign
    if is_ca:
        if not subject_present:
            raise ValueError('CA certificate requires a nonempty subject')
        if not basic.critical:
            raise ValueError('CA basicConstraints must be critical')
        if subject_key is None:
            raise ValueError('CA certificate requires subjectKeyIdentifier')
        if not can_sign_certificates:
            raise ValueError('CA certificate requires keyCertSign in keyUsage')
    elif can_sign_certificates:
        raise ValueError('keyCertSign requires basicConstraints cA TRUE')
    if not is_ca:
        for oid, name in ((ExtensionOID.NAME_CONSTRAINTS, 'nameConstraints'),
                          (ExtensionOID.POLICY_MAPPINGS, 'policyMappings'),
                          (ExtensionOID.POLICY_CONSTRAINTS, 'policyConstraints')):
            if oid in fields:
                raise ValueError(f'{name} requires a CA certificate')


def _check_certificate(encoded, *, profile=False, schemas=None, budget=None):
    fields = _DER(_DER(encoded).take(0x30))
    tbs = _DER(fields.take(0x30))
    version = b'\x00'
    if tbs.next_is(0xa0):
        version_field = _DER(tbs.take(0xa0))
        version = version_field.take(0x02)
        version_field.done()
        if version not in (b'\x01', b'\x02'):
            raise ValueError('expected certificate v2, v3, or omitted v1 default')
    _check_certificate_serial(tbs.take(0x02))
    _check_x509_signature(tbs, fields)
    issuer = tbs.take(0x30)
    if not issuer:
        raise ValueError('empty certificate issuer Name')
    _check_name(issuer)
    validity = _DER(tbs.take(0x30))
    not_before = _check_x509_time(validity)
    not_after = _check_x509_time(validity)
    validity.done()
    if not_before > not_after:
        raise ValueError('certificate notBefore is later than notAfter')
    subject = tbs.take(0x30)
    if subject:
        _check_name(subject, field='subject')
    tbs.take(0x30)  # SubjectPublicKeyInfo.
    for identifier_tag in (0x81, 0x82):
        if tbs.next_is(identifier_tag):
            if version == b'\x00':
                raise ValueError('certificate unique identifiers require v2 or v3')
            _check_bit_string(tbs.take(identifier_tag))
    if tbs.next_is(0xa3):
        if version != b'\x02':
            raise ValueError('certificate extensions require v3')
        _check_extensions(tbs.take(0xa3), check_value=_check_certificate_extension_value if profile else None,
                          schemas=schemas, budget=budget)
    tbs.done()
    if version == b'\x01':
        # GB/T 20518 permits v2, which cryptography's certificate loader rejects.
        # Decode the original bytes, including the unique identifier fields.
        ASN1Certificate.load(encoded, strict=True).native
        if profile:
            _check_certificate_profile((), subject_present=bool(subject))
        return
    certificate = load_der_x509_certificate(encoded)
    if not certificate.issuer.rdns:
        raise ValueError('empty certificate issuer Name')
    try:
        # The X.509 decoder parses known extension values on access.
        extensions = certificate.extensions
    except UnsupportedGeneralNameType as error:
        raise ValueError(f'invalid X.509 certificate extension: {error}') from error
    if profile:
        _check_certificate_profile(extensions, subject_present=bool(subject))
    locally_decoded = _CERTIFICATE_EXTENSION_TYPES if profile else ()
    _require_extension_schemas(extensions, schemas, locally_decoded=locally_decoded)


def _check_crl_profile(extensions):
    fields = {extension.oid: extension for extension in extensions}
    authority_key = fields.get(ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
    if authority_key is not None and authority_key.critical:
        raise ValueError('authorityKeyIdentifier must be noncritical')
    issuer_names = fields.get(ExtensionOID.ISSUER_ALTERNATIVE_NAME)
    if issuer_names is not None and not len(issuer_names.value):
        raise ValueError('issuerAltName must contain at least one name')

    for oid, name, critical in ((ExtensionOID.CRL_NUMBER, 'cRLNumber', False),
                                (ExtensionOID.DELTA_CRL_INDICATOR, 'deltaCRLIndicator', True)):
        extension = fields.get(oid)
        if extension is None:
            continue
        if extension.critical != critical:
            raise ValueError(f'{name} must be {"critical" if critical else "noncritical"}')
        number = extension.value.crl_number
        if number < 0 or number.bit_length() > 159:
            # A 160-bit nonnegative DER INTEGER needs a leading sign octet.
            raise ValueError(f'{name} requires a nonnegative DER INTEGER of at most 20 octets')
    distribution = fields.get(ExtensionOID.ISSUING_DISTRIBUTION_POINT)
    if distribution is not None and not distribution.critical:
        raise ValueError('issuingDistributionPoint must be critical')
    delta = fields.get(ExtensionOID.DELTA_CRL_INDICATOR)
    if delta is not None:
        number = fields.get(ExtensionOID.CRL_NUMBER)
        if number is None:
            raise ValueError('delta CRL requires cRLNumber')
        if number.value.crl_number <= delta.value.crl_number:
            raise ValueError('delta CRL number must be greater than its BaseCRLNumber')
    freshest = fields.get(ExtensionOID.FRESHEST_CRL)
    if freshest is not None:
        if delta is not None:
            raise ValueError('freshestCRL must not appear on a delta CRL')
        if freshest.critical:
            raise ValueError('freshestCRL must be noncritical')
        if not len(freshest.value):
            raise ValueError('freshestCRL must contain at least one distribution point')
        if any(point.reasons is not None or point.crl_issuer is not None for point in freshest.value):
            raise ValueError('freshestCRL distribution points must omit reasons and cRLIssuer')
    return delta is not None


def _check_crl_entry_profile(serial, extensions, *, is_delta):
    if serial <= 0 or serial.bit_length() > 159:
        raise ValueError('revoked certificate serial number must be positive and at most 20 DER octets')
    fields = {extension.oid: extension for extension in extensions}
    reason = fields.get(CRLEntryExtensionOID.CRL_REASON)
    if reason is not None:
        if reason.critical:
            raise ValueError('reasonCode must be noncritical')
        if reason.value.reason == ReasonFlags.remove_from_crl and not is_delta:
            raise ValueError('removeFromCRL requires a delta CRL')
    invalidity = fields.get(CRLEntryExtensionOID.INVALIDITY_DATE)
    if invalidity is not None and invalidity.critical:
        raise ValueError('invalidityDate must be noncritical')
    issuer = fields.get(CRLEntryExtensionOID.CERTIFICATE_ISSUER)
    if issuer is not None and not len(issuer.value):
        raise ValueError('certificateIssuer must contain at least one name')


def _check_crl(encoded, *, profile=False, schemas=None, budget=None):
    fields = _DER(_DER(encoded).take(0x30))
    tbs = _DER(fields.take(0x30))
    version_2 = tbs.next_is(0x02)
    if version_2 and tbs.take(0x02) != b'\x01':
        raise ValueError('expected CRL v2 or omitted v1 version')
    _check_x509_signature(tbs, fields)
    _check_name(tbs.take(0x30))
    this_update = _check_x509_time(tbs)
    if not tbs.next_is(0x17) and not tbs.next_is(0x18):
        raise ValueError('missing CRL nextUpdate')
    next_update = _check_x509_time(tbs)
    if this_update > next_update:
        raise ValueError('CRL thisUpdate is later than nextUpdate')
    if tbs.next_is(0x30):
        revoked = _DER(tbs.take(0x30))
        if profile and not revoked.data:
            raise ValueError('empty CRL revokedCertificates must be omitted')
        while revoked.position < len(revoked.data):
            entry = _DER(revoked.take(0x30))
            entry.take(0x02)  # userCertificate.
            _check_x509_time(entry)  # revocationDate.
            if entry.next_is(0x30):
                if not version_2:
                    raise ValueError('revoked certificate extensions require CRL v2')
                _check_extensions(entry.take_encoded(0x30), schemas=schemas, budget=budget)
            entry.done()
    if tbs.next_is(0xa0):
        if not version_2:
            raise ValueError('CRL extensions require v2')
        _check_extensions(tbs.take(0xa0), check_value=_check_crl_extension_value if profile else None,
                          schemas=schemas, budget=budget)
    tbs.done()
    crl = load_der_x509_crl(encoded)
    if not crl.issuer.rdns:
        raise ValueError('empty CRL issuer Name')
    try:
        extensions = crl.extensions
        is_delta = _check_crl_profile(extensions) if profile else False
        for entry in crl:
            entry_extensions = entry.extensions
            if profile:
                _check_crl_entry_profile(entry.serial_number, entry_extensions, is_delta=is_delta)
            _require_extension_schemas(entry_extensions, schemas)
    except UnsupportedGeneralNameType as error:
        raise ValueError(f'invalid X.509 revocation extension: {error}') from error
    _require_extension_schemas(extensions, schemas)
    return crl


def _issuer_key(issuer):
    # Preserve RDN order and multiplicity while matching DirectoryString and
    # domainComponent attributes according to RFC 5280 §§7.1 and 7.3.
    name = ASN1Name.load(issuer.public_bytes(), strict=True)
    key = []
    for rdn in name.chosen:
        attributes = []
        for attribute in rdn:
            oid, value = attribute['type'], attribute['value']
            if isinstance(value, DirectoryString):
                canonical = attribute.prepped_value.encode('utf-8')
            elif oid.native == 'domain_component':
                canonical = value.native.lower().encode('ascii')
            else:
                canonical = value.dump()
            attributes.append((oid.dotted, canonical))
        key.append(tuple(sorted(attributes)))
    return tuple(key)


@dataclass(frozen=True)
class _CRLRevision:
    issuer: tuple
    scope: bytes | None
    issued: datetime
    number: int
    base: int | None
    crl: CertificateRevocationList


def _crl_revision(encoded, schemas):
    if not isinstance(encoded, bytes):
        raise ValueError('expected a DER CRL')
    crl = _check_crl(encoded, profile=True, schemas=schemas)
    extensions = {extension.oid: extension.value for extension in crl.extensions}
    number = extensions.get(ExtensionOID.CRL_NUMBER)
    if number is None:
        raise ValueError('CRL revision requires cRLNumber')
    delta = extensions.get(ExtensionOID.DELTA_CRL_INDICATOR)
    scope = extensions.get(ExtensionOID.ISSUING_DISTRIBUTION_POINT)
    return _CRLRevision(_issuer_key(crl.issuer), scope.public_bytes() if scope is not None else None,
                        crl.last_update_utc, number.crl_number, delta.crl_number if delta is not None else None, crl)


def _check_crl_numbering(revisions):
    if not revisions:
        raise ValueError('expected at least one CRL revision')
    issuer = revisions[0].issuer
    scope = revisions[0].scope
    if any(revision.issuer != issuer for revision in revisions):
        raise ValueError('CRL revisions must have the same issuer name')
    if any(revision.scope != scope for revision in revisions):
        raise ValueError('CRL revisions must have the same issuing distribution point scope')

    by_time = sorted(revisions, key=lambda revision: revision.issued)
    previous_max = -1
    for _, members in groupby(by_time, key=lambda revision: revision.issued):
        bucket = list(members)
        numbers = {revision.number for revision in bucket}
        kinds = {revision.base is not None for revision in bucket}
        if len(kinds) > 1 and len(numbers) > 1:
            raise ValueError('complete and delta CRLs issued at the same time must have the same number')
        if min(numbers) <= previous_max:
            raise ValueError('CRL numbers must increase with thisUpdate for the same issuer and scope')
        previous_max = max(numbers)


def validate_crl_series(crls, *, extension_schemas=None):
    """Check issuance numbering for one caller-selected issuer and scope.

    Supply DER CRLs in any order. The caller authenticates the issuer and
    provides the relevant objects. This check compares issuance metadata.
    """
    _check_crl_numbering([_crl_revision(encoded, extension_schemas) for encoded in crls])


def _validated_crl_pair(complete_crl, delta_crl, extension_schemas):
    complete = _crl_revision(complete_crl, extension_schemas)
    delta = _crl_revision(delta_crl, extension_schemas)
    if complete.base is not None or delta.base is None:
        raise ValueError('expected a complete CRL followed by a delta CRL')
    if not delta.base <= complete.number < delta.number:
        raise ValueError('complete CRL number must be at least BaseCRLNumber and below the delta CRL number')
    _check_crl_numbering((complete, delta))
    return complete, delta


def _extension_value(extensions, oid):
    try:
        return extensions.get_extension_for_oid(oid).value
    except ExtensionNotFound:
        return None


def _revocation_certificate(encoded, role):
    """Decode a certificate and report unsupported or invalid extensions as ValueError."""
    certificate = _load_certificate(encoded, role)
    try:
        # Known extension values are decoded on first access.
        certificate.extensions
    except (DuplicateExtension, UnsupportedGeneralNameType, ValueError) as error:
        raise ValueError(f'invalid {role} certificate extension: {error}') from error
    return certificate


def _crl_signer_certificate(encoded):
    certificate = _revocation_certificate(encoded, 'CRL issuer')
    if not certificate.subject.rdns:
        raise ValueError('CRL issuer certificate requires a nonempty subject')
    usage = _extension_value(certificate.extensions, ExtensionOID.KEY_USAGE)
    if usage is not None and not usage.crl_sign:
        raise ValueError('CRL issuer certificate keyUsage must allow cRLSign')
    return certificate


def _check_crl_signer_identifier(crl, certificate):
    if _issuer_key(crl.issuer) != _issuer_key(certificate.subject):
        raise ValueError('CRL issuer name must match the signing certificate subject')
    authority = _extension_value(crl.extensions, ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
    if authority is None:
        return
    subject_key = _extension_value(certificate.extensions, ExtensionOID.SUBJECT_KEY_IDENTIFIER)
    if (authority.key_identifier is not None and subject_key is not None
            and authority.key_identifier != subject_key.digest):
        raise ValueError('CRL authority key identifier must match the signing certificate subject key identifier')
    if authority.authority_cert_serial_number is not None:
        issuer = _issuer_key(certificate.issuer)
        alternatives = _extension_value(certificate.extensions, ExtensionOID.ISSUER_ALTERNATIVE_NAME)
        names_match = any((isinstance(name, DirectoryName) and _issuer_key(name.value) == issuer)
                          or (alternatives is not None and name in alternatives)
                          for name in authority.authority_cert_issuer)
        if authority.authority_cert_serial_number != certificate.serial_number or not names_match:
            raise ValueError('CRL authority certificate issuer and serial must match the signing certificate')


def _sm2_certificate_public_key(encoded):
    certificate = ASN1Certificate.load(encoded, strict=True)
    spki = _DER(_DER(certificate['tbs_certificate']['subject_public_key_info'].dump()).take(0x30))
    algorithm = _DER(spki.take(0x30))
    if algorithm.take(0x06) != _EC_PUBLIC_KEY or not algorithm.next_is(0x06) or algorithm.take(0x06) != _CURVE_SM2:
        raise ValueError('SM2 CRL requires a signing certificate with an id-ecPublicKey on curveSM2')
    algorithm.done()
    bits = spki.take(0x03)
    spki.done()
    if bits[:1] != b'\x00':
        raise ValueError('curveSM2 public key BIT STRING must be octet-aligned')
    key = bits[1:]
    parse_public(key)
    return key


def _verify_crl_with_certificate(crl, certificate, certificate_der, sm2_user_id):
    _check_crl_signer_identifier(crl, certificate)
    if crl.signature_algorithm_oid.dotted_string in _SM2_X509_SIGNATURE_OIDS:
        if not isinstance(sm2_user_id, bytes) or len(sm2_user_id) > 8191:
            raise ValueError('SM2 CRL verification requires an explicit SM2 signer ID of at most 8191 bytes')
        key = _sm2_certificate_public_key(certificate_der)
        valid = verify(key, crl.tbs_certlist_bytes, _signature(crl.signature), sm2_user_id)
    else:
        try:
            valid = crl.is_signature_valid(certificate.public_key())
        except (TypeError, UnsupportedAlgorithm) as error:
            raise ValueError('unsupported CRL signature algorithm or signing certificate key') from error
    if not valid:
        raise ValueError('invalid CRL signature for the authorized signing certificate')


def verify_crl_signature(crl, issuer_certificate, *, sm2_user_id=None, extension_schemas=None):
    """Verify a DER CRL using a caller-authenticated DER issuer certificate.

    The caller supplies a certificate authorized for the intended CRL scope
    and its configured SM2 signer ID when the signature algorithm is SM2.
    """
    if not isinstance(crl, bytes):
        raise ValueError('expected a DER CRL')
    certificate = _crl_signer_certificate(issuer_certificate)
    parsed_crl = _check_crl(crl, profile=True, schemas=extension_schemas)
    _verify_crl_with_certificate(parsed_crl, certificate, issuer_certificate, sm2_user_id)


def validate_crl_pair(complete_crl, delta_crl, *, extension_schemas=None):
    """Check whether the supplied complete CRL can be updated by the delta.

    The caller authenticates both CRLs with the same authorized signing key.
    The function checks the metadata for combining the two DER CRLs.
    """
    _validated_crl_pair(complete_crl, delta_crl, extension_schemas)


@dataclass(frozen=True)
class CRLRevocation:
    revocation_date: datetime
    reason: ReasonFlags
    invalidity_date: datetime | None


@dataclass(frozen=True)
class CRLRevocationSnapshot:
    number: int
    this_update: datetime
    next_update: datetime
    issuing_distribution_point: bytes | None
    _entries: Mapping[tuple, CRLRevocation] = field(repr=False)
    issuer: Name | None = None
    _distribution: IssuingDistributionPoint | None = field(default=None, repr=False)
    _authenticated: bool = field(default=False, repr=False)
    _issuer_certificate: bytes | None = field(default=None, repr=False)
    _signer_key_id: bytes | None = field(default=None, repr=False)

    def revocation_for(self, issuer: Name, serial_number: int) -> CRLRevocation | None:
        """Return the entry in this scope, or None when the issuer and serial are absent."""
        return self._entries.get((_issuer_key(issuer), serial_number))


def _certificate_issuer_key(extension, serial, issuer_resolver):
    names = extension.value.get_values_for_type(DirectoryName)
    if not names or any(not name.rdns for name in names):
        raise ValueError('certificateIssuer requires a nonempty directoryName for revocation lookup')
    candidates = {_issuer_key(name): name for name in names}
    if len(candidates) == 1:
        return next(iter(candidates))
    if issuer_resolver is None:
        raise AmbiguousCertificateIssuer('certificateIssuer has multiple directoryNames; supply an issuer resolver')
    chosen = issuer_resolver(serial, tuple(candidates.values()))
    key = _issuer_key(chosen) if isinstance(chosen, Name) else None
    if key not in candidates:
        raise AmbiguousCertificateIssuer('issuer resolver must select a directoryName from certificateIssuer')
    return key


def _crl_revocations(revision, issuer_resolver):
    extensions = {extension.oid: extension for extension in revision.crl.extensions}
    for extension in extensions.values():
        if extension.critical and extension.oid not in (ExtensionOID.ISSUING_DISTRIBUTION_POINT,
                                                        ExtensionOID.DELTA_CRL_INDICATOR,
                                                        ExtensionOID.ISSUER_ALTERNATIVE_NAME):
            raise ValueError(f'unsupported critical CRL extension {extension.oid.dotted_string}')
    distribution = extensions.get(ExtensionOID.ISSUING_DISTRIBUTION_POINT)
    indirect = distribution is not None and distribution.value.indirect_crl
    issuer = revision.issuer
    entries = {}
    for entry in revision.crl:
        fields = {extension.oid: extension for extension in entry.extensions}
        for extension in fields.values():
            if extension.critical and extension.oid != CRLEntryExtensionOID.CERTIFICATE_ISSUER:
                raise ValueError(f'unsupported critical revoked-entry extension {extension.oid.dotted_string}')
        certificate_issuer = fields.get(CRLEntryExtensionOID.CERTIFICATE_ISSUER)
        if certificate_issuer is not None:
            if not indirect or not certificate_issuer.critical:
                raise ValueError('certificateIssuer must be critical and appear only in an indirect CRL')
            issuer = _certificate_issuer_key(certificate_issuer, entry.serial_number, issuer_resolver)
        key = issuer, entry.serial_number
        if key in entries:
            raise ValueError('duplicate revoked entry for the same issuer and serial number')
        reason = fields.get(CRLEntryExtensionOID.CRL_REASON)
        invalidity = fields.get(CRLEntryExtensionOID.INVALIDITY_DATE)
        entries[key] = CRLRevocation(entry.revocation_date_utc,
                                     reason.value.reason if reason is not None else ReasonFlags.unspecified,
                                     invalidity.value.invalidity_date_utc if invalidity is not None else None)
    return entries


def _certificate_key_id(encoded):
    certificate = ASN1Certificate.load(encoded, strict=True)
    return sha256(certificate['tbs_certificate']['subject_public_key_info'].dump()).digest()


def _crl_snapshot(revision, entries, *, issuer_certificate):
    crl = revision.crl
    distribution = _extension_value(crl.extensions, ExtensionOID.ISSUING_DISTRIBUTION_POINT)
    return CRLRevocationSnapshot(revision.number, revision.issued, crl.next_update_utc,
                                 revision.scope, MappingProxyType(entries), crl.issuer,
                                 distribution, issuer_certificate is not None, issuer_certificate,
                                 _certificate_key_id(issuer_certificate) if issuer_certificate is not None else None)


def load_crl_snapshot(crl, issuer_certificate, *, sm2_user_id=None, issuer_resolver=None, extension_schemas=None):
    """Authenticate a numbered complete CRL and return its revocation snapshot."""
    revision = _crl_revision(crl, extension_schemas)
    if revision.base is not None:
        raise ValueError('a delta CRL requires a compatible complete CRL')
    certificate = _crl_signer_certificate(issuer_certificate)
    _verify_crl_with_certificate(revision.crl, certificate, issuer_certificate, sm2_user_id)
    return _crl_snapshot(revision, _crl_revocations(revision, issuer_resolver), issuer_certificate=issuer_certificate)


def merge_crl_revocations(complete_crl, delta_crl, *, published_crl=None, issuer_resolver=None,
                          issuer_certificate=None, sm2_user_id=None, extension_schemas=None):
    """Return the revocation snapshot for a complete CRL and a compatible delta.

    Supply an authenticated issuer certificate to verify every supplied CRL
    against its key, or authenticate the CRLs externally before calling.
    When published_crl is supplied, compare it to the merged state at the
    delta's number and thisUpdate. An issuer_resolver(serial, names) can
    select an authenticated Name for an indirect entry with multiple DNs.
    """
    complete, delta = _validated_crl_pair(complete_crl, delta_crl, extension_schemas)
    authority_key = ExtensionOID.AUTHORITY_KEY_IDENTIFIER
    if _extension_value(complete.crl.extensions, authority_key) != _extension_value(delta.crl.extensions, authority_key):
        raise ValueError('complete and delta CRL authority key identifiers must match')
    revisions = (complete, delta)
    published = None
    if published_crl is not None:
        published = _crl_revision(published_crl, extension_schemas)
        if published.base is not None or published.issued != delta.issued or published.number != delta.number:
            raise ValueError('expected a published complete CRL with the delta CRL number and thisUpdate')
        revisions += (published,)
        _check_crl_numbering(revisions)
    if issuer_certificate is not None:
        certificate = _crl_signer_certificate(issuer_certificate)
        for revision in revisions:
            _verify_crl_with_certificate(revision.crl, certificate, issuer_certificate, sm2_user_id)
    elif sm2_user_id is not None:
        raise ValueError('SM2 signer ID requires an issuer certificate for CRL verification')

    entries = _crl_revocations(complete, issuer_resolver)
    for key, revocation in _crl_revocations(delta, issuer_resolver).items():
        if revocation.reason == ReasonFlags.remove_from_crl:
            entries.pop(key, None)
        else:
            entries[key] = revocation

    if published is not None and entries != _crl_revocations(published, issuer_resolver):
        raise ValueError('merged revocation state differs from the published complete CRL')

    return _crl_snapshot(delta, entries, issuer_certificate=issuer_certificate)


_ALL_REVOCATION_REASONS = frozenset(ReasonFlags) - {ReasonFlags.unspecified, ReasonFlags.remove_from_crl}


@dataclass(frozen=True)
class CertificateRevocationAssessment:
    status: str
    covered_reasons: frozenset[ReasonFlags]
    revocation: CRLRevocation | None = None


def _distribution_names(point, issuers):
    if point.full_name is not None:
        return point.full_name
    if point.relative_name is not None and len(issuers) == 1:
        return (DirectoryName(Name([*issuers[0].rdns, point.relative_name])),)
    return ()


def _general_name_matches(left, right):
    if isinstance(left, DirectoryName) and isinstance(right, DirectoryName):
        return _issuer_key(left.value) == _issuer_key(right.value)
    return left == right


def _crl_distribution_coverage(snapshot, point, certificate, *, is_ca):
    distribution = snapshot._distribution
    certificate_issuer = certificate.issuer
    if point.crl_issuer is None:
        if _issuer_key(snapshot.issuer) != _issuer_key(certificate_issuer):
            return None
        issuers = (certificate_issuer,)
    else:
        issuers = tuple(name.value for name in point.crl_issuer if isinstance(name, DirectoryName))
        if (distribution is None or not distribution.indirect_crl
                or not any(_issuer_key(name) == _issuer_key(snapshot.issuer) for name in issuers)):
            return None

    reasons = _ALL_REVOCATION_REASONS if point.reasons is None else point.reasons
    if distribution is None:
        return reasons
    if (distribution.only_contains_attribute_certs or (distribution.only_contains_user_certs and is_ca)
            or (distribution.only_contains_ca_certs and not is_ca)):
        return None
    if certificate.version != Version.v3 and (distribution.only_contains_user_certs or distribution.only_contains_ca_certs):
        return None
    if distribution.full_name is not None or distribution.relative_name is not None:
        if point.full_name is None and point.relative_name is None:
            names = point.crl_issuer or ()
        else:
            names = _distribution_names(point, issuers)
        if not any(_general_name_matches(left, right)
                   for left in _distribution_names(distribution, (snapshot.issuer,)) for right in names):
            return None
    only_reasons = distribution.only_some_reasons
    return reasons if only_reasons is None else reasons & only_reasons


def _latest_crl_scopes(snapshots, validation_time):
    latest = {}
    conflicts = set()
    for snapshot in snapshots:
        if (not isinstance(snapshot, CRLRevocationSnapshot) or not snapshot._authenticated
                or snapshot._issuer_certificate is None or snapshot._signer_key_id is None):
            raise ValueError('certificate revocation assessment requires authenticated CRL snapshots')
        if snapshot.this_update > validation_time:
            continue
        key = _issuer_key(snapshot.issuer), snapshot._signer_key_id, snapshot.issuing_distribution_point
        previous = latest.get(key)
        if previous is not None:
            current_rank = snapshot.this_update, snapshot.number
            previous_rank = previous.this_update, previous.number
            if current_rank < previous_rank:
                continue
            if current_rank == previous_rank:
                if (snapshot.next_update, snapshot._entries) != (previous.next_update, previous._entries):
                    conflicts.add(key)
                continue
        conflicts.discard(key)
        latest[key] = snapshot
    if conflicts:
        raise ValueError('conflicting authenticated CRL snapshots share issuer key, scope, time and number')
    return (snapshot for snapshot in latest.values() if validation_time < snapshot.next_update)


def _verify_path_revocation(target, signers, paths, snapshots, trust_anchor, validation_time):
    parents = {}
    required = set()
    for endpoint, path in paths.items():
        for child, parent in zip(path, path[1:]):
            if child in parents and parents[child] != parent:
                raise ValueError('selected certificate paths disagree on revocation evidence issuer')
            parents[child] = parent
            if child != target or endpoint != target or child in signers:
                required.add(child)
    parents = {child: parent for child, parent in parents.items() if child in required}

    authenticated_evidence = {}
    for snapshot in snapshots:
        authenticated_evidence.setdefault(snapshot._issuer_certificate, []).append(snapshot)
    verified = {trust_anchor}
    while parents:
        ready = [child for child, parent in parents.items() if parent in verified]
        if not ready:
            raise ValueError('certificate path revocation evidence depends on an unverified issuer')
        for child in ready:
            parent = parents.pop(child)
            role = 'CRL signer' if child in signers else 'intermediate'
            certificate = _revocation_certificate(child, role)
            verdict = _assess_revocation_status(
                certificate, authenticated_evidence.get(parent, ()), validation_time,
                issuer_key_id=_certificate_key_id(parent),
            )
            if verdict.status != 'unrevoked':
                raise ValueError(f'{role} certificate revocation status is {verdict.status}')
            verified.add(child)


def _delegated_signers_for_path(target_path, signers, paths):
    # The signed distribution point declares a cRLIssuer. Its CRL-signing
    # certificate must be issued by an authority on the target's path.
    authorities = set(target_path[1:] or target_path)
    return {
        signer for signer in signers if signer in authorities
        or (len(paths[signer]) > 1 and paths[signer][1] in authorities)
    }


def assess_certificate_revocation(certificate, snapshots, *, validation_time, trust_anchor=None, intermediates=(),
                                  require_chain_revocation=False, issuer_certificate=None, openssl_path=None):
    """Assess a DER certificate against caller-supplied authenticated CRL snapshots.

    Supply a DER trust_anchor and any untrusted DER intermediates to verify
    the target and snapshot signer paths under that anchor. Pass an absolute
    openssl_path to select a trusted OpenSSL executable explicitly. Set
    require_chain_revocation to require unrevoked status for every used
    intermediate and CRL signer except the anchor. Each certificate's
    evidence comes from its validated parent. With no trust anchor, an
    optional issuer_certificate pins the externally authenticated target
    issuer. Otherwise direct CRL keys must verify the target's signature,
    and the caller authenticates applicable delegated CRL signing keys.
    Unsupported X.509 certificate versions raise ValueError.
    """
    if not isinstance(validation_time, datetime) or validation_time.utcoffset() is None:
        raise ValueError('CRL validation time must be a timezone-aware datetime')
    if not isinstance(certificate, bytes):
        raise ValueError('expected a DER certificate for revocation assessment')
    issuer_key_id = None
    delegated_signers = None
    if trust_anchor is not None:
        if issuer_certificate is not None:
            raise ValueError('select either a trust anchor or an externally authenticated issuer certificate')
        snapshots = tuple(snapshots)
        signers = []
        for snapshot in snapshots:
            if (not isinstance(snapshot, CRLRevocationSnapshot) or not snapshot._authenticated
                    or snapshot._issuer_certificate is None):
                raise ValueError('certificate path validation requires CRL snapshots with authenticated signer certificates')
            signers.append(snapshot._issuer_certificate)
        signers = dict.fromkeys(signers)
        paths = verify_revocation_paths(certificate, signers, trust_anchor=trust_anchor,
                                       intermediates=intermediates, validation_time=validation_time,
                                       identify=True, openssl_path=openssl_path)
        target_path = paths[certificate]
        issuer_key_id = _certificate_key_id(target_path[1] if len(target_path) > 1 else trust_anchor)
        delegated_signers = _delegated_signers_for_path(target_path, signers, paths)
        if require_chain_revocation:
            _verify_path_revocation(certificate, signers, paths, snapshots, trust_anchor, validation_time)
    elif require_chain_revocation:
        raise ValueError('certificate path revocation requires an explicit trust anchor')
    elif intermediates:
        raise ValueError('certificate path intermediates require an explicit trust anchor')
    elif openssl_path is not None:
        raise ValueError('openssl_path requires an explicit trust anchor')
    target = _revocation_certificate(certificate, 'target')
    if issuer_certificate is not None:
        issuer = _load_certificate(issuer_certificate, 'target issuer')
        if _issuer_key(issuer.subject) != _issuer_key(target.issuer):
            raise ValueError('target issuer certificate must match the certificate issuer name')
        try:
            target.verify_directly_issued_by(issuer)
        except (TypeError, ValueError, InvalidSignature) as error:
            raise ValueError('target certificate does not verify under the supplied issuer certificate') from error
        except UnsupportedAlgorithm:
            # Explicit pin for an issuer established by an external path verifier.
            pass
        issuer_key_id = _certificate_key_id(issuer_certificate)
    return _assess_revocation_status(target, snapshots, validation_time,
                                     issuer_key_id=issuer_key_id, delegated_signers=delegated_signers)


def _crl_scope_reasons(target, snapshots, distribution_points, *, is_ca, issuer_key_id, delegated_signers):
    applicable = {}
    direct_verdicts = {}
    for point in distribution_points:
        matches = []
        delegate_keys = {}
        for index, snapshot in enumerate(snapshots):
            reasons = _crl_distribution_coverage(snapshot, point, target, is_ca=is_ca)
            if not reasons:
                continue
            key = snapshot._signer_key_id
            if point.crl_issuer is None:
                if issuer_key_id is not None:
                    if key != issuer_key_id:
                        continue
                else:
                    if key not in direct_verdicts:
                        try:
                            target.verify_directly_issued_by(load_der_x509_certificate(snapshot._issuer_certificate))
                            direct_verdicts[key] = True
                        except (ValueError, TypeError, InvalidSignature, UnsupportedAlgorithm):
                            direct_verdicts[key] = False
                    if not direct_verdicts[key]:
                        continue
                matches.append((index, reasons, None))
            elif delegated_signers is None or snapshot._issuer_certificate in delegated_signers:
                name = _issuer_key(snapshot.issuer)
                delegate_keys.setdefault(name, set()).add(key)
                matches.append((index, reasons, name))
        for index, reasons, delegate in matches:
            if delegate is None or len(delegate_keys[delegate]) == 1:
                applicable.setdefault(index, set()).update(reasons)
    return applicable


def _assess_revocation_status(target, snapshots, validation_time, *, issuer_key_id=None, delegated_signers=None):
    basic = _extension_value(target.extensions, ExtensionOID.BASIC_CONSTRAINTS)
    is_ca = basic is not None and basic.ca
    distribution_points = _extension_value(target.extensions, ExtensionOID.CRL_DISTRIBUTION_POINTS)
    if distribution_points is None:
        alternatives = _extension_value(target.extensions, ExtensionOID.ISSUER_ALTERNATIVE_NAME) or ()
        distribution_points = (
            DistributionPoint([DirectoryName(target.issuer), *alternatives], None, None, None),
        )
    covered = set()
    revocations = []
    fresh = tuple(_latest_crl_scopes(snapshots, validation_time))
    applicable = _crl_scope_reasons(target, fresh, distribution_points, is_ca=is_ca,
                                    issuer_key_id=issuer_key_id, delegated_signers=delegated_signers)
    for index, reasons in applicable.items():
        snapshot = fresh[index]
        entry = snapshot.revocation_for(target.issuer, target.serial_number)
        if entry is not None:
            distribution = snapshot._distribution
            only_reasons = distribution.only_some_reasons if distribution is not None else None
            if (entry.reason != ReasonFlags.unspecified and only_reasons is not None
                    and entry.reason not in only_reasons):
                continue
            if entry.revocation_date > validation_time:
                continue
            # RFC 5280 §6.3.3(j): a listing on an applicable CRL revokes the
            # certificate whatever its reason. The reasons mask only governs
            # coverage for certificates that are absent from the list.
            revocations.append(entry)
        covered.update(reasons)
    if revocations:
        revocation = min(revocations, key=lambda entry: (entry.revocation_date, entry.reason.value,
                                                        entry.invalidity_date is None,
                                                        entry.invalidity_date or entry.revocation_date))
        return CertificateRevocationAssessment('revoked', frozenset(covered), revocation)
    status = 'unrevoked' if covered == _ALL_REVOCATION_REASONS else 'undetermined'
    return CertificateRevocationAssessment(status, frozenset(covered))


def _check_optional_set(fields, tag, field_name, parse_member, *, nonempty=False, limit=None):
    if not fields.next_is(tag):
        return
    try:
        content = fields.take(tag)
        if nonempty and not content:
            raise ValueError('empty DER SET OF')
        for member in _set_members(content, 0x30, limit=limit):
            parse_member(member)
    except (MissingAttributeSchema, MissingExtensionSchema, SignedDataLimitsExceeded):
        raise
    except ValueError as error:
        raise ValueError(f'invalid SignedData {field_name}: {error}') from error


def _signed_data(envelope):
    if len(envelope) > _MAX_ENVELOPE_BYTES:
        raise SignedDataLimitsExceeded('SignedData envelope byte limit exceeded')
    budget = _DERBudget()
    for _ in _walk_der(envelope, defer_syntax=True, budget=budget):
        pass
    outer = _DER(envelope)
    content_info = _DER(outer.take(0x30))
    outer.done()
    if content_info.take(0x06) != _SIGNED_DATA:
        raise ValueError('expected SM2 SignedData content type')
    tagged = _DER(content_info.take(0xa0))
    content_info.done()
    signed_data = _DER(tagged.take(0x30), budget=budget)
    tagged.done()
    if signed_data.take(0x02) != b'\x01':
        raise ValueError('unsupported SignedData version')
    return signed_data


def _content(fields):
    encapsulated = _DER(fields.take(0x30))
    oid = encapsulated.take(0x06)
    _check_oid(oid)
    content = None
    if encapsulated.next_is(0xa0):
        attached = _DER(encapsulated.take(0xa0))
        content = attached.take(0x04)
        attached.done()
    encapsulated.done()
    return oid, content


def _signer_infos(fields, *, x509_profile=False, extension_schemas=None):
    _check_optional_set(fields, 0xa0, 'certificates',
                        lambda member: _check_certificate(
                            member, profile=x509_profile, schemas=extension_schemas, budget=fields.budget,
                        ))
    _check_optional_set(fields, 0xa1, 'crls',
                        lambda member: _check_crl(
                            member, profile=x509_profile, schemas=extension_schemas, budget=fields.budget,
                        ))
    signers = fields.take(0x31)
    fields.done()
    return signers


def _signer_identifier(signer):
    if signer.take(0x02) != b'\x02':
        raise ValueError('expected SignerInfo version 2')
    return signer.take_encoded(0x30)


def _signer_signature(signer, attribute_schemas=None):
    _algorithm(signer, _SIGNATURE_ALGORITHM_PARAMETERS)
    signature = _signature(signer.take(0x04))
    _check_optional_set(signer, 0xa1, 'unsignedAttrs',
                        lambda member: _attribute(member, attribute_schemas), nonempty=True, limit=_MAX_ATTRIBUTES)
    signer.done()
    return signature


def _direct_signature(envelope, message, signer_identifier):
    fields = _signed_data(envelope)
    algorithms = _DER(fields.take(0x31))
    _digest_algorithm(algorithms)
    algorithms.done()
    oid, content = _content(fields)
    if oid != _DATA:
        raise ValueError('expected SM2 data content type')
    if content is not None and content != message:
        raise ValueError('SignedData content differs from the approved transaction message')

    signers = _DER(_signer_infos(fields))
    signer = _DER(signers.take(0x30))
    signers.done()
    if _signer_identifier(signer) != signer_identifier:
        raise ValueError('SignedData signer identifier differs from the configured signer')
    _digest_algorithm(signer)
    if signer.next_is(0xa0):
        raise ValueError('signedAttrs signatures cannot authorize the existing payment template')
    return _signer_signature(signer)


def _check_signed_attributes(encoded, attribute_schemas, content_type, *, require_signed_content_type):
    members = _DER(encoded).take(0xa0)
    digests = []
    content_types = []
    for member in _set_members(members, 0x30, limit=_MAX_ATTRIBUTES):
        oid, values = _attribute(member, attribute_schemas)
        if oid == _MESSAGE_DIGEST:
            digests.append(values)
        elif oid == _CONTENT_TYPE:
            content_types.append(_content_type_attribute_oid(values))
    if len(digests) != 1 or len(digests[0]) != 1:
        raise ValueError('signedAttrs requires exactly one messageDigest with one value')
    if require_signed_content_type and not content_types:
        raise ValueError('SignedData signer requires a signed contentType')
    if len(content_types) > 1:
        raise ValueError('signedAttrs has duplicate contentType attributes')
    if content_types and content_types[0] != content_type:
        raise ValueError('signed contentType differs from eContentType')
    return _message_digest_octets(digests[0][0])


def _general_fields(envelope, *, require_signer=False, x509_profile=False, extension_schemas=None):
    if not isinstance(envelope, bytes):
        raise ValueError('expected a DER SignedData envelope')
    fields = _signed_data(envelope)
    algorithms = set()
    for algorithm in _set_members(fields.take(0x31), 0x30):
        oid = _digest_algorithm(_DER(algorithm))
        if oid in algorithms:
            raise ValueError('duplicate digestAlgorithms OID')
        algorithms.add(oid)
    content_type, content = _content(fields)
    signers = _signer_infos(fields, x509_profile=x509_profile, extension_schemas=extension_schemas)
    if require_signer and not signers:
        raise ValueError('SignedData requires at least one signer')
    if signers and not algorithms:
        raise ValueError('expected SM3 in digestAlgorithms')
    return content_type, content, algorithms, signers


def _decode_signers(signers, attribute_schemas, content_type, algorithms, *, require_signed_content_type=False):
    previous = None
    for encoded in _set_members(signers, 0x30):
        if encoded == previous:
            continue
        previous = encoded
        signer = _DER(_DER(encoded).take(0x30))
        identifier = _signer_identifier(signer)
        _check_issuer_and_serial_number(identifier)
        if _digest_algorithm(signer) not in algorithms:
            raise ValueError('SignerInfo digestAlgorithm is missing from digestAlgorithms')
        attributes = None
        attribute_digest = None
        if signer.next_is(0xa0):
            attributes = signer.take_encoded(0xa0)
            attribute_digest = _check_signed_attributes(
                attributes, attribute_schemas, content_type, require_signed_content_type=require_signed_content_type,
            )
        elif require_signed_content_type:
            raise ValueError('SignedData signer requires a signed contentType')
        yield identifier, attributes, attribute_digest, _signer_signature(signer, attribute_schemas)


def validate_signed_data_format(envelope, *, require_signer=False, attribute_schemas=None, extension_schemas=None):
    """Check SignedData ASN.1 framing and the implemented X.509 profile rules.

    Pass require_signer=True to enforce Chapter 8's minimum of one signer.
    With the default, the structural check can inspect unsigned metadata.
    Pass extension_schemas to check declared extension types by dotted OID
    and to report a missing schema for any unrecognized extension value.
    """
    content_type, _, algorithms, signers = _general_fields(
        envelope, require_signer=require_signer, x509_profile=True, extension_schemas=extension_schemas,
    )
    for _ in _decode_signers(signers, attribute_schemas, content_type, algorithms):
        pass


def verify_signed_data(envelope, trusted_signers, *, detached_content=None, attribute_schemas=None,
                       signed_attrs_encoding='context-field', expected_content_type=DATA_CONTENT_TYPE,
                       require_signed_content_type=False):
    """Verify one or more v2 signers and return the signed content octets.

    trusted_signers maps DER IssuerAndSerialNumber to (SM2 public key, user ID).
    Use externally authenticated keys. Certificate path and revocation
    decisions belong to the caller. Raises ValueError on a rejected envelope.
    Supply attribute_schemas as a mapping from dotted attribute OIDs to
    asn1crypto ASN.1 classes for schema-aware DER checks. Missing types in
    this mode raise MissingAttributeSchema. messageDigest and contentType
    have built-in types. The expected eContentType defaults to the SM2 data
    OID. Use a trusted application OID when verifying another content type.
    Set require_signed_content_type to bind that OID in every signer's signature.
    Chapter 8 signs the DER encoding of the signedAttrs [0] field. Select
    cms-set explicitly to verify a CMS-style signature over the universal
    SET encoding. A verification call uses a single encoding.
    """
    if detached_content is not None:
        if not isinstance(detached_content, bytes):
            raise ValueError('expected detached content octets')
        if len(detached_content) > _MAX_DETACHED_BYTES:
            raise SignedDataLimitsExceeded('SignedData detached content byte limit exceeded')
    if signed_attrs_encoding not in ('cms-set', 'context-field'):
        raise ValueError('expected cms-set or context-field for signedAttrs encoding')

    if not isinstance(expected_content_type, str):
        raise ValueError('expected_content_type must be a dotted OID')
    expected_oid = ObjectIdentifier(expected_content_type).contents
    _check_oid(expected_oid, 'expected content type OID')
    content_type, content, algorithms, signers = _general_fields(envelope, require_signer=True)
    if content_type != expected_oid:
        raise ValueError('SignedData eContentType differs from expected content type')
    if content is None:
        if detached_content is None:
            raise ValueError('SignedData requires detached content')
        content = detached_content
    elif detached_content is not None and detached_content != content:
        raise ValueError('supplied content differs from encapsulated SignedData content')

    content_digest = None
    direct_digests = {}
    verified = set()
    decoded = _decode_signers(signers, attribute_schemas, content_type, algorithms,
                              require_signed_content_type=require_signed_content_type)
    for identifier, attributes, attribute_digest, signature in decoded:
        if attribute_digest is not None:
            if content_digest is None:
                content_digest = sm3(content)
            if attribute_digest != content_digest:
                raise ValueError('signedAttrs messageDigest differs from SM3 of the content')
        if identifier not in trusted_signers:
            raise ValueError('untrusted SignedData signer identifier')
        key, user_id = trusted_signers[identifier]
        if not isinstance(key, bytes) or not isinstance(user_id, bytes):
            raise ValueError('invalid SignedData signature')
        try:
            if attributes is None:
                identity = key, user_id
                if identity not in direct_digests:
                    direct_digests[identity] = message_digest(key, content, user_id)
                digest = direct_digests[identity]
            else:
                payload = b'\x31' + attributes[1:] if signed_attrs_encoding == 'cms-set' else attributes
                digest = message_digest(key, payload, user_id)
        except ValueError as error:
            raise ValueError('invalid SignedData signature') from error
        check = key, digest, signature
        if check in verified:
            continue
        if not verify_digest(key, digest, signature):
            raise ValueError('invalid SignedData signature')
        verified.add(check)
    return content


def signed_data_signer(signer, key, *, signer_identifier):
    """Adapt signer(message, user_id) returning SignedData to the wallet API.

    Pin the complete DER IssuerAndSerialNumber from trusted signer configuration.
    Require SignedData version 1 and SignerInfo version 2 for every response.
    """
    parse_public(key)
    if not isinstance(signer_identifier, bytes):
        raise ValueError('expected a pinned DER IssuerAndSerialNumber')
    _check_issuer_and_serial_number(signer_identifier)

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
