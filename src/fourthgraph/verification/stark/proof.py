"""Proof packet, public inputs and the SHA-256 Fiat–Shamir transcript."""

from dataclasses import dataclass
from hashlib import sha256

LOG_TRACE = 4
LOG_BLOWUP = 3
LOG_LDE = LOG_TRACE + LOG_BLOWUP
QUERIES = 64
DIGEST = 32


@dataclass(frozen=True)
class Profile:
    name: str
    modulus: int
    generator: int
    dimension: int
    nonresidue: int
    width: int

    @property
    def extension_width(self):
        return self.dimension * self.width

    @property
    def domain(self):
        return f"4thgraph/fibonacci-stark/v1/{self.name}".encode()

    @property
    def header_size(self):
        return (2 + LOG_TRACE) * DIGEST + (5 + self.dimension) * self.extension_width

    @property
    def query_size(self):
        paths = 2 * LOG_LDE + sum(LOG_LDE - i - 1 for i in range(LOG_TRACE))
        return (2 + self.dimension) * self.width + LOG_TRACE * self.extension_width + paths * DIGEST

    @property
    def proof_size(self):
        return self.header_size + QUERIES * self.query_size

    @property
    def witness_size(self):
        return self.proof_size + QUERIES * self.extension_width

    def subgroup_root(self, log_size):
        return pow(self.generator, (self.modulus - 1) >> log_size, self.modulus)

    def encode(self, value):
        if type(value) is not int or not 0 <= value < self.modulus:
            raise ValueError(f"expected a canonical {self.name} field element")
        return value.to_bytes(self.width, "little")


BABYBEAR = Profile("babybear", 0x78000001, 31, 4, 11, 4)
GOLDILOCKS = Profile("goldilocks", 0xFFFFFFFF00000001, 7, 2, 7, 8)


class Packet:
    def __init__(self, read):
        self.read = read
        self.offset = 0

    def take(self, width):
        start = self.offset
        self.offset += width
        return self.read(start, width)


@dataclass(frozen=True)
class Header:
    trace: object
    quotient: object
    fri: tuple
    opened: tuple
    final: object


def read_header(profile, packet):
    trace, quotient = packet.take(DIGEST), packet.take(DIGEST)
    fri = tuple(packet.take(DIGEST) for _ in range(LOG_TRACE))
    opened = tuple(packet.take(profile.extension_width) for _ in range(4 + profile.dimension))
    return Header(trace, quotient, fri, opened, packet.take(profile.extension_width))


class Transcript:
    def __init__(self, profile, public, header, *, script=None):
        self.profile = profile
        self.script = script
        initial = profile.domain + b"".join(map(profile.encode, (LOG_TRACE, LOG_TRACE, 0)))
        if len(public) != 3:
            raise ValueError("expected the two Fibonacci seeds and the final right value")
        public_bytes = b"".join(map(profile.encode, public))
        self.pending = initial
        self.observe(header.trace, public_bytes)
        self.alpha = self.extension()
        self.observe(header.quotient)
        self.zeta = self.extension()
        self.observe(*header.opened)
        self.rho = self.extension()
        betas = []
        for root in header.fri:
            self.observe(root)
            betas.append(self.extension())
        self.betas = tuple(betas)
        self.observe(header.final, profile.encode(1) * LOG_TRACE)

    def observe(self, *parts):
        if self.script is None:
            self.pending += b"".join(parts)
        else:
            self.pending = self.script.concat(self.pending, *parts)

    def squeeze(self):
        if self.script is None:
            self.pending = sha256(b"\x02" + self.pending).digest()
        else:
            self.pending = self.script.fragment("stark-transcript-hash", self.pending)
        return self.pending

    def extension(self):
        return tuple(self.number(self.squeeze(), self.profile.modulus) for _ in range(self.profile.dimension))

    def query_index(self):
        digest = self.squeeze()
        byte = digest[:1] if self.script is None else self.script.slice(digest, 0, 1)
        return self.number(byte, 1 << LOG_LDE)

    def number(self, data, modulus):
        if self.script is None:
            return int.from_bytes(data, "little") % modulus
        return self.script.op("OP_MOD", self.script.unsigned(data), modulus)


def inverse_hint(profile, zeta, index):
    # Coordinates in the row-commitment coset match Plonky3's bit-reversed order.
    power = sum((index >> bit & 1) << (LOG_LDE - 1 - bit) for bit in range(LOG_LDE))
    p, d = profile.modulus, profile.dimension
    x = profile.generator * pow(profile.subgroup_root(LOG_LDE), power, p) % p
    omega = profile.subgroup_root(LOG_TRACE)
    zeta_next = tuple(limb * omega % p for limb in zeta)
    a = ((zeta[0] - x) % p, *zeta[1:])
    b = ((zeta_next[0] - x) % p, *zeta_next[1:])

    def multiply(left, right):
        result = [0] * d
        for i, u in enumerate(left):
            for j, v in enumerate(right):
                result[(i + j) % d] += u * v * (profile.nonresidue if i + j >= d else 1)
        return tuple(coefficient % p for coefficient in result)

    factor = multiply(a, b)
    if not any(factor):
        raise ValueError("Fiat–Shamir opening coincides with an LDE point")
    result = (1, *(0,) * (d - 1))
    exponent = p**d - 2
    while exponent:
        if exponent & 1:
            result = multiply(result, factor)
        factor = multiply(factor, factor)
        exponent >>= 1
    return b"".join(map(profile.encode, result))


def witness_packet(profile, public, proof):
    """Insert one checked reciprocal in front of each native FRI query."""
    if len(proof) != profile.proof_size:
        raise ValueError(f"expected a {profile.proof_size}-byte {profile.name} proof")
    packet = Packet(lambda offset, width: proof[offset:offset + width])
    header = read_header(profile, packet)
    transcript = Transcript(profile, public, header)
    pieces = [proof[:packet.offset]]
    for _ in range(QUERIES):
        pieces.append(inverse_hint(profile, transcript.zeta, transcript.query_index()))
        pieces.append(packet.take(profile.query_size))
    return b"".join(pieces)
