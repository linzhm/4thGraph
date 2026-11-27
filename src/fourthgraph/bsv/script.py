"""Small dependency-free Bitcoin Script encoder and literal-block assembler."""
from functools import cache
from pathlib import Path

SECP256K1_FIELD = (1 << 256) - (1 << 32) - 977

_NAMES = '''0 1NEGATE RESERVED 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 NOP VER IF NOTIF VERIF VERNOTIF ELSE ENDIF VERIFY RETURN TOALTSTACK FROMALTSTACK 2DROP 2DUP 3DUP 2OVER 2ROT 2SWAP IFDUP DEPTH DROP DUP NIP OVER PICK ROLL ROT SWAP TUCK CAT SPLIT NUM2BIN BIN2NUM SIZE INVERT AND OR XOR EQUAL EQUALVERIFY RESERVED1 RESERVED2 1ADD 1SUB 2MUL 2DIV NEGATE ABS NOT 0NOTEQUAL ADD SUB MUL DIV MOD LSHIFT RSHIFT BOOLAND BOOLOR NUMEQUAL NUMEQUALVERIFY NUMNOTEQUAL LESSTHAN GREATERTHAN LESSTHANOREQUAL GREATERTHANOREQUAL MIN MAX WITHIN RIPEMD160 SHA1 SHA256 HASH160 HASH256 CODESEPARATOR CHECKSIG CHECKSIGVERIFY CHECKMULTISIG CHECKMULTISIGVERIFY'''.split()
OPS = {'OP_0': 0, **{'OP_'+n: i+0x4f for i,n in enumerate(_NAMES[1:])}}
OPS.update(OP_SUBSTR=0xb3, OP_LEFT=0xb4)


def encode_num(n):
    value = abs(n)
    out = value.to_bytes((value.bit_length()+7)//8, 'little')
    if out and out[-1] & 128: out += bytes([128 if n < 0 else 0])
    elif n < 0: out = out[:-1] + bytes([out[-1] | 128])
    return out


def decode_num(b):
    return -(int.from_bytes(b, 'little') & ~(128 << (8*(len(b)-1)))) if b and b[-1] & 128 else int.from_bytes(b, 'little')


def push(b):
    n = len(b)
    if n < 76: return bytes([n])+b
    if n <= 255: return b'\x4c'+bytes([n])+b
    if n <= 65535: return b'\x4d'+n.to_bytes(2,'little')+b
    return b'\x4e'+n.to_bytes(4,'little')+b


def number(n):
    return bytes([0x50+n]) if 1 <= n <= 16 else b'\x4f' if n == -1 else push(encode_num(n))


def token(t):
    if t.startswith('OP_'): return bytes([OPS[t]])
    if t.startswith('0x'): return push(bytes.fromhex(t[2:]))
    return number(int(t))


def asm(text):
    return b''.join(token(t) for t in text.split())


@cache
def tile_top(count):
    """Generate binary concatenation of copies of the top byte string."""
    if count < 1:
        raise ValueError("Stack byte tiling requires a positive count")
    prefix, suffix = bytearray(), []
    while count > 1:
        if count & 1:
            prefix.extend(asm("OP_DUP"))
            suffix.append(asm("OP_CAT"))
            count -= 1
        else:
            suffix.append(asm("OP_DUP OP_CAT"))
            count //= 2
    return bytes(prefix) + b"".join(reversed(suffix))


def script_operations(script):
    """Yield complete Script instructions, including each push's data."""
    cursor = 0
    while cursor < len(script):
        start = cursor
        opcode = script[cursor]
        cursor += 1
        if opcode <= 75:
            cursor += opcode
        elif opcode <= 78:
            width = (1, 2, 4)[opcode - 76]
            end = cursor + width
            if end > len(script):
                raise ValueError('truncated Script push length')
            cursor = end + int.from_bytes(script[cursor:end], 'little')
        if cursor > len(script):
            raise ValueError('truncated Script push payload')
        yield script[start:cursor]


def without_codeseparators(script):
    """Remove CODESEPARATOR opcodes outside pushed data for OTDA scriptCode."""
    separator = asm('OP_CODESEPARATOR')
    clean = bytearray()
    for operation in script_operations(script):
        if operation != separator:
            clean.extend(operation)
    return bytes(clean)


def is_compressed_public_key(encoded):
    if not isinstance(encoded, bytes) or len(encoded) != 33 or encoded[0] not in (2, 3):
        return False
    x = int.from_bytes(encoded[1:], "big")
    if x >= SECP256K1_FIELD:
        return False
    # A nonzero quadratic residue has one root of each parity.
    square = (pow(x, 3, SECP256K1_FIELD) + 7) % SECP256K1_FIELD
    if square == 0:
        return encoded[0] == 2
    return pow(square, (SECP256K1_FIELD - 1) // 2, SECP256K1_FIELD) == 1


def assemble(directory, owner, injected=None, entry="LOCK"):
    if len(owner) != 20: raise ValueError('expected a 20-byte owner hash')
    constants = dict(injected or {}); constants['OWNER'] = push(owner)
    blocks = {}
    for path in sorted(Path(directory).glob('*.asm')):
        current = None
        for line in path.read_text().splitlines():
            tokens = line.partition('#')[0].split()
            if not tokens: continue
            if current is not None:
                if tokens == ['end']: current = None
                else: blocks[current].append(tokens)
                continue
            kind, name, *args = tokens
            if name in blocks or name in constants: raise ValueError('duplicate definition: '+name)
            if kind == 'block': current=name; blocks[name]=[]
            elif kind == 'bytes': constants[name]=push(bytes.fromhex(args[0]))
            elif kind == 'number': constants[name]=number(int(args[0],16))
            else: raise ValueError('unknown declaration: '+kind)
        if current is not None: raise ValueError('unterminated block: '+current)
    @cache
    def emit(t):
        if not t.startswith('@'): return token(t)
        name=t[1:]
        if name in constants: return constants[name]
        return b''.join(emit('@'+line[2])*int(line[1]) if line[0]=='repeat' else b''.join(emit(x) for x in line) for line in blocks[name])
    return emit('@'+entry)
