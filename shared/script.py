"""Small dependency-free Bitcoin Script encoder and literal-block assembler."""
from functools import cache
from pathlib import Path

_NAMES = '''0 1NEGATE RESERVED 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 NOP VER IF NOTIF VERIF VERNOTIF ELSE ENDIF VERIFY RETURN TOALTSTACK FROMALTSTACK 2DROP 2DUP 3DUP 2OVER 2ROT 2SWAP IFDUP DEPTH DROP DUP NIP OVER PICK ROLL ROT SWAP TUCK CAT SPLIT NUM2BIN BIN2NUM SIZE INVERT AND OR XOR EQUAL EQUALVERIFY RESERVED1 RESERVED2 1ADD 1SUB 2MUL 2DIV NEGATE ABS NOT 0NOTEQUAL ADD SUB MUL DIV MOD LSHIFT RSHIFT BOOLAND BOOLOR NUMEQUAL NUMEQUALVERIFY NUMNOTEQUAL LESSTHAN GREATERTHAN LESSTHANOREQUAL GREATERTHANOREQUAL MIN MAX WITHIN RIPEMD160 SHA1 SHA256 HASH160 HASH256 CODESEPARATOR CHECKSIG CHECKSIGVERIFY CHECKMULTISIG CHECKMULTISIGVERIFY'''.split()
OPS = {'OP_0': 0, **{'OP_'+n: i+0x4f for i,n in enumerate(_NAMES[1:])}}


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
