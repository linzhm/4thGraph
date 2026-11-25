"""Unroll fixed-length SM3 into ordinary BSV Script opcodes (no new opcode)."""
from functools import cache
from shared.script import asm, number, push

MASK=0xffffffff
IV=(0x7380166f,0x4914b2b9,0x172442d7,0xda8a0600,0xa96f30bc,0x163138aa,0xe38dee4d,0xb0fb0e4e)


def rol(x,n):
    n%=32
    return ((x<<n)|(x>>(32-n)))&MASK


def message_schedule(block):
    w=[int.from_bytes(block[i:i+4],'big') for i in range(0,64,4)]
    for j in range(16,68):
        x=w[j-16]^w[j-9]^rol(w[j-3],15)
        w.append(x^rol(x,15)^rol(x,23)^rol(w[j-13],7)^w[j-6])
    return w


def compress(state, block):
    w=message_schedule(block)
    a,b,c,d,e,f,g,h=state
    for j in range(64):
        ss1=rol((rol(a,12)+e+rol(0x79cc4519 if j<16 else 0x7a879d8a,j))&MASK,7)
        ss2=ss1^rol(a,12)
        ff=a^b^c if j<16 else (a&b)|(a&c)|(b&c)
        gg=e^f^g if j<16 else (e&f)|((MASK^e)&g)
        tt1=(ff+d+ss2+(w[j]^w[j+4]))&MASK
        tt2=(gg+h+ss1+w[j])&MASK
        a,b,c,d,e,f,g,h=tt1,a,rol(b,9),c,tt2^rol(tt2,9)^rol(tt2,17),e,rol(f,19),g
    return tuple(x^y for x,y in zip(state,(a,b,c,d,e,f,g,h)))


def xor(x,y): return ('XOR',x,y)
def band(x,y): return ('AND',x,y)
def bor(x,y): return ('OR',x,y)
def plus(*v):
    x=v[0]
    for y in v[1:]: x=('ADD',x,y)
    return ('MOD',x,1<<32)
def rot(x,n): return ('ROT',x,n%32)
def perm(x,a,b): return xor(xor(x,rot(x,a)),rot(x,b))


REVERSE4=asm(' '.join(['OP_1 OP_SPLIT OP_SWAP OP_TOALTSTACK']*3+['OP_FROMALTSTACK OP_CAT']*3))
# The larger powers used by rotations and reduction modulo 2**32 cost more
# to push as literals than to copy from a cached stack slot.
ROTATION_CONSTANTS = tuple(1 << exponent for exponent in (15, 17, 19, 20, 23, 25, 32))
SHALLOW_DROPS = ('OP_DROP', 'OP_NIP', 'OP_ROT OP_DROP')


class Builder:
    def __init__(self, optimized, compact):
        self.code=bytearray()
        self.stack=['data']
        self.optimized=optimized
        self.compact = compact
        self.constants = {value: f'constant_{value}' for value in ROTATION_CONSTANTS} if compact else {}

    def cache_constants(self):
        for value, name in self.constants.items():
            self.code.extend(number(value))
            self.stack.append(name)

    def raw(self,s): self.code.extend(asm(s))
    def expr(self,e,*,binary=False):
        # A five-byte word keeps the Script sign bit clear and gives all
        # SM3 bitwise operands the same width. Only arithmetic needs decoding.
        if isinstance(e, int):
            if e in self.constants:
                self.expr(self.constants[e], binary=binary)
                return
            self.code.extend(number(e))
        elif isinstance(e, str):
            depth = len(self.stack) - 1 - self.stack.index(e)
            if self.compact and depth < 2:
                self.raw(('OP_DUP', 'OP_OVER')[depth])
            else:
                self.code.extend(number(depth) + asm('OP_PICK'))
        elif e[0]=='ROT':
            _, word, count = e
            self.expr(word)
            self.raw('OP_DUP')
            self.stack.append(None)
            # Track the temporary operands so cached constants can be picked
            # at the correct depth throughout the numeric rotation.
            self.expr(1 << count)
            self.raw('OP_MUL')
            self.stack.pop()
            self.expr(1 << 32)
            self.raw('OP_MOD OP_SWAP')
            self.stack.pop()
            self.expr(1 << (32 - count))
            self.raw('OP_DIV OP_ADD')
            del self.stack[-2:]
            if binary: self.raw('5 OP_NUM2BIN')
            return
        else:
            op,x,y=e
            bitwise=op in ('XOR','AND','OR')
            binary_operands=bitwise and self.optimized
            self.expr(x,binary=binary_operands); self.expr(y,binary=binary_operands)
            if bitwise and not self.optimized:
                self.raw('5 OP_NUM2BIN OP_SWAP 5 OP_NUM2BIN OP_'+op+' OP_BIN2NUM')
            else:
                self.raw('OP_'+op)
                if bitwise and not binary: self.raw('OP_BIN2NUM')
                if binary and not bitwise: self.raw('5 OP_NUM2BIN')
            self.stack.pop(); return
        if binary: self.raw('5 OP_NUM2BIN')
        self.stack.append(None)
    def assign(self,name,e):
        self.expr(e)
        if name in self.stack: self.drop(name)
        self.stack[-1]=name
    def drop(self,name):
        index=self.stack.index(name); depth=len(self.stack)-1-index
        if self.compact and depth < len(SHALLOW_DROPS):
            self.raw(SHALLOW_DROPS[depth])
        else:
            self.code.extend(number(depth)+asm('OP_ROLL OP_DROP'))
        self.stack.pop(index)
    def word(self,name,offset):
        self.expr('data')
        self.code.extend(number(offset)+asm('OP_SPLIT OP_NIP')+number(4)+asm('OP_SPLIT OP_DROP')+REVERSE4+push(b'\0')+asm('OP_CAT OP_BIN2NUM'))
        self.stack[-1]=name


@cache
def hash_script(length, state=IV, processed=0, *, optimized=False, compact=False):
    """Top item is exactly length bytes. Replace it with SM3, preserving lower stack.

    state is a known fixed-prefix midstate; processed must be whole blocks.
    The default uses the baseline SM3 generator. optimized uses a static
    schedule for padding-only blocks. compact also enables constant, stack,
    and Boolean optimizations.
    """
    if processed%64: raise ValueError('midstate must start on a block boundary')
    optimized = optimized or compact
    b=Builder(optimized, compact)
    b.code.extend(asm('OP_SIZE')+number(length)+asm('OP_NUMEQUALVERIFY'))
    total=processed+length
    padding=b'\x80'+bytes((55-total)%64)+(total*8).to_bytes(8,'big')
    b.code.extend(push(padding)+asm('OP_CAT'))
    b.cache_constants()
    for i,v in enumerate(state): b.assign('h'+str(i),v)
    for offset in range(0,length+len(padding),64):
        static_padding=optimized and offset>=length
        if static_padding:
            # The schedule of a padding-only block is independent of its
            # chaining state. The 64 compression rounds still run in Script.
            start=offset-length
            words=message_schedule(padding[start:start+64])
        else:
            words=[f'w{j}' for j in range(68)]
            for j in range(16): b.word(words[j],offset+j*4)
            for j in range(16,68):
                x=xor(xor(words[j-16],words[j-9]),rot(words[j-3],15))
                if optimized:
                    b.assign('expansion_mix',x)
                    x='expansion_mix'
                b.assign(words[j],xor(xor(perm(x,15,23),rot(words[j-13],7)),words[j-6]))
                if optimized: b.drop('expansion_mix')
        for i,c in enumerate('abcdefgh'): b.assign(c,'h'+str(i))
        for j in range(64):
            a_rot12=rot('a',12)
            if optimized:
                b.assign('a_rot12',a_rot12)
                a_rot12='a_rot12'
            b.assign('ss1',rot(plus(a_rot12,'e',rol(0x79cc4519 if j<16 else 0x7a879d8a,j)),7))
            b.assign('ss2',xor('ss1',a_rot12))
            if optimized: b.drop('a_rot12')
            if j < 16:
                ff = xor(xor('a', 'b'), 'c')
                gg = xor(xor('e', 'f'), 'g')
            elif compact:
                ff = bor(band('a', 'b'), band('c', bor('a', 'b')))
                gg = xor('g', band('e', xor('f', 'g')))
            else:
                ff = bor(bor(band('a', 'b'), band('a', 'c')), band('b', 'c'))
                gg = bor(band('e', 'f'), band(xor('e', MASK), 'g'))
            cross_word=words[j]^words[j+4] if static_padding else xor(words[j],words[j+4])
            b.assign('tt1',plus(ff,'d','ss2',cross_word))
            b.assign('tt2',plus(gg,'h','ss1',words[j]))
            for name,expr in [('d','c'),('c',rot('b',9)),('b','a'),('a','tt1'),('h','g'),('g',rot('f',19)),('f','e'),('e',perm('tt2',9,17))]: b.assign(name,expr)
        for i,c in enumerate('abcdefgh'): b.assign('h'+str(i),xor('h'+str(i),c))
        for name in [*(() if static_padding else words),*'abcdefgh','ss1','ss2','tt1','tt2']: b.drop(name)
    b.drop('data')
    for name in b.constants.values():
        b.drop(name)
    for i in range(8):
        b.expr('h'+str(i))
        b.code.extend(asm('5 OP_NUM2BIN 4 OP_SPLIT OP_DROP')+REVERSE4)
        b.stack[-1]='out'+str(i)
    for _ in range(7): b.raw('OP_CAT'); b.stack.pop()
    b.stack[-1]='digest'
    for i in range(8): b.drop('h'+str(i))
    assert b.stack==['digest']
    return bytes(b.code)
