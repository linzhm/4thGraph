"""Unroll fixed-length SM3 into ordinary BSV Script opcodes (no new opcode)."""
from functools import cache
from shared.script import asm, number, push

MASK=0xffffffff
IV=(0x7380166f,0x4914b2b9,0x172442d7,0xda8a0600,0xa96f30bc,0x163138aa,0xe38dee4d,0xb0fb0e4e)


def rol(x,n):
    n%=32
    return ((x<<n)|(x>>(32-n)))&MASK


def compress(state, block):
    w=[int.from_bytes(block[i:i+4],'big') for i in range(0,64,4)]
    for j in range(16,68):
        x=w[j-16]^w[j-9]^rol(w[j-3],15)
        w.append(x^rol(x,15)^rol(x,23)^rol(w[j-13],7)^w[j-6])
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


class Builder:
    def __init__(self): self.code=bytearray(); self.stack=['data']
    def raw(self,s): self.code.extend(asm(s))
    def expr(self,e):
        if isinstance(e,int): self.code.extend(number(e))
        elif isinstance(e,str): self.code.extend(number(len(self.stack)-1-self.stack.index(e))+asm('OP_PICK'))
        elif e[0]=='ROT':
            self.expr(e[1]); n=e[2]
            self.code.extend(asm('OP_DUP')+number(1<<n)+asm('OP_MUL')+number(1<<32)+asm('OP_MOD OP_SWAP')+number(1<<(32-n))+asm('OP_DIV OP_ADD'))
            return
        else:
            op,x,y=e
            self.expr(x); self.expr(y)
            if op in ('XOR','AND','OR'):
                self.raw('5 OP_NUM2BIN OP_SWAP 5 OP_NUM2BIN OP_'+op+' OP_BIN2NUM')
            else: self.raw('OP_'+op)
            self.stack.pop(); return
        self.stack.append(None)
    def assign(self,name,e):
        self.expr(e)
        if name in self.stack: self.drop(name)
        self.stack[-1]=name
    def drop(self,name):
        index=self.stack.index(name); depth=len(self.stack)-1-index
        self.code.extend(number(depth)+asm('OP_ROLL OP_DROP'))
        self.stack.pop(index)
    def word(self,name,offset):
        self.expr('data')
        self.code.extend(number(offset)+asm('OP_SPLIT OP_NIP')+number(4)+asm('OP_SPLIT OP_DROP')+REVERSE4+push(b'\0')+asm('OP_CAT OP_BIN2NUM'))
        self.stack[-1]=name


@cache
def hash_script(length, state=IV, processed=0):
    """Top item is exactly length bytes. Replace it with SM3, preserving lower stack.

    state is a known fixed-prefix midstate; processed must be whole blocks.
    """
    if processed%64: raise ValueError('midstate must start on a block boundary')
    b=Builder()
    b.code.extend(asm('OP_SIZE')+number(length)+asm('OP_NUMEQUALVERIFY'))
    total=processed+length
    padding=b'\x80'+bytes((55-total)%64)+(total*8).to_bytes(8,'big')
    b.code.extend(push(padding)+asm('OP_CAT'))
    for i,v in enumerate(state): b.assign('h'+str(i),v)
    for offset in range(0,length+len(padding),64):
        for j in range(16): b.word('w'+str(j),offset+j*4)
        for j in range(16,68):
            x=xor(xor('w'+str(j-16),'w'+str(j-9)),rot('w'+str(j-3),15))
            b.assign('w'+str(j),xor(xor(perm(x,15,23),rot('w'+str(j-13),7)),'w'+str(j-6)))
        for i,c in enumerate('abcdefgh'): b.assign(c,'h'+str(i))
        for j in range(64):
            b.assign('ss1',rot(plus(rot('a',12),'e',rol(0x79cc4519 if j<16 else 0x7a879d8a,j)),7))
            b.assign('ss2',xor('ss1',rot('a',12)))
            ff=xor(xor('a','b'),'c') if j<16 else bor(bor(band('a','b'),band('a','c')),band('b','c'))
            gg=xor(xor('e','f'),'g') if j<16 else bor(band('e','f'),band(xor('e',MASK),'g'))
            b.assign('tt1',plus(ff,'d','ss2',xor('w'+str(j),'w'+str(j+4))))
            b.assign('tt2',plus(gg,'h','ss1','w'+str(j)))
            for name,expr in [('d','c'),('c',rot('b',9)),('b','a'),('a','tt1'),('h','g'),('g',rot('f',19)),('f','e'),('e',perm('tt2',9,17))]: b.assign(name,expr)
        for i,c in enumerate('abcdefgh'): b.assign('h'+str(i),xor('h'+str(i),c))
        for name in [*(f'w{j}' for j in range(68)),*'abcdefgh','ss1','ss2','tt1','tt2']: b.drop(name)
    b.drop('data')
    for i in range(8):
        b.expr('h'+str(i))
        b.code.extend(asm('5 OP_NUM2BIN 4 OP_SPLIT OP_DROP')+REVERSE4)
        b.stack[-1]='out'+str(i)
    for _ in range(7): b.raw('OP_CAT'); b.stack.pop()
    b.stack[-1]='digest'
    for i in range(8): b.drop('h'+str(i))
    assert b.stack==['digest']
    return bytes(b.code)
