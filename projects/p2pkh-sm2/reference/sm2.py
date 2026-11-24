"""SM2/SM3 public verification and test-only arithmetic. Not constant-time."""
from hashlib import new, sha256

P = 0xfffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff
A = P-3
B = 0x28e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbcbd414d940e93
N = 0xfffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123
G = (0x32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7,
     0xbc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0)
USER_ID = b'1234567812345678'


def sm3(data): return new('sm3', data).digest()
def hash256(data): return sha256(sha256(data).digest()).digest()
def be32(n): return n.to_bytes(32, 'big')


def add(q, r):
    if q is None: return r
    if r is None: return q
    x,y=q; u,v=r
    if x==u and (y+v)%P==0: return None
    slope=((3*x*x+A)*pow(2*y,-1,P) if q==r else (v-y)*pow(u-x,-1,P))%P
    z=(slope*slope-x-u)%P
    return z,(slope*(x-z)-y)%P


def mul(k, q=G):
    if k < 0: raise ValueError('negative scalar')
    r=None
    while k:
        if k&1: r=add(r,q)
        q=add(q,q); k>>=1
    return r


def encode_public(q):
    if q is None: raise ValueError('point at infinity')
    return b'\x04'+be32(q[0])+be32(q[1])


def parse_public(key):
    if not isinstance(key,bytes) or len(key)!=65 or key[0]!=4: raise ValueError('expected uncompressed curveSM2 public key')
    x=int.from_bytes(key[1:33],'big'); y=int.from_bytes(key[33:],'big')
    if not (0<=x<P and 0<=y<P) or (y*y-x*x*x-A*x-B)%P: raise ValueError('invalid curveSM2 point')
    return x,y


def public_key_hash160(key):
    parse_public(key)
    return new('ripemd160', sha256(key).digest()).digest()


def za(key, user_id=USER_ID):
    parse_public(key)
    if not isinstance(user_id,bytes) or len(user_id)>8191: raise ValueError('SM2 ID bit length must fit uint16')
    return sm3((8*len(user_id)).to_bytes(2,'big')+user_id+be32(A)+be32(B)+be32(G[0])+be32(G[1])+key[1:])


def message_digest(key, message, user_id=USER_ID): return sm3(za(key,user_id)+message)


def verify_digest(key, digest, signature):
    try:
        q=parse_public(key)
        if len(digest)!=32 or len(signature)!=64: return False
        r=int.from_bytes(signature[:32],'big'); s=int.from_bytes(signature[32:],'big')
        if not (1<=r<N and 1<=s<N): return False
        t=(r+s)%N
        if not t: return False
        point=add(mul(s),mul(t,q))
        return point is not None and (int.from_bytes(digest,'big')+point[0])%N==r
    except (ValueError,TypeError): return False


def verify(key, message, signature, user_id=USER_ID):
    try: return verify_digest(key,message_digest(key,message,user_id),signature)
    except (ValueError,TypeError): return False


def fixture_sign(d, message, k, user_id=USER_ID):
    """Known, caller-supplied NONCE FOR TEST VECTORS ONLY; never use for real keys."""
    if not (1<=d<N-1 and 1<=k<N): raise ValueError('invalid test scalar')
    q=encode_public(mul(d)); e=int.from_bytes(message_digest(q,message,user_id),'big')
    r=(e+mul(k)[0])%N
    if r==0 or r+k==N: raise ValueError('nonce requires retry')
    s=pow(1+d,-1,N)*(k-r*d)%N
    if s==0: raise ValueError('nonce requires retry')
    return be32(r)+be32(s)
