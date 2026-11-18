// Emits post-Genesis BSV Script. Stack indices in the generator are zero-based
// from the bottom. Every operation below emits ordinary opcodes or pushed data.
const field = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const order = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const curveB = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;
const gx = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n;
const gy = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n;
const k1Order = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const k1Gx = '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
export const signingTag = 'BSV/SecureEnclave/P256/v1\0';

const OP = Object.freeze({
  EQUAL: '87', ADD: '93', SUB: '94', MUL: '95', DIV: '96', MOD: '97',
  BOOLAND: '9a', BOOLOR: '9b', NUMEQUAL: '9c', LESSTHAN: '9f',
  MIN: 'a3', CAT: '7e'
});

const byte = x => Number(x).toString(16).padStart(2, '0');
const ascii = s => Array.from(s, c => byte(c.charCodeAt(0))).join('');

function numberPush(n) {
  let value = BigInt(n);
  if (value < 0n) throw new Error('expected unsigned constant');
  if (value === 0n) return '00';
  if (value <= 16n) return byte(0x50n + value);
  let encoded = '';
  while (value) {
    encoded += byte(value & 255n);
    value >>= 8n;
  }
  if (parseInt(encoded.slice(-2), 16) >= 128) encoded += '00';
  return byte(encoded.length / 2) + encoded;
}

class Script {
  constructor(depth) { this.depth = depth; this.chunks = []; }
  emit(hex, change) {
    this.chunks.push(hex);
    this.depth += change;
    return this.depth - 1;
  }
  num(n) { return this.emit(numberPush(n), 1); }
  data(hex) {
    if (/^(0[1-9a-f]|10)$/i.test(hex)) return this.num(parseInt(hex,16));
    if (hex.length % 2 || hex.length > 150) throw new Error('literal length');
    return this.emit(byte(hex.length / 2) + hex, 1);
  }
  copy(slot) {
    if (slot < 0 || slot >= this.depth) throw new Error('invalid stack slot');
    this.num(this.depth - 1 - slot);
    return this.emit('79', 0); // PICK
  }
  op(hex, left, right) {
    this.copy(left); this.copy(right);
    return this.emit(hex, -1);
  }
  keep(base, slots) {
    for (const slot of [...slots].reverse()) {
      this.copy(slot); this.emit('6b', -1); // TOALTSTACK
    }
    while (this.depth >= base + 2) this.emit('6d', -2); // 2DROP
    if (this.depth > base) this.emit('75', -1);
    return slots.map(() => this.emit('6c', 1));
  }
  length(slot, bytes) {
    this.copy(slot); this.emit('82', 1); this.num(bytes);
    this.emit('9d75', -3); // NUMEQUALVERIFY DROP
  }
  slice(slot, start, length) {
    this.copy(slot); this.num(start); this.emit('7f77', -1); // SPLIT NIP
    this.num(length); return this.emit('7f75', -1); // SPLIT DROP
  }
  reverse32() {
    for (let i = 1; i < 32; ++i) this.emit('517f7c6b', 0);
    for (let i = 1; i < 32; ++i) this.emit('6c7e', 0);
  }
  uint256be(slot) {
    this.copy(slot); this.reverse32();
    return this.emit('01007e81', 0); // append sign byte, BIN2NUM
  }
}

// Complete homogeneous-projective addition, Renes–Costello–Batina,
// Appendix A.1. All coordinates and temporaries are residues modulo p.
function pointAdd(c, L, R, p, a, b3) {
  const base = c.depth;
  const reduce = t => c.op(OP.MOD, t, p);
  const mul = (x,y) => reduce(c.op(OP.MUL, x, y));
  const add = (x,y) => reduce(c.op(OP.ADD, x, y));
  const sub = (x,y) => reduce(c.op(OP.ADD, c.op(OP.SUB, x, y), p));
  const [x,y,z] = L, [u,v,w] = R;
  const xx = mul(x,u), yy = mul(y,v), zz = mul(z,w);
  const pair = (i,j,k,l,ik,jl) => sub(sub(mul(add(i,j),add(k,l)),ik),jl);
  const xy = pair(x,y,u,v,xx,yy), xz = pair(x,z,u,w,xx,zz);
  const yz = pair(y,z,v,w,yy,zz);
  const h = add(mul(a,xz), mul(b3,zz));
  const minus = sub(yy,h), plus = add(yy,h);
  const azz = mul(a,zz);
  const t = add(add(add(xx,xx),xx),azz);
  const k = add(mul(b3,xz),mul(a,sub(xx,azz)));
  return c.keep(base, [
    sub(mul(xy,minus),mul(yz,k)),
    add(mul(minus,plus),mul(t,k)),
    add(mul(yz,plus),mul(xy,t))
  ]);
}

function verifyR1(c, qx, qy, r, s, digest) {
  const p = c.num(field), n = c.num(order), zero = c.num(0), one = c.num(1);
  const two = c.num(2), three = c.num(3), a = c.num(field-3n);
  const b = c.num(curveB), b3 = c.num(3n*curveB % field);
  for (const [value,lower,upper] of [[qx,zero,p],[qy,zero,p],[r,one,n],[s,one,n]]) {
    c.copy(value); c.copy(lower); c.copy(upper); c.emit('a569', -3); // WITHIN VERIFY
  }
  const mulMod = (x,y,m) => c.op(OP.MOD,c.op(OP.MUL,x,y),m);
  const xsq = mulMod(qx,qx,p), ysq = mulMod(qy,qy,p);
  const rhs = c.op(OP.ADD, c.op(OP.ADD,mulMod(xsq,qx,p),mulMod(a,qx,p)), b);
  c.op(OP.NUMEQUAL,ysq,c.op(OP.MOD,rhs,p)); c.emit('69',-1);

  // Fermat inversion. The exponent and number of rounds are fixed at build time.
  const scratch = c.depth;
  let inv = c.copy(one);
  for (const bit of (order-2n).toString(2)) {
    inv = mulMod(inv,inv,n);
    if (bit === '1') inv = mulMod(inv,s,n);
    [inv] = c.keep(scratch,[inv]);
  }
  const u = mulMod(digest,inv,n), v = mulMod(r,inv,n);
  const inf = [zero,one,zero], G = [c.num(gx),c.num(gy),one], Q = [qx,qy,one];
  const GQ = pointAdd(c,G,Q,p,a,b3);
  const table = c.depth;
  for (const point of [inf,G,Q,GQ]) for (const coord of point) c.copy(coord);
  const roundBase = c.depth;
  let acc = inf.map(coord => c.copy(coord));
  for (let bit = 255; bit >= 0; --bit) {
    const doubled = pointAdd(c,acc,acc,p,a,b3);
    const pow = c.num(1n << BigInt(bit));
    const getBit = value => c.op(OP.MOD,c.op(OP.DIV,value,pow),two);
    const index = c.op(OP.ADD, getBit(u),c.op(OP.MUL,two,getBit(v)));
    const offset = c.op(OP.MUL,three,index);
    const selected = [0,1,2].map(axis => {
      c.num(c.depth-1-table-axis); c.copy(offset);
      c.emit('94',-1); return c.emit('79',0);
    });
    const sum = pointAdd(c,doubled,selected,p,a,b3);
    acc = c.keep(roundBase,sum);
  }
  const [X,,Z] = acc;
  c.copy(Z); c.emit('69',-1); // reject infinity
  // x mod n == r iff x is r or r+n below p. X/Z is affine x.
  const same = c.op(OP.NUMEQUAL,X,mulMod(r,Z,p));
  const rPlusN = c.op(OP.ADD,r,n);
  const second = c.op(OP.BOOLAND,c.op(OP.LESSTHAN,rPlusN,p),c.op(OP.NUMEQUAL,X,mulMod(rPlusN,Z,p)));
  c.op(OP.BOOLOR,same,second); c.emit('69',-1);
}

function transactionBinding(c, preimage, type) {
  c.copy(preimage); const hash = c.emit('aa',0);
  const z = c.uint256be(hash), n = c.num(k1Order);
  const rawS = c.op(OP.MOD,c.op(OP.ADD,z,c.num(BigInt('0x'+k1Gx))),n);
  c.copy(rawS); c.emit('69',-1);
  const lowS = c.op(OP.MIN,rawS,c.op(OP.SUB,n,rawS)); // MIN
  c.copy(lowS); c.emit('826b',0); // save minimal signed byte length
  c.num(32); c.emit('80',-1); c.reverse32();
  c.num(32); c.emit('6c947f77',-1); // take minimal big-endian DER integer
  const derS = c.depth-1;
  // s is low, hence 1..32 bytes; DER one-byte lengths suffice.
  const header = c.data('0220'+k1Gx+'02');
  c.copy(derS); c.emit('8277',0); const slen = c.depth-1;
  const seqLen = c.op(OP.ADD,slen,c.num(36));
  let sig = c.op(OP.CAT,c.data('30'),seqLen);
  for (const part of [header,slen,derS,type]) sig = c.op(OP.CAT,sig,part);
  c.keep(0,[sig]);
  c.data('02'+k1Gx);
  c.emit('abac',-1); // CODESEPARATOR CHECKSIG: scriptCode is exactly ac
}

// Unlocking pushes in order: raw parent transaction, ForkID preimage,
// X9.63 uncompressed P-256 public key, then raw P-256 signature r||s.
export function lockingScriptHex(ownerHash160, allowedTypes = [0x41]) {
  if (typeof ownerHash160 !== 'string' || !/^[a-f0-9]{40}$/i.test(ownerHash160)) throw new Error('expected a 20-byte owner hash');
  if (!Array.isArray(allowedTypes) || !allowedTypes.length ||
      allowedTypes.some(t => ![0x41,0xc1,0x43,0xc3].includes(t))) throw new Error('unsupported sighash');
  const c = new Script(4);
  c.emit('74549d',0); // DEPTH 4 NUMEQUALVERIFY
  const [parent,P,Q,sig] = [0,1,2,3];
  c.length(P,158); c.length(Q,65); c.length(sig,64);
  const prefix = c.slice(Q,0,1);
  c.copy(prefix); c.data('04'); c.emit('88',-2);
  c.copy(Q); c.emit('a9',0); c.data(ownerHash160); c.emit('88',-2);
  const txid = c.slice(P,68,32);
  c.copy(parent); c.emit('aa',0); c.copy(txid); c.emit('88',-2);
  const scriptCode = c.slice(P,104,2);
  c.copy(scriptCode); c.data('01ac'); c.emit('88',-2);
  const type = c.slice(P,154,1), upper = c.slice(P,155,3);
  c.copy(upper); c.data('000000'); c.emit('88',-2);
  let allowed = c.num(0);
  for (const t of new Set(allowedTypes)) {
    const match = c.op(OP.EQUAL,type,c.data(byte(t)));
    allowed = c.op(OP.BOOLOR,allowed,match);
  }
  c.copy(allowed); c.emit('69',-1);
  // A SINGLE spend of this payment template must have its paired output.
  const single = c.op(OP.BOOLOR,c.op(OP.EQUAL,type,c.data('43')),c.op(OP.EQUAL,type,c.data('c3')));
  c.copy(single); c.emit('63',-1);
  const branchBase = c.depth;
  const outputs = c.slice(P,118,32); c.copy(outputs); c.data('00'.repeat(32));
  c.emit('879169',-2); // EQUAL NOT VERIFY
  c.keep(branchBase,[]); c.emit('68',0);
  const message = c.op(OP.CAT,c.data(ascii(signingTag)),P);
  c.copy(message); const hash = c.emit('a8',0);
  const digest = c.uint256be(hash);
  const coord = (slot, off) => c.uint256be(c.slice(slot,off,32));
  verifyR1(c,coord(Q,1),coord(Q,33),coord(sig,0),coord(sig,32),digest);
  transactionBinding(c,P,type);
  return c.chunks.join('');
}

function pushField(hex) {
  if (typeof hex !== 'string' || !/^(?:[a-f0-9]{2})+$/i.test(hex)) {
    throw new Error('expected a nonempty even-length hex string');
  }
  const size = hex.length / 2;
  if (size <= 75) return byte(size) + hex;
  if (size <= 255) return '4c' + byte(size) + hex;
  if (size <= 65535) return '4d' + byte(size & 255) + byte(size >>> 8) + hex;
  if (size > 0xffffffff) throw new Error('field exceeds PUSHDATA4');
  return '4e' + [0, 8, 16, 24].map(shift => byte((size >>> shift) & 255)).join('') + hex;
}

export function unlockingScriptHex(parentHex, preimageHex, x963PublicKeyHex, rawSignatureHex) {
  if (preimageHex?.length !== 316 || x963PublicKeyHex?.length !== 130 ||
      !x963PublicKeyHex.startsWith('04') || rawSignatureHex?.length !== 128) {
    throw new Error('expected a 158-byte preimage, a 65-byte X9.63 key and a 64-byte signature');
  }
  return [parentHex, preimageHex, x963PublicKeyHex, rawSignatureHex].map(pushField).join('');
}
