// Deterministic offline input-0 fixture. No wallet, node connection, or network I/O.
import assert from 'node:assert/strict';
import { createHash, createPublicKey, verify } from 'node:crypto';
import { lockingScriptHex, unlockingScriptHex, signingTag } from './script.mjs';

const bytes = hex => Buffer.from(hex, 'hex');
const sha = data => createHash('sha256').update(data).digest();
const hash256 = hex => sha(sha(bytes(hex))).toString('hex');
const le = (value, size) => {
  const hex = BigInt(value).toString(16).padStart(size * 2, '0');
  return Buffer.from(hex, 'hex').reverse().toString('hex');
};
function sizePrefix(n) {
  if (n < 253) return le(n,1);
  if (n <= 65535) return 'fd' + le(n,2);
  return 'fe' + le(n,4);
}
const scriptField = script => sizePrefix(script.length / 2) + script;
const out = (sats, script) => le(sats,8) + scriptField(script);
const seq = 'ffffffff';
const input = (op, unlock) => op + scriptField(unlock) + seq;
const pub = '048e533b6fa0bf7b4625bb30667c01fb607ef9f8b8a80fef5b300628703187b2a373eb1dbde03318366d069f83a6f5900053c73633cb041b21c55e1a86c1f400b4';
const sig = '3ae7b158956c12b5f1429b6702bac89acf3d728f5aed1ca7f2d26d98b4923e7051f325c04de0c4eece97768385fc43132a4e5d0cf1b0ba2b338683398545bb22';
const owner = createHash('ripemd160').update(sha(bytes(pub))).digest('hex');
const lock = lockingScriptHex(owner);
assert.equal(lock.length / 2, 339383);
assert.equal(hash256(lock), '5e47f0a7a32cadefbda4fdb2c088080fed6558b97b72e00742e730082a30d0a6');

const version = '01000000';
const locktime = '00000000';
const parent = version + '01' + input('11'.repeat(32) + le(0,4), '') +
  '01' + out(1000,lock) + locktime;
const source = hash256(parent) + le(0,4);
const other = '22'.repeat(32) + le(2,4);
const outputs = out(800,'51') + out(300,'51');
const preimage = version + hash256(source + other) + hash256(seq + seq) +
  source + '01ac' + le(1000,8) + seq + hash256(outputs) + locktime + '41000000';
const message = Buffer.concat([Buffer.from(signingTag,'ascii'),bytes(preimage)]);
assert.equal(sha(message).toString('hex'),'d5b920e40e013207d71081049ea9bfece1da8bc67e8f4ec5e6bdc04a3719b870');
const key = createPublicKey({
  key: bytes('3059301306072a8648ce3d020106082a8648ce3d030107034200' + pub),
  type: 'spki', format: 'der'
});
assert.ok(verify('sha256',message,{ key, dsaEncoding:'ieee-p1363' },bytes(sig)));
const unlock = unlockingScriptHex(parent,preimage,pub,sig);
const prefix = version + '02' + input(source,unlock) + input(other,'') + '02';
if (process.argv.includes('--rpc')) {
  // Digest checks remain on. Both cases use the identical original scriptSig.
  // The second changes output 1, which is covered by the default ALL mode.
  const flags = (1<<1)|(1<<2)|(1<<3)|(1<<5)|(1<<6)|(1<<16)|(1<<18)|(1<<19);
  const scripts = [outputs, out(800,'51')+out(299,'51')].map(serialized => ({
    tx: prefix + serialized + locktime, n: 0, flags, reportflags: true,
    txo: { lock, value: 1000 }
  }));
  console.log(JSON.stringify({ jsonrpc:'1.0', id:'p256-input-0',
    method:'verifyscript', params:[scripts,false,10000] }));
} else {
  console.log(JSON.stringify({ owner, lockingScriptBytes:lock.length/2,
    unlockingScriptBytes:unlock.length/2, p256Digest:sha(message).toString('hex'),
    publicVectorSignatureVerified:true },null,2));
}
