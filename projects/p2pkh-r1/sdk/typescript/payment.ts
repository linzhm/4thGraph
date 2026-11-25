import { Buffer } from "node:buffer";
import { createHash, createPublicKey, verify } from "node:crypto";
import { recognize } from "./index.ts";

export interface Payment {
  /** 32-byte funding transaction ID in explorer/display order. */
  txid: Uint8Array;
  vout: number;
  inputSatoshis: bigint;
  inputScript: Uint8Array;
  outputs: ReadonlyArray<{ satoshis: bigint; script: Uint8Array }>;
  fee: bigint;
}

const order = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const maxAmount = (1n << 63n) - 1n;
const version = Buffer.from("02000000", "hex");
const sequence = Buffer.from("ffffffff", "hex");
const locktime = Buffer.alloc(4);

function sha256(b: Uint8Array): Buffer {
  return createHash("sha256").update(b).digest();
}
function hash256(b: Uint8Array): Buffer {
  return sha256(sha256(b));
}
function amount(n: bigint): Buffer {
  if (n < 0n || n > maxAmount) throw new RangeError("invalid amount");
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(n);
  return b;
}
function uint32(n: number): Buffer {
  if (!Number.isInteger(n) || n < 0 || n > 0xffffffff) throw new RangeError("invalid uint32");
  const b = Buffer.alloc(4);
  b.writeUInt32LE(n);
  return b;
}
function compactSize(n: number): Buffer {
  if (n < 253) return Buffer.from([n]);
  if (n <= 65535) {
    const b = Buffer.alloc(3);
    b[0] = 253;
    b.writeUInt16LE(n, 1);
    return b;
  }
  if (n <= 0xffffffff) return Buffer.concat([Buffer.from([254]), uint32(n)]);
  return Buffer.concat([Buffer.from([255]), amount(BigInt(n))]);
}
function inverseLE(s: bigint): Buffer {
  let a = s, b = order, x = 1n, y = 0n;
  while (b !== 0n) {
    const q = a / b;
    [a, b] = [b, a % b];
    [x, y] = [y, x - q * y];
  }
  if (a !== 1n) throw new Error("invalid P-256 scalar");
  return Buffer.from(((x + order) % order).toString(16).padStart(64, "0"), "hex").reverse();
}

/** Spend one authenticated R1 UTXO with ForkID ALL. Returns the serialized transaction. */
export async function signPayment(p: Payment, publicKey: Uint8Array,
  signDigest: (digest: Buffer) => Promise<Uint8Array> | Uint8Array): Promise<Buffer> {
  return signPaymentWithMessage(p, publicKey, message => signDigest(sha256(message)));
}

/** Sign SHA256(P) with a device that applies SHA-256 internally. */
export async function signPaymentWithMessage(p: Payment, publicKey: Uint8Array,
  signMessage: (message: Buffer) => Promise<Uint8Array> | Uint8Array): Promise<Buffer> {
  const q = Buffer.from(publicKey);
  if (q.length !== 65 || q[0] !== 4) throw new Error("expected uncompressed P-256 key");
  const key = createPublicKey({ format: "jwk", key: {
    kty: "EC", crv: "P-256", x: q.subarray(1, 33).toString("base64url"), y: q.subarray(33).toString("base64url")
  }});
  const owner = recognize(p.inputScript);
  if (!owner?.equals(createHash("ripemd160").update(sha256(q)).digest())) throw new Error("wrong funding lock");
  if (p.txid.length !== 32 || !p.outputs.length) throw new Error("invalid outpoint or outputs");
  const inputValue = amount(p.inputSatoshis);
  if (p.fee < 0n || p.outputs.reduce((sum, o) => sum + o.satoshis, p.fee) !== p.inputSatoshis)
    throw new Error("payment does not balance");
  const outpoint = Buffer.concat([Buffer.from(p.txid).reverse(), uint32(p.vout)]);
  const outputs = Buffer.concat(p.outputs.flatMap(o => [amount(o.satoshis), compactSize(o.script.length), o.script]));
  const count = compactSize(p.outputs.length);
  const preimage = Buffer.concat([version, hash256(outpoint), hash256(sequence), outpoint,
    Buffer.from("0268ac", "hex"), inputValue, sequence, hash256(outputs), locktime, uint32(0x41)]);
  const message = sha256(preimage);
  const signature = Buffer.from(await signMessage(Buffer.from(message)));
  if (signature.length !== 64 || !verify("sha256", message, {key, dsaEncoding: "ieee-p1363"}, signature))
    throw new Error("invalid R1 digest signature");
  const s = BigInt("0x" + signature.subarray(32).toString("hex"));
  const witness = Buffer.concat([Buffer.from([0x4c, preimage.length]), preimage, Buffer.from([65]), q,
    Buffer.from([64]), signature, Buffer.from([32]), inverseLE(s), Buffer.from([0])]);
  return Buffer.concat([version, Buffer.from([1]), outpoint, compactSize(witness.length), witness,
    sequence, count, outputs, locktime]);
}
