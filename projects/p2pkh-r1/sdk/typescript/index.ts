import { createHash, ECDH } from "node:crypto";
import { Buffer } from "node:buffer";

const start = 208;
const end = 228;
const header = /^760052a569766b7c8201[0-9a-f]{396}([0-9a-f]{40})$/;
const fingerprints = new Map([
  [59_582, "2129d374594069d08a9b2127555f48ea21c75fb06d1ad5e77c68ad251e97f784"],
  [47_510, "2c514b452c30fe908bfb59a5b630ec4402c5f356717c1235ffa75c0c1df8e208"],
  [46_302, "52a1d9eb9e236403c66e845e18cf31d9c3a5f4c2e0ed7ca0270a60ba4e867ca6"],
]);

/** Input begins at the first opcode, without a CompactSize prefix. */
export function recognize(script: Uint8Array): Buffer | null {
  const fingerprint = fingerprints.get(script.length);
  if (!fingerprint) return null;
  const match = header.exec(Buffer.from(script.subarray(0, end)).toString("hex"));
  if (!match) return null;
  const digest = createHash("sha256").update(script.subarray(0, start))
    .update(script.subarray(end)).digest("hex");
  return digest === fingerprint ? Buffer.from(match[1], "hex") : null;
}

export function lockForOwner(template: Uint8Array, owner: Uint8Array): Buffer {
  if (owner.length !== 20) throw new Error("expected a 20-byte owner hash");
  const script = Buffer.from(template);
  if (!recognize(script)) throw new Error("unrecognized P2PKH-R1 template");
  script.set(owner, start);
  return script;
}

export function lockForKey(template: Uint8Array, key: Uint8Array): Buffer {
  if (key.length !== 65 || key[0] !== 4) throw new Error("expected uncompressed P-256 public key");
  const point = ECDH.convertKey(key, "prime256v1", undefined, undefined, "uncompressed");
  const sha = createHash("sha256").update(point).digest();
  return lockForOwner(template, createHash("ripemd160").update(sha).digest());
}
