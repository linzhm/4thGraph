import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { lockForKey as r1LockForKey, lockForOwner as r1LockForOwner, recognize as r1Recognize } from "../../../p2pkh-r1/sdk/typescript/index.ts";

const fields = [[1, 21], [22, 54], [109, 117], [134, 166]] as const;
const fingerprint = "c81b70f59e00402fb3cd936d174e7c8a45eb8205a18b3ad43fac29e93f58ccb4";
const zero = Buffer.alloc(32);

function sha256(bytes: Uint8Array): Buffer {
  return createHash("sha256").update(bytes).digest();
}

function canonical(script: Uint8Array): boolean {
  if (script.length !== 1435) return false;
  const fixed = Buffer.from(script);
  for (const [start, end] of fields) fixed.fill(0, start, end);
  return sha256(fixed).toString("hex") === fingerprint;
}

function isLegacy(script: Uint8Array): boolean {
  return script.length === 1480 && script[0] === 65 && script[1] === 4;
}

function compactTemplate(template: Uint8Array, ownerHash160: Uint8Array): Buffer {
  return isLegacy(template)
    ? Buffer.concat([Buffer.from([20]), ownerHash160, template.subarray(66)])
    : Buffer.from(template);
}

function buildLock(template: Uint8Array, target: Uint8Array, ownerHash160: Uint8Array, satoshis: bigint): Buffer {
  const script = compactTemplate(template, ownerHash160);
  if (!canonical(script)) throw new Error("unrecognized deferred template");
  if (satoshis < 0n || satoshis > 2_100_000_000_000_000n) throw new RangeError("invalid amount");
  const header = Buffer.alloc(11);
  header.writeBigUInt64LE(satoshis);
  header[8] = 0xfd;
  header.writeUInt16LE(target.length, 9);
  const outputHash = sha256(sha256(Buffer.concat([header, target])));
  if (outputHash.equals(zero)) throw new Error("zero target commitment");
  script.set(ownerHash160, 1);
  script.set(sha256(target), 22);
  script.set(header.subarray(0, 8), 109);
  script.set(outputHash, 134);
  return script;
}

export function lockForOwner(template: Uint8Array, r1Template: Uint8Array,
  ownerHash160: Uint8Array, satoshis: bigint): Buffer {
  return buildLock(template, r1LockForOwner(r1Template, ownerHash160), ownerHash160, satoshis);
}

export function lockForKey(template: Uint8Array, r1Template: Uint8Array,
  publicKey: Uint8Array, satoshis: bigint): Buffer {
  const target = r1LockForKey(r1Template, publicKey);
  const owner = r1Recognize(target);
  if (!owner) throw new Error("unrecognized target R1 lock");
  return buildLock(template, target, owner, satoshis);
}

export interface Commitment {
  ownerHash160: Buffer;
  /** Present only if the previous output disclosed a full public key. */
  publicKey?: Buffer;
  targetScriptSha256: Buffer;
  targetTxOutHash256: Buffer;
}

export function recognize(r1Template: Uint8Array, rawScript: Uint8Array,
  satoshis: bigint): Commitment | null {
  try {
    const script = Buffer.from(rawScript);
    const publicKey = isLegacy(script) ? script.subarray(1, 66) : undefined;
    const ownerHash160 = publicKey ? r1Recognize(r1LockForKey(r1Template, publicKey)) : script.subarray(1, 21);
    if (!ownerHash160) return null;
    const compact = compactTemplate(script, ownerHash160);
    if (!lockForOwner(compact, r1Template, ownerHash160, satoshis).equals(compact)) return null;
    return {ownerHash160, publicKey, targetScriptSha256: compact.subarray(22, 54),
      targetTxOutHash256: compact.subarray(134, 166)};
  } catch {
    return null;
  }
}

/** Encode the paired output preimage and optional type byte plus selected transaction digest. */
export function activationWitness(r1Template: Uint8Array, script: Uint8Array,
  satoshis: bigint, preimage: Uint8Array, auxiliary?: Uint8Array): Buffer {
  const commitment = recognize(r1Template, script, satoshis);
  const pre = Buffer.from(preimage);
  const code = Buffer.from(auxiliary ? "04ad68abac" : "01ac", "hex");
  const valueOffset = 104 + code.length;
  if (!commitment || pre.length !== valueOffset + 52 || !pre.subarray(104, valueOffset).equals(code) ||
      pre.readBigUInt64LE(valueOffset) !== satoshis ||
      !pre.subarray(valueOffset + 12, valueOffset + 44).equals(commitment.targetTxOutHash256))
    throw new Error("activation preimage does not match the funding output");
  const bindingType = pre.readUInt32LE(pre.length - 4);
  if (bindingType !== 0x43 && bindingType !== 0xc3) throw new Error("expected ForkID SINGLE");
  const bound = Buffer.concat([Buffer.from([0x4c, pre.length]), pre]);
  if (!auxiliary) return bound;
  const type = auxiliary[0];
  const normalized = type & 0x5f;
  if (auxiliary.length !== 33 || normalized < 0x41 || normalized > 0x43 ||
      type === 0x43 || type === 0xc3 || (type & 0x80) !== (bindingType & 0x80))
    throw new Error("invalid auxiliary activation digest");
  return Buffer.concat([Buffer.from([33]), auxiliary, bound]);
}
