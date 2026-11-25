import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";
import { lockForKey, lockForOwner, recognize } from "./index.ts";

const fixture = (name: string) => readFileSync(new URL(
  "../../template/" + name, import.meta.url), "utf8");
const base = Buffer.from(fixture("template.hex").replace(/\s/g, ""), "hex");
const layout = JSON.parse(fixture("layout.json"));

test("one template, three owners and two public constructors", () => {
  for (const v of layout.vectors) {
    const owner = Buffer.from(v.owner_hash160, "hex");
    const script = lockForOwner(base, owner);
    assert.equal(createHash("sha256").update(script).digest("hex"), v.script_sha256);
    assert.deepEqual(recognize(script), owner);
    if (v.public_key_x963) assert.deepEqual(lockForKey(base, Buffer.from(v.public_key_x963, "hex")), script);
  }
  assert.equal(createHash("sha256").update(base).digest("hex"), layout.base_script_sha256);
});

test("reject altered code, framing, malformed public keys and owner width", () => {
  for (const offset of [0, 100, 207, 228, base.length - 1]) {
    const changed = Buffer.from(base);
    changed[offset] ^= 1;
    assert.equal(recognize(changed), null);
    assert.throws(() => lockForOwner(changed, Buffer.alloc(20)));
  }
  assert.equal(recognize(base.subarray(1)), null);
  assert.equal(recognize(Buffer.concat([base, Buffer.alloc(1)])), null);
  assert.throws(() => lockForOwner(base, Buffer.alloc(19)));
  assert.throws(() => lockForKey(base, Buffer.alloc(32)));
  const offCurve = Buffer.alloc(65);
  offCurve[0] = 4;
  assert.throws(() => lockForKey(base, offCurve));
});

for (const [templateName, vectorName] of [
  ["template.hex", "spend-all.json"],
  ["candidates/compiled.hex", "candidates/spend-all.json"],
]) test(`ordinary payment from ${templateName} reproduces the signed transaction`, async () => {
  const { signPayment } = await import("./payment.ts");
  const v = JSON.parse(fixture(vectorName));
  const template = Buffer.from(fixture(templateName).replace(/\s/g, ""), "hex");
  const q = Buffer.from(v.public_key_x963, "hex");
  const p = { txid: Buffer.from(v.parent_txid, "hex"), vout: 0,
    inputSatoshis: 1000n, inputScript: lockForKey(template, q),
    outputs: [{satoshis: 900n, script: Buffer.from([0x51])}], fee: 100n };
  assert.deepEqual(recognize(p.inputScript), Buffer.from(v.owner_hash160, "hex"));
  const changed = Buffer.from(p.inputScript);
  changed[228] ^= 1;
  assert.equal(recognize(changed), null);
  const signed = await signPayment(p, q, digest => {
    assert.equal(digest.toString("hex"), v.digest_hex);
    return Buffer.from(v.signature_hex, "hex");
  });
  assert.ok(signed.includes(Buffer.from(v.script_sig_hex, "hex")));
  const first = createHash("sha256").update(signed).digest();
  assert.equal(createHash("sha256").update(first).digest().reverse().toString("hex"), v.signed_txid);
  await assert.rejects(signPayment(p, q, () => Buffer.alloc(64)), /invalid R1/);
  await assert.rejects(signPayment({...p, fee: 99n}, q, () => { throw Error("unexpected signer"); }), /balance/);
});
