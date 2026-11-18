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
