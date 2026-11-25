import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import type { Config, LocalClient, Output, Recognition, Spend } from "../typescript/index.ts";

const project = process.env.SCRIPT_LAB_SDK_PROJECT;
const fixture = process.env.SCRIPT_LAB_SDK_VECTOR;
const bridge = process.env.SCRIPT_LAB_SDK_BRIDGE;
if (!project || !fixture || !bridge) throw new Error("Missing SDK replay configuration");
const { createClient }: { createClient(config: Config): LocalClient } = await import(
  new URL(`../../../projects/${project}/sdk/typescript/index.ts`, import.meta.url).href
);
const client = createClient({ bridge, python: process.env.SCRIPT_LAB_SDK_PYTHON });

interface Vector {
  profile: string;
  lock: string;
  recognition: Recognition;
  request: Spend;
  outputs: Output[];
  arguments: string[];
  signature: string;
  signed: string;
}

const vectors: Vector[] = JSON.parse(readFileSync(fixture, "utf8"));
for (const vector of vectors) {
  test(`${vector.profile} 0x${vector.request.sighash?.toString(16)}`, () => {
    const { transaction: _, ...options } = vector.request;
    const payment = { ...options, outputs: vector.outputs, feeSats: "100" };
    assert.equal(client.lock(options.publicKey, vector.profile), vector.lock);
    assert.deepEqual(client.recognize(vector.lock, options.publicKey), vector.recognition);
    if (vector.recognition.ownerHash160) assert.equal(client.lockForOwner(vector.recognition.ownerHash160), vector.lock);
    assert.equal(client.recognize("00" + vector.lock.slice(2), options.publicKey), null);
    let calls = 0;
    const signer = (...args: Uint8Array[]) => {
      calls++;
      assert.deepEqual(args.map((arg) => Buffer.from(arg).toString("hex")), vector.arguments);
      return Buffer.from(vector.signature, "hex");
    };
    assert.equal(client.signSpend(vector.request, signer), vector.signed);
    assert.equal(client.signPayment(payment, signer), vector.signed);
    assert.throws(() => client.signPayment({ ...payment, feeSats: "99" }, signer));
    assert.equal(calls, 2);
    assert.throws(() => client.signSpend(vector.request, () => Uint8Array.of(0)));
  });
}
