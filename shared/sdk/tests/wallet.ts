import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { WalletClient, type Output, type SigningRequest, type WalletInput, type WalletRecognition } from "../typescript/index.ts";

const project = process.env.SCRIPT_LAB_SDK_PROJECT;
const fixture = process.env.SCRIPT_LAB_SDK_VECTOR;
const bridge = process.env.SCRIPT_LAB_SDK_BRIDGE;
if (!project || !fixture || !bridge) throw new Error("Missing SDK replay configuration");

interface Vector {
  profile: string;
  funding: string;
  vout: number;
  lock: string;
  recognition: WalletRecognition;
  request: WalletInput;
  outputs: Output[];
  metadata: Omit<SigningRequest, "payload" | "userId">;
  arguments: string[];
  signature: string | null;
  signed: string;
}

const vectors: Vector[] = JSON.parse(readFileSync(fixture, "utf8"));
assert.ok(vectors.length);
for (const row of vectors) {
  test(`${row.profile} 0x${row.request.sighash?.toString(16)}`, () => {
    const client = new WalletClient(project, { bridge, python: process.env.SCRIPT_LAB_SDK_PYTHON, template: row.profile });
    const prevout = client.prevoutFromFunding(row.funding, row.vout);
    assert.deepEqual(prevout, row.request.prevout);
    const scope = row.signature === null ? { valueSats: prevout.valueSats } : {};
    assert.equal(client.createLock({ publicKey: row.request.publicKey, ...scope }), row.lock);
    assert.deepEqual(client.recognize({ script: row.lock, publicKey: row.request.publicKey, ...scope }), row.recognition);
    if (row.recognition.ownerHash160) {
      assert.equal(client.createLock({ ownerHash160: row.recognition.ownerHash160, ...scope }), row.lock);
    }
    const { transaction, inputIndex, ...options } = row.request;
    const signature = row.signature;
    if (signature === null) {
      assert.equal(client.activate({ transaction, inputIndex, prevout, sighash: options.sighash,
        chronicleActive: options.chronicleActive }), row.signed);
      return;
    }
    let calls = 0;
    const signer = ({ payload, userId, ...metadata }: SigningRequest) => {
      calls++;
      assert.deepEqual(metadata, row.metadata);
      const args = userId ? [payload, userId] : [payload];
      assert.deepEqual(args.map((arg) => Buffer.from(arg).toString("hex")), row.arguments);
      return Buffer.from(signature, "hex");
    };
    const payment = { ...options, outputs: row.outputs, feeSats: "100" };
    assert.equal(client.signInput(row.request, signer), row.signed);
    assert.equal(client.signPayment(payment, signer), row.signed);
    assert.throws(() => client.signPayment({ ...payment, feeSats: "99" }, signer));
    assert.throws(() => client.signInput({ ...row.request, inputIndex: 1 }, signer));
    assert.equal(calls, 2);
  });
}
