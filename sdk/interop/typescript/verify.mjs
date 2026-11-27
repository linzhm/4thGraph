import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { KeyDeriver, PrivateKey, Spend, Transaction } from "@bsv/sdk";
import toolbox from "@bsv/wallet-toolbox";
import * as client from "@bsv/wallet-toolbox-client";
import * as mobile from "@bsv/wallet-toolbox-mobile";

function decodePayment(fixture) {
  const funding = Transaction.fromHex(fixture.funding);
  const signed = Transaction.fromHex(fixture.signed);
  const vout = fixture.vout ?? 0;
  assert.equal(funding.toHex(), fixture.funding);
  assert.equal(signed.toHex(), fixture.signed);
  assert.equal(signed.id("hex"), fixture.txid);
  assert.equal(signed.inputs.length, 1);
  assert.equal(signed.inputs[0].sourceTXID, funding.id("hex"));
  assert.equal(signed.inputs[0].sourceOutputIndex, vout);
  assert.ok(funding.outputs[vout]);
  return { funding, signed };
}

const fixture = JSON.parse(readFileSync(process.argv[2], "utf8"));
const { funding, signed } = decodePayment(fixture);
const [input] = signed.inputs;
const [output] = funding.outputs;

const keyDeriver = new KeyDeriver(PrivateKey.fromHex(fixture.senderTestKey));
for (const [name, walletTools] of Object.entries({ toolbox, client, mobile })) {
  const template = new walletTools.ScriptTemplateBRC29({
    keyDeriver,
    derivationPrefix: fixture.derivationPrefix,
    derivationSuffix: fixture.derivationSuffix,
  });
  const lock = template.lock(fixture.senderTestKey, fixture.recipientPublicKey);
  assert.equal(lock.toHex(), output.lockingScript.toHex(), name);
}

const spend = new Spend({
  sourceTXID: input.sourceTXID,
  sourceOutputIndex: input.sourceOutputIndex,
  sourceSatoshis: output.satoshis,
  lockingScript: output.lockingScript,
  transactionVersion: signed.version,
  otherInputs: [],
  outputs: signed.outputs,
  unlockingScript: input.unlockingScript,
  inputSequence: input.sequence,
  inputIndex: 0,
  lockTime: signed.lockTime,
});
assert.ok(spend.validate());
console.log(`TypeScript SDK and Wallet Toolbox (Node, browser and mobile packages): ${fixture.txid}`);

const projects = JSON.parse(readFileSync(process.argv[3], "utf8"));
for (const project of projects) {
  try {
    decodePayment(project);
  } catch (error) {
    throw new Error(`${project.project} v${project.release}: TypeScript SDK transaction round-trip failed`,
                    { cause: error });
  }
}
console.log(`TypeScript SDK: ${projects.length} project transactions round-tripped`);
