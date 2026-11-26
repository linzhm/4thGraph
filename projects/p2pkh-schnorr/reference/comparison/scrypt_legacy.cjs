"use strict";

const { execFileSync } = require("node:child_process");
const { createHash } = require("node:crypto");
const { mkdtempSync, readFileSync, realpathSync, rmSync } = require("node:fs");
const { createRequire } = require("node:module");
const { tmpdir } = require("node:os");
const { join } = require("node:path");

const sourceCommit = "7b2cd79d005b2fcdc3c992d039efd619fb47abf7";
const compilerSha256 = "889b8797ed04412e2ea6c0cc56ef5bfcdfb54451c162bcfbc12a6dd43325777b";

if (process.argv.length !== 3 || !process.env.SCRYPTC) {
  throw new Error("usage: SCRYPTC=/path/to/scryptc node scrypt_legacy.cjs UPSTREAM_CHECKOUT");
}
const source = realpathSync(process.argv[2]);
const compiler = realpathSync(process.env.SCRYPTC);
const contractPath = "contracts/schnorr.scrypt";
const arithmeticPath = "contracts/ec.scrypt";
const actualCommit = execFileSync("git", ["rev-parse", "HEAD"], { cwd: source, encoding: "utf8" }).trim();
if (actualCommit !== sourceCommit) throw new Error("expected the pinned sCrypt commit " + sourceCommit);
execFileSync("git", ["diff", "--quiet", "HEAD", "--", contractPath, arithmeticPath, "package-lock.json"],
  { cwd: source });
const digest = createHash("sha256").update(readFileSync(compiler)).digest("hex");
if (digest !== compilerSha256) throw new Error("expected the pinned Linux x86-64 compiler");
process.env.SCRYPTC = compiler;

const load = createRequire(join(source, "package.json"));
if (load("scryptlib/package.json").version !== "2.1.36") throw new Error("run npm ci in the pinned checkout");
const { bsv, buildContractClass, compileContract, PubKey, Bytes, Sig, Int, DEFAULT_FLAGS } = load("scryptlib");

// Deterministic public test fixture for the linked legacy implementation,
// with the same message and public-key x as official BIP340 test vector zero.
const message = "00".repeat(32);
const publicKey = "04f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9" +
  "388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672";
const signature = "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f292506" +
  "d072d3fc3d9dbb63f9be397c6fafaf8f00556abc28b68e732c993919bed098";
const noncePoint = {
  x: Int("10528302870886930155018956035531801295006046805503783683817619163573847470564"),
  y: Int("93775756143006431917783992996469581955679034112151104528936240294480420298956"),
};

const scratch = mkdtempSync(join(tmpdir(), "scrypt-schnorr-"));
try {
  const compiled = compileContract(join(source, contractPath), { out: scratch });
  if (compiled.errors.length) throw new Error(JSON.stringify(compiled.errors));
  const Contract = buildContractClass(compiled);
  const contract = new Contract();
  const lock = contract.lockingScript;
  const unlock = contract.verify(Sig(signature), PubKey(publicKey), Bytes(message), noncePoint).unlockingScript;
  const interpreter = new bsv.Script.Interpreter();
  const sdkVerdict = interpreter.verify(unlock, lock, new bsv.Transaction(), 0, DEFAULT_FLAGS, new bsv.crypto.BN(10_000));
  process.stdout.write(JSON.stringify({
    sourceCommit,
    compilerSha256,
    message,
    publicKey,
    lock: lock.toHex(),
    unlock: unlock.toHex(),
    sdkVerdict,
    sdkError: interpreter.errstr,
  }) + "\n");
} finally {
  rmSync(scratch, { recursive: true, force: true });
}
