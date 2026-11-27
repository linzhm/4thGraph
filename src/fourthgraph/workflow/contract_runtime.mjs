// Single invocation of a locally approved project reactor. No inherited WASI files or environment.
import { readFileSync, openSync } from "node:fs";
import { devNull } from "node:os";
import { createHash } from "node:crypto";
import { WASI } from "node:wasi";

const [filename, digest, entry] = process.argv.slice(2);
if (!["recognize", "prepare_spend", "assemble_unlock"].includes(entry)) throw Error("unknown ABI entry");
const raw = readFileSync(filename);
if (createHash("sha256").update(raw).digest("hex") !== digest) throw Error("module digest mismatch");
const input = readFileSync(0);
if (!input.length || input.length > 8 * 1024 * 1024) throw Error("ABI message outside permitted size");
const sink = openSync(devNull, "r+");
const wasi = new WASI({version: "preview1", args: [], env: {}, preopens: {},
                       stdin: sink, stdout: sink, stderr: sink, returnOnExit: true});
let instance;
const imports = {...wasi.getImportObject(), fourthgraph: {
    hash160(pointer, length, destination) {
        const data = new Uint8Array(instance.exports.memory.buffer, pointer, length);
        const sha = createHash("sha256").update(data).digest();
        new Uint8Array(instance.exports.memory.buffer, destination, 20).set(createHash("ripemd160").update(sha).digest());
    }
}};
const module = await WebAssembly.compile(raw);
instance = await WebAssembly.instantiate(module, imports);
const api = instance.exports;
if (["abi_buffer", "recognize", "prepare_spend", "assemble_unlock"].some(key => typeof api[key] !== "function")) {
    throw Error("missing required contract ABI export");
}
wasi.initialize(instance);
const pointer = api.abi_buffer(input.length);
if (!pointer) throw Error("module refused request size");
new Uint8Array(api.memory.buffer, pointer, input.length).set(input);
const encoded = BigInt.asUintN(64, api[entry](input.length));
const size = Number(encoded & 0xffffffffn);
if (size > 8 * 1024 * 1024) throw Error("oversize ABI result");
process.stdout.write(new Uint8Array(api.memory.buffer, Number(encoded >> 32n), size));
