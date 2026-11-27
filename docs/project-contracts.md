# Project WASM packages and spend fixtures

[简体中文](project-contracts.zh-CN.md)

A project package pairs exact Script bytes, parameter slots, signing anchors, a fixture set, and a project WASM module. The manifest identifies the build and spending paths. The host opens the package approved by its digest and checks the actual parent output before requesting authorization. R1 ordinary payment and PELS Counter are the two fixture projects.

```sh
export PYTHONPATH=src:.
python3 tools/build_project_contract.py p2pkh-r1 workspace/r1-package --verify
python3 tools/build_project_contract.py pels-counter workspace/counter-package --verify
```

Verification uses pinned chain-gang and the repository's offline fixture keys. `--smoke` uses fresh R1 keys in memory. `--with-bsv-node` also checks a configured local regtest node. The host requires Node.js for the WASI preview1 runtime. A public replay can verify the receipt with the approved manifest hash and the actual transactions recorded in the receipt.

The generic ABI exposes `recognize`, `prepare_spend`, and `assemble_unlock`. Supply an explicit integer for `prevout.amount`, including zero. The module returns `MissingContext` when that amount is missing or `null`. R1 and PELS Counter use BIP143 ALL. The neutral settlement bundle pairs one exact lock with BIP143 ALL and Chronicle OTDA ALL. Each settlement path records its authenticated fields, signature anchor, chain context and witness layout. The host recalculates the selected preimage and the verifier replays both paths against the same actual fixture parent. PELS Counter advances modulo 2³². [Commands and failure cases](project-contracts.zh-CN.md) · [Host implementation](../src/fourthgraph/workflow/project_contract.py)

<a name="preimage-constructor"></a>

## Preimage constructor selection

A WASM project computes the complete preimage from the approved transaction, actual prevout and executed signing path in `prepare_spend`. It returns the bytes and their SHA256d digest to the host. When a path requires a wallet signature, the host supplies that digest to its signer. PELS binds the complete preimage to the current input.

For a lock that accepts a complete preimage on the stack, run `4thgraph preimage-constructor request.json` to compile its push operation separately. The request supplies wire-format `parent_hex` and `transaction_hex`, `input_index`, the integer `sighash`, the approved `script_code_hex` and `chronicle_active` from the chain context. Optional `templates` entries contain `script_hex` and ordered `fields` with byte `offset` and `length`. Supply the path's `companion_code_hex` where required. `witness_tail_bytes` includes any Script bytes appended after the constructor.

Pass the existing WASM `prepare_spend` result as `prepared` to check its transaction hash, outpoint, input index, sighash, preimage and digest. The compiler evaluates each eligible program and requires one exact preimage and an empty alternate stack. Functional constructors are eligible for Chronicle-active version-2 OTDA ALL and paired SINGLE. It ranks by the serialized input Script field, including CompactSize, and returns the chosen `program_hex` and candidate records. Use `mode: "literal"` for a literal control or `max_payload_bytes` to constrain the measured constructor payload. Production selection currently runs in the compiler and Schnorr wallet. The WASM ABI's prepare call stays in charge of deriving the preimage and digest. Paths with a packed-context stack layout continue to use their declared encoder. [Compiler entry](../src/fourthgraph/workflow/preimage_constructor.py) · [Dual-engine matrix](../projects/p2pkh-schnorr/experiments/high-level/constructor-matrix.json)
