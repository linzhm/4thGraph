# 4thGraph standard library

[简体中文](stdlib.zh-CN.md)

Load source with Forth 2012 `REQUIRE filename`. The interface catalog and build reports identify registered modules as `std/…`.

## Module paths

| Purpose | `REQUIRE` paths |
| --- | --- |
| Language basics and Script fragments | `BSV`, `stdlib/u32.fth`, `stdlib/script-fragments.fth` |
| Repeated hashing | `stdlib/hash-chain.fth` |
| Fixed-width fields and byte constants | `stdlib/byte-layout.fth` |
| Native payments | `stdlib/p2pk.fth`, `stdlib/p2pkh.fth`, `stdlib/native-p2pk.fth`, `stdlib/native-p2pkh.fth` |
| Curve arithmetic and signature verification | `stdlib/p256.fth`, `stdlib/secp256k1.fth`, `stdlib/bip340.fth` |
| Wallet lock construction | `stdlib/wallet/` contains `r1.fth`, `p2pkh-r1-deferred.fth`, `p2pkh-sm2.fth`, `lamport-ots.fth`, `wots-plus.fth`, and `ml-dsa.fth` |
| Verification backends | `stdlib/verify.fth`, `stdlib/groth16-bls12-381.fth` |

For ordinary file paths, `REQUIRE` searches relative to the source file containing that directive, then checks the bundled library. In-memory source with no source path starts from the current working directory. `REQUIRE BSV` is a case-insensitive built-in alias. A bundled import of `stdlib/u32.fth` appears in the report as `std/u32` with an interface digest. When a project file with the same path is found first, the report records the project path and its source digest. [Import syntax](syntax.en.md) · [Catalog and path resolution](../../src/fourthgraph/stdlib/__init__.py)

### Transaction preimage construction

| Stage | Existing entry points and responsibilities |
| --- | --- |
| Off-chain construction | `preimage_forkid` and `preimage_otda` serialize the transaction preimage for the selected sighash mode. The caller supplies the current input index and the correct `scriptCode`. BIP143 also requires the previous output amount. [Serialization](../../src/fourthgraph/bsv/transaction.py) |
| On-chain reconstruction | PELS and Workflow reconstruct preimages from known transaction structure, linked `scriptCode`, and outputs constructed by the contract. The sighash mode and contract constraints determine which fields can be omitted. [Reconstruction](../../src/fourthgraph/workflow/forkid_lowering.py) |
| Authorization and spend binding | The wallet interface prepares ordinary and companion authorization paths. The lock uses native signature verification to bind the authorization to the actual spend. Unpaired OTDA SINGLE uses a special digest and has no serializable transaction preimage. [Authorization](../../src/fourthgraph/bsv/spend_authorization.py) · [Spend binding](../../src/fourthgraph/bsv/pushtx.py) |

The shared PELS entry supports a single-input `lock:` with a complete output vector built in Forth. The compile target and sighash policy determine the implementation. A lock that asserts the previous output amount needs BIP143 coverage in this implementation. Validate the selected path against its actual parent. [Build and assembly commands](../pels-locks.md)

## Public interfaces

| Module | Public interface | Example |
| --- | --- | --- |
| `std/bsv` | `REQUIRE BSV` loads `verify ( cell -- )` and supported native `OP_*` words | [P2PKH](../../projects/p2pk-p2pkh-baseline/forth/p2pkh.fth) |
| `std/pels` | `tx-output` constructs an expected output. `inputs=` and `outputs=` commit to one input and all ordered outputs. `tx-locktime` and `tx-prevout-amount` can be compared with constants. | [PELS settlement](../../projects/workflow-examples/pels-settle.fth) |
| `std/u32` | `u32-inc ( u32 -- u32 )`, wrapping at 32 bits | [PELS Counter](../../projects/pels-counter/pels-counter.fth) |
| `std/p2pk` | `p2pk-lock ( bytes -- bytes )` takes a 33-byte compressed public key and returns a lock script | [Source](../../src/fourthgraph/stdlib/p2pk.fth) · [P2PK](../../projects/p2pk-p2pkh-baseline/forth/p2pk.fth) |
| `std/p2pkh` | `p2pkh-lock ( bytes -- bytes )` takes a 20-byte public-key hash and returns a lock script | [Source](../../src/fourthgraph/stdlib/p2pkh.fth) · [P2PKH](../../projects/p2pk-p2pkh-baseline/forth/p2pkh.fth) |
| `std/native-p2pk`, `std/native-p2pkh` | Compile native payment locks with a bound recipient | [Payment build commands](../../projects/p2pk-p2pkh-baseline/forth/README.md) |
| `std/p256` | `p256-add` and `p256-double` use projective coordinates and preserve `p b3` at the bottom of the stack | [P-256 kernels](../../src/fourthgraph/stdlib/p256.fth) |
| `std/script-fragments` | Build fragments for stack movement, 32-byte reversal, and unsigned big-endian decoding | [Source](../../src/fourthgraph/stdlib/script-fragments.fth) |
| `std/hash-chain` | `sha256-chain-single` and `sha256-chain-pairs` build a fixed count of SHA-256 rounds or pairs. Each runtime region consumes one byte string. | [Hash kernels](../../src/fourthgraph/stdlib/hash-chain.fth) |
| `std/byte-layout` | Reverse packed 32-byte fields at a caller-checked width, or build a fixed byte string from a literal or a repeating seed. | [Byte kernels](../../src/fourthgraph/stdlib/byte-layout.fth) · [Binding experiments](../optimization-paths.md) |
| `std/secp256k1` | Homogeneous projective addition, mixed affine addition, doubling, and their scaled-coordinate kernels. `secp256k1-lambda-split` splits a scalar. `secp256k1-lambda-split-with-order` takes `k n` when the group order is already on the stack. | [Curve kernels](../../src/fourthgraph/stdlib/secp256k1.fth) |
| `std/bip340` | `bip340-verify ( script -- script )` builds a BIP340 verification fragment | [Payment example](../../projects/p2pkh-schnorr/README.md) |
| `std/groth16-bls12-381` | `groth16-bls12-381-verify ( -- groth16-verified )` compiles through the BLS12-381 verifier backend | [Forth source](../../src/fourthgraph/stdlib/groth16-bls12-381.fth) |
| `std/verify` | `relation: TRANSITION ROUTE ;` declares a relation available to multiple verification backends | [State verification](../../projects/proof-counter/verify-state.fth) |

Payment construction words check input widths. P2PK takes 33 bytes and P2PKH takes 20 bytes. The wallet interface also checks that a compressed public key represents a secp256k1 point. The spending Script verifies the signature with native `CHECKSIG`.

Files load into the caller's dictionary. Each file loads once per build, and a dependency cycle raises a build error. Builds record the SHA-256 digest of each loaded file and the interface digest of each registered module. Diagnostics and rewrite records can identify source lines and columns. `--capabilities` lists public stack signatures, parameters, failure behavior, and backends. [Syntax reference](syntax.en.md)

## Libraries, entry points, and artifacts

Forth libraries and applications use the same word definitions. Loading interprets top-level content, while a word's body runs when the word is invoked. Forth 2012 `REQUIRE` calls `REQUIRED` to avoid loading a file more than once. Gforth's `string.fs` uses `require` to declare dependencies and documents stack effects alongside string operations. 4thGraph runs `REQUIRE` at build time. [Forth 2012 REQUIRED](https://forth-standard.org/standard/file/REQUIRED) · [Gforth file loading](https://gforth.org/manual/Forth-source-files.html) · [Gforth string.fs](https://github.com/forthy42/gforth/blob/master/string.fs#L21)

- **Group words by caller requirements.** P2PK takes a compressed key and P2PKH takes a key hash, so callers can build the two locks independently. The P-256 addition and doubling words share field arithmetic and coordinate conventions. Related helper words can stay together in the same module. [Rust module organization](https://doc.rust-lang.org/book/ch07-02-defining-modules-to-control-scope-and-privacy.html)
- **List public words explicitly.** Register each export's stack signature, input contract, and failure behavior in the catalog. Helper words load with the file. Callers can use the documented exports to compare or extract individual words. [Scheme R7RS library declarations](https://standards.scheme.org/r7rs-html5/index.html#5.6.1)
- **Bind recipients at native payment entry points.** The P2PK and P2PKH examples load bundled `lock:` definitions. The build binds the recipient, and the spending Script executes the verification defined in the same Forth source. [Build and replay](../../projects/p2pk-p2pkh-baseline/forth/README.md)

The following example composes words from two modules. It leaves the wrapping counter and the generated P2PKH lock on the data stack. [Complete Forth source](../../projects/workflow-examples/library-composition.fth)

```forth
REQUIRE BSV
REQUIRE stdlib/u32.fth
REQUIRE stdlib/p2pkh.fth
: advance-and-pay ( u32 bytes -- u32 bytes ) swap u32-inc swap p2pkh-lock ;
```

```sh
PYTHONPATH=src:. python -m fourthgraph.workflow.protocol --capabilities
PYTHONPATH=src:. python -m fourthgraph.workflow.protocol "projects/workflow-examples/library-composition.fth" \
  --entry advance-and-pay --optimize stack
```

## Reusing PELS preimage reconstruction

The dynamic PELS words require BIP143 ALL (`0x41`), one input, and one successor output. Both take a Script prefix and a state/amount rule at build time. Start the assembled lock with a direct push of the five-byte current state (`05` followed by the state bytes), immediately followed by `OP_CODESEPARATOR` (`ab`). The bytes after the separator form the `scriptCode` and are copied verbatim into the successor. At spend time the rule consumes the current state and the previous amount as a ScriptNum. It leaves a five-byte successor state followed by an eight-byte unsigned little-endian amount.

With `REQUIRE stdlib/wallet/pels-verify.fth`, push `tail` first (the final eight preimage bytes, locktime followed by sighash type, four little-endian bytes each), then `head` (all preimage bytes before `hashOutputs`). The lock pushes `state` above them. `pels-verify` reconstructs and authenticates the preimage and leaves its digest. For the full-preimage variant, `pels-assert-successor` from `stdlib/wallet/pels-successor.fth` expects `preimage` at the top of the stack with `state` immediately below it. The caller must authenticate that same preimage against the actual input. [Standalone state-label fixture](../../tests/test_pels_successor_library.py) · [R1 composition example](../../projects/p2pkh-r1/forth/r1-pels-lock.fth)

Keep witness compression in the transaction compiler. The contract defines and constructs the complete ordered output vector. The reconstructor assembles the preimage for the selected sighash mode, and the authentication fragment binds that preimage to the actual spend with native `OP_CHECKSIG`. The Counter's single-successor construction and Workflow's ordered multi-output construction use this boundary. [Counter build and replay](../../projects/pels-counter/README.md) · [Reconstruction implementation](../../src/fourthgraph/workflow/forkid_lowering.py)

| Single-input path | Reconstructed fields | Requirements |
| --- | --- | --- |
| BIP143 ALL | `hashPrevouts`, `hashSequence`, `hashOutputs`, and sighash type. The packed context is 56 B when a fixed `scriptCode` is linked. | The contract can construct all outputs. The previous output amount stays in the packed context and is authenticated by the preimage. |
| OTDA ALL | Input record, output count, ordered outputs, and sighash type. The packed context is 48 B when a fixed `scriptCode` is linked. | The contract can construct all outputs and its constraints can be checked without the previous output amount, which OTDA does not commit to. |

The dual-mode Workflow lock selects the mode by the packed context length and passes the corresponding sighash type to the authentication fragment. Both branches consume the same ordered outputs. A contract that must verify the previous output amount selects the BIP143 path at build time.

The packed context accounts for part of the witness. Include the application witness and the added reconstruction code when comparing sizes. The Counter's self-referencing path can carry `scriptCode` and omit one copy once the linker checks that the two fragments match. Multi-input transactions, open outputs, and other sighash modes need separate proofs of which fields can be reconstructed. Existing callers continue to build from their current templates. [Reconstruction regression](../../tests/test_workflow.py) · [Counter witness regression](../../tests/test_counter_optimization.py)

<a id="验证路径"></a>

## Verification paths

`relation:` declares a public `current → next → route` relation. Each candidate checks the same deployed state, actual input, settlement or review output, and receipt for the next state. Circuit backends use the public signal order `next, route, current, bindLo, bindHi`. A proof-based path derives SHA-256d from the authenticated BIP143 ALL preimage and checks the two binding fields in the proof.

| Path | Eligibility |
| --- | --- |
| Direct Script | Both words can lower to Script, and policy allows direct verification |
| Transparent R1CS | The same Forth compiles to a circuit, pinned Circom and snarkjs are available, and policy permits a transparent assignment |
| BLS12-381 Groth16 | snarkjs verifies the external `.zkey` and Phase 2 `.ptau` against the generated BLS12-381 R1CS |

The planner ranks eligible candidates by the upper bound on serialized deployment lock and one spend witness by default. `--objective lock-bytes` ranks by deployment lock size. BLS12-381 prices three witness layouts separately. The report records the choice, exclusions, library digests, R1CS, and verification-key digest. Replay also records complete deployment and spend bytes and both engines' verdicts.

`compilations` reports the direct verification lock bytes and the generated Circom source, with build status and candidate eligibility recorded separately. `--max-expanded-ops` limits expansion before either backend and counts repeated calls and branches in the call graph. `--max-lock-bytes` excludes oversized locks, including proof verification locks, before ranking. All paths use the same `--spend-fee` so replay compares equal output amounts.

Installed `4thgraph-circuit` and `4thgraph-verify` commands can read bundled library files outside the repository. Given a `relation:`, the planner builds R1CS from the same parsed Forth. The separate `python -m fourthgraph.verification.proof_contract --verification-key` entry point accepts external R1CS that the deployer has checked. [Installation and dependencies](../install.md)

`relation:` currently supports bounded public state transitions. Tracing an arbitrary history requires an authenticated predecessor state or a history proof interface. A proof backend can replace over-budget direct Script when it enforces the same history relation and binds it to the actual spend.

`--policy allow-direct` ranks all eligible paths. Use `require-proof` for external proofs or `require-groth16` for Groth16 specifically. The BN254 fixed-statement adapter has a different authorization and spend-binding interface, and the example report explains its exclusion.

Run replay from the repository root. Generate the keys file using the test public keys from an existing replay report. The Groth16 option accepts an external setup for this circuit that the deployer has approved. Use the local test setup only on regtest.

```sh
source="projects/proof-counter/verify-state.fth"
keys="workspace/workflow-test-keys.json"

PYTHONPATH=src:. python -m fourthgraph.verification.circuit_backend "$source" --output "workspace/verify-state.circom"
PYTHONPATH=src:. bash tools/verify_node.sh --profile raised -- \
  python -m fourthgraph.verification.plan "$source" --keys "$keys" --current 19 \
  --target both --r1cs --replay --output "workspace/v0.2.5-relation-auto.json"
```

Add `--groth16 "$zkey" "$ptau"` to include BLS12-381 in the selection. The example defaults to direct Script, while `--policy require-proof` selects R1CS. With Groth16 required, the total field size objective selects `affine-inline`, while the lock size objective selects `affine-witness`.

`--policy require-groth16 --max-lock-bytes 400000` retains the total field size objective and imposes a lock size budget. The `affine-inline` lock exceeds that budget, so the compiler selects `affine-witness`.
