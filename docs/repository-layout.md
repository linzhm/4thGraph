# 4thGraph repository layout

[Documentation index](README.md) · [Project index](../projects/README.md) · [Wallet SDK](../sdk/README.md)

```text
4thGraph/
├── .gitignore                    # Local workspaces and generated files
├── AGENTS.md
├── LICENSE
├── README.md / README.zh-CN.md
├── .github/workflows/            # Manual project acceptance jobs
├── docs/
│   ├── README.md / README.zh-CN.md
│   ├── language/
│   │   ├── README.md             # 4thGraph SDL documentation index
│   │   ├── specification.md
│   │   ├── syntax.md
│   │   └── stdlib.md
│   ├── templates/                # Protocol, SDK, and reproduction guide templates
│   ├── install.md
│   ├── toolchain.md
│   ├── groth16-bls12-381.md
│   ├── infrastructure.md
│   ├── benchmark.md
│   ├── benchmark.zh-CN.md
│   ├── chronicle-regression.md
│   └── repository-layout.md
├── projects/
│   ├── README.md / README.zh-CN.md
│   ├── lamport-ots/
│   ├── ml-dsa/
│   ├── p2pk-p2pkh-baseline/
│   ├── p2pkh-r1/
│   ├── p2pkh-r1-deferred/
│   ├── p2pkh-schnorr/
│   ├── p2pkh-sm2/
│   ├── pels-counter/
│   ├── proof-counter/
│   ├── stark-counter/             # Winterfell BLAKE3 proof reference
│   ├── stark-winterfell-sha256/   # SHA-256 profile and trace-opening replay
│   ├── template/                 # Copier project template, schema, and version examples
│   ├── workflow-examples/
│   └── wots-plus/
├── sdk/                          # Go, Python, Rust and TypeScript adapters
│   ├── README.md / README.zh-CN.md
│   └── docs/                     # Integration guide and API reference
├── showcase/                     # Evidence and reproduction links
├── skills/4thgraph/
│   ├── SKILL.md
│   └── references/
├── src/fourthgraph/
│   ├── benchmark/                # Measurement drivers
│   ├── bsv/                      # Script and transaction primitives
│   ├── compiler/                 # Forth parsing, checking and optimization
│   ├── replay/                   # Funded regtest and evidence generation
│   ├── stdlib/                   # Bundled Forth words and interface catalog
│   ├── verification/             # Script, circuits and proof backends
│   ├── workflow/                 # Transaction state and workflow frontends
│   └── reporting.py
├── tests/                        # Toolchain, packaging and layout regression tests
├── tools/                        # Setup, installation and node launchers
├── workspace/                    # Local toolchain builds, caches and logs
└── pyproject.toml                # Python package and four installed commands
```

[Projects](../projects/README.md) are the runnable examples. They keep their own reference code, templates, experiments and verified results. `bash tools/setup-workspaces.sh` creates Git-ignored local workspaces at the root and inside each project. Start new projects with the shared scaffold. [New project scaffold](../projects/template/README.md)

## Project compiler inputs

Each Forth entry is a standalone `.fth` file. Follow its `REQUIRE` imports for the rest of the source. The host drivers supply fixture data, build-time parameters and compiler primitives, then assemble or replay the resulting transactions. The per-project version manifests record the build and verification commands.

| Project | Forth source used for compilation | Host build or replay entry |
| --- | --- | --- |
| Groth16 BLS12-381 | [Modular verifier](../projects/groth16-bls12-381/forth/verifier.fth) | [Release replay](../projects/groth16-bls12-381/reference/replay_plan.py), [affine-inline plan](../projects/groth16-bls12-381/versions/v0.13.0/manifest.json), [projective-cofactor and affine-witness plans](../projects/groth16-bls12-381/versions/v0.14.0/manifest.json) |
| Groth16 BN254 | [v0.6.0 verifier](../projects/groth16-bn254/forth/last-use-verifier.fth), [modular verifier](../projects/groth16-bn254/forth/verifier.fth), [fixed statement](../projects/groth16-bn254/forth/statement.fth) | [Build launcher](../projects/groth16-bn254/reference/build.sh), [v0.6.0 release commands](../projects/groth16-bn254/versions/v0.6.0/manifest.json) |
| Lamport OTS | [Payment locks](../projects/lamport-ots/forth/payment-lock.fth), [committed verifier](../projects/lamport-ots/forth/committed-verifier.fth), [fixed-weight verifier](../projects/lamport-ots/forth/subset-verifier.fth) | [Lock compiler](../projects/lamport-ots/reference/script.py) |
| ML-DSA-44 | [Payment lock](../projects/ml-dsa/forth/payment-lock.fth), [challenge reconstruction](../projects/ml-dsa/forth/challenge.fth) | [Compiler and kernel bindings](../projects/ml-dsa/reference/script.py) |
| Native P2PK/P2PKH | [P2PK entry](../projects/p2pk-p2pkh-baseline/forth/p2pk.fth), [P2PKH entry](../projects/p2pk-p2pkh-baseline/forth/p2pkh.fth) | [Shared lock compiler](../src/fourthgraph/bsv/native_payments.py), [project fixtures](../projects/p2pk-p2pkh-baseline/reference/script_lab.py) |
| P2PKH-R1 | [Baseline payment lock](../projects/p2pkh-r1/forth/r1-baseline.fth), [PELS lock](../projects/p2pkh-r1/forth/r1-pels-lock.fth) | [Build and pinned plan replay](../projects/p2pkh-r1/forth/compile_r1.py) |
| P2PKH-R1-Deferred | [Activation lock](../projects/p2pkh-r1-deferred/forth/deferred-activation.fth) | [Compiler and field bindings](../projects/p2pkh-r1-deferred/reference/forth_lock.py) |
| P2PKH-Schnorr | [Payment lock and witness words](../projects/p2pkh-schnorr/forth/schnorr.fth) | [Template check](../projects/p2pkh-schnorr/reference/generate_template.py) |
| P2PKH-SM2 | [Lock and binding](../src/fourthgraph/stdlib/wallet/p2pkh-sm2.fth), [point formulas](../projects/p2pkh-sm2/forth/point-formulas.fth), [window formulas](../projects/p2pkh-sm2/forth/point-window.fth), [byte fields](../projects/p2pkh-sm2/forth/byte-fields.fth) | [Lock compiler and SM3 bindings](../projects/p2pkh-sm2/reference/assemble.py) |
| PELS Counter | [Fee-constrained counter](../projects/pels-counter/pels-counter.fth), [core counter](../projects/pels-counter/pels-counter-core.fth), [bounded-fee counter](../projects/pels-counter/pels-counter-bounded-fee.fth) | [Build and replay](../projects/pels-counter/pels_counter.py) |
| Proof Counter | [Counter relation](../projects/proof-counter/counter.fth), [state verification](../projects/proof-counter/verify-state.fth), [transaction workflow](../projects/proof-counter/workflow.fth) | [Circuit compiler](../src/fourthgraph/verification/circuit_backend.py), [proof replay](../src/fourthgraph/replay/groth16_bls12381.py) |
| STARK Counter | [Counter transition](../projects/stark-counter/counter.fth) | [Forth and Script replay](../projects/stark-counter/reference/replay.py), [Winterfell counter program](../projects/stark-counter/reference/src/counter.rs) |
| Winterfell SHA-256 STARK | [SHA-256 words](../projects/stark-winterfell-sha256/hashes.fth), [trace-opening verifier](../projects/stark-winterfell-sha256/opening.fth) | [Hash replay](../projects/stark-winterfell-sha256/reference/hash_replay.py), [opening replay](../projects/stark-winterfell-sha256/reference/opening_replay.py) |
| Workflow Examples | [Counter example](../projects/workflow-examples/example.fth), [fork/join graph](../projects/workflow-examples/fork-join-graph.fth), [PELS settlement](../projects/workflow-examples/pels-settle.fth) | [Workflow compiler](../src/fourthgraph/workflow/protocol.py) |
| WOTS+ | [v0.12.0 payment lock](../projects/wots-plus/forth/payment-lock.fth), [canonical SDK lock](../projects/wots-plus/forth/canonical.fth), [compact chain words](../projects/wots-plus/forth/compact.fth) | [Lock compiler](../projects/wots-plus/reference/script.py), [template check](../projects/wots-plus/reference/generate_reconstruction.py) |

The ML-DSA compiler binds individual signature, polynomial and SHAKE256 kernels to the Forth challenge flow. The SM2 compiler binds the generated SM3 fragments to the Forth lock. The STARK projects use Rust and Winterfell for full proof generation and verification. Their Forth sources cover the counter transition, SHA-256 compatibility checks and the Merkle opening of a committed trace row.

The [SDL documentation](language/README.md) describes code shipped with 4thGraph. The [Codex skill](../skills/4thgraph/SKILL.md) has its own installation and uses the toolchain through documented inputs and commands. The [showcase](../showcase/README.md) links measurements to the project that produced them.
