# 4thGraph projects

| Project | Runnable use case |
| --- | --- |
| [PELS Counter](pels-counter/README.md) | Build and replay an incrementing covenant |
| [Native P2PK and P2PKH](p2pk-p2pkh-baseline/README.md) | Build native payment locks and reproduce baseline transactions |
| [Workflow examples](workflow-examples/README.md) | Build parallel and serial transaction graphs, including Gforth input |
| [Proof counter](proof-counter/README.md) | Build a public state transition with Script, Circom, or a proof backend |
| [P2PKH-R1](p2pkh-r1/README.md) | Compare the reference P-256 lock with its Forth build |
| [P2PKH-R1 Deferred](p2pkh-r1-deferred/README.md) | Activate a P-256 lock after funding |
| [P2PKH-Schnorr](p2pkh-schnorr/README.md) | Build and test a BIP340 lock |
| [P2PKH-SM2](p2pkh-sm2/README.md) | Use SM2 signatures and SignedData |
| [Lamport OTS](lamport-ots/README.md) | Compare one-time signature locks |
| [WOTS+](wots-plus/README.md) | Compare Winternitz witness and lock layouts |
| [ML-DSA-44](ml-dsa/README.md) | Replay a pure-mode post-quantum signature spend |

Run `bash tools/setup-workspaces.sh` from the repository root to create Git-ignored `workspace/build/`, `workspace/cache/` and `workspace/logs/` directories for each project. Install the [toolchain](../docs/install.md) or set `PYTHONPATH=src:.` for commands shown from the repository root.

Keep reference implementations, fixed transaction vectors and comparison experiments with their project. Store selected replay records in the project and link to them from the [showcase](../showcase/README.md).
