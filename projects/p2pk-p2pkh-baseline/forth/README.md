# Native P2PKH and P2PK in 4thGraph


4thGraph compiles typed Forth spending conditions for the native payment locks. The wallet SDK, fixture generator, and benchmark compile the same bundled sources with a bound recipient. P2PKH duplicates the public key for the owner-hash check, then consumes the signature and public key in `OP_CHECKSIG`. A mismatched hash stops execution at `OP_EQUALVERIFY`. [P2PK source](../../../src/fourthgraph/stdlib/native-p2pk.fth) · [P2PKH source](../../../src/fourthgraph/stdlib/native-p2pkh.fth)

```sh
export PYTHONPATH=src:.
payment=projects/p2pk-p2pkh-baseline/forth

python3 -m fourthgraph.workflow.protocol "$payment/p2pkh.fth" --entry p2pkh \
  --bind-bytes owner-hash=751e76e8199196d454941c45d1b3a323f1433bd6
python3 -m fourthgraph.workflow.protocol "$payment/p2pk.fth" --entry p2pk \
  --bind-bytes owner-key=0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
```

The 25-byte P2PKH lock spends with `<signature> <public key>`. The 35-byte P2PK lock spends with `<signature>`. Both commands use the public test fixture key and reproduce the native baseline locks byte for byte. The wallet project includes the matching signed transactions, rejection cases, and SDK commands. [Native payment baselines](../README.md)
