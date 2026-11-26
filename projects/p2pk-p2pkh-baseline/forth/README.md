# Native P2PKH and P2PK in 4thGraph


4thGraph evaluates the native payment project's Forth constructors at build time. P2PKH places a 20-byte public-key hash between `OP_DUP OP_HASH160` and `OP_EQUALVERIFY OP_CHECKSIG`. P2PK pushes the compressed public key before `OP_CHECKSIG`. The wallet SDK, fixture generator, and benchmark use the corresponding project source. [p2pk.fth](p2pk.fth) · [p2pkh.fth](p2pkh.fth)

```sh
export PYTHONPATH=src:.
payment=projects/p2pk-p2pkh-baseline/forth/payments.py

python3 "$payment" --hash160 751e76e8199196d454941c45d1b3a323f1433bd6
python3 "$payment" --public-key 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
```

The 25-byte P2PKH lock spends with `<signature> <public key>`. The 35-byte P2PK lock spends with `<signature>`. Both commands use the public test fixture key and reproduce the native baseline locks byte for byte. The wallet project includes the matching signed transactions, rejection cases, and SDK commands. [Native payment baselines](../README.md)
