# 4thGraph examples

Run the commands from the repository root with Git and Python 3.11 or later. The build and transaction construction commands use the Python standard library.

## PELS Counter

4thGraph compiles the `advance` word in [`pels-counter.fth`](pels-counter.fth). The example wraps that word in a covenant that requires every spend to create one successor with the incremented `u32` and the same covenant code. The transaction consumes output 0, subtracts 1,000 sat from it as the fee, and writes the remainder to the successor. The example provides a single spend path that continues the counter while its balance can fund the next update.

### Build

```sh
export PYTHONPATH=.:projects/4thgraph
counter=projects/4thgraph/examples/pels_counter.py
python3 "$counter" build
```

The JSON gives the counter-zero lock in `script_hex` and the starting output amount in `satoshis`. The Forth increment compiles to 8 bytes. The full lock includes the checks that bind the successor output to the actual transaction.

### Spend and verify on regtest

On Linux x86-64, set up the [regtest dependencies](../INSTALL.md#cli), including Rust/Cargo and a C toolchain to build the pinned chain-gang package. Run the following after the build step.

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install ecdsa -r shared/requirements-chronicle.txt

report=projects/4thgraph/build/pels-counter.json
bash shared/verify_node.sh --profile default -- python "$counter" replay --output "$report"
```

The replay deploys state `0`, then spends it as `0 → 1 → 2`. The outputs hold 1,020,000, 1,019,000, and 1,018,000 sat, respectively. For each update, the report records the transaction hex, the input Script verdict from BSV Node, the complete-transaction verdict from chain-gang, and the mined block. Both engines reject a wrong count, a changed successor script, a wrong amount, and a transaction that changed its output while reusing the original preimage.

To build the first spend separately, pass the raw deployment transaction to the `spend` command. The following command uses `jq` to read it from the replay report.

```sh
python3 "$counter" spend --parent "$(jq -r '.deployment.raw' "$report")"
```

The result includes `transaction_hex`, the input and output counter values, the fee, and the transaction ID. With the replay's deployment it reconstructs the first spend byte for byte.

The unlock script pushes the ForkID ALL preimage. In the lock, `OP_CODESEPARATOR` places the counter data outside the authenticated `scriptCode`. Script reads the immutable covenant code and the amount from the preimage, reconstructs the required successor output, and checks `hashOutputs`. The native signature check authenticates that preimage against the actual spend. [PELS construction](https://patents.google.com/patent/EP4374535A1/en)

## Native P2PKH and P2PK

[`payments.fth`](payments.fth) defines two build-time Forth constructors. P2PKH places a 20-byte public-key hash between `OP_DUP OP_HASH160` and `OP_EQUALVERIFY OP_CHECKSIG`. P2PK pushes the full compressed public key before `OP_CHECKSIG`.

```sh
export PYTHONPATH=.:projects/4thgraph
payment=projects/4thgraph/examples/payments.py

python3 "$payment" --hash160 751e76e8199196d454941c45d1b3a323f1433bd6
python3 "$payment" --public-key 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
```

The 25-byte P2PKH lock spends with `<signature> <public key>`. The 35-byte P2PK lock spends with `<signature>`. Both commands use the public test fixture key and reproduce the native baseline locks byte for byte. The wallet project includes the matching signed transactions, rejection cases, and SDK commands. [Native payment baselines](../../p2pk-p2pkh-baseline/README.md)
