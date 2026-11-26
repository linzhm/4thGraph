# PELS Counter

[简体中文](README.zh-CN.md) · [Project index](../README.md) · [Versions](versions/index.json)

**[Build the lock](#build)** · [Fund and replay on regtest](#spend-and-verify-on-regtest) · [Compare fee rules](#declare-a-fee-constraint)

Run the commands from the repository root with Git and Python 3.11 or later. The counter build commands use the Python standard library.

4thGraph compiles `advance` into a covenant that requires one successor with the incremented `u32` and the same covenant code. The [core PELS source](pels-counter-core.fth) takes the successor's amount from the witness and binds that amount to the actual successor. Its spends use different fees chosen by the transaction builder. The [original tutorial](pels-counter.fth) adds a 1,000 sat fee rule.

## Build

```sh
export PYTHONPATH=src:.
counter=projects/pels-counter/pels_counter.py
python3 "$counter" build
```

The JSON gives the counter-zero lock in `script_hex` and the starting output amount in `satoshis`. The Forth increment compiles to 8 bytes. The full lock includes the checks that bind the successor output to the actual transaction.

The build combines PUSHTX and witness candidates and selects the least serialized bytes for the deployment lock field and first spend. The `optimization` record lists the typed transition, the lowering rules, and the cost of each candidate. A single input determines `hashPrevouts` and `hashSequence`. An exact successor determines `hashOutputs`. The transaction template fixes the BIP143 ALL sighash type (`0x41`), so the reconstructed witness omits these four fields. When the compiler can link a stable script size, it also supplies the script's CompactSize. The smallest PUSHTX candidate derives the compressed public key from the fixed `r` in the DER signature.

The successor assertions fix the next counter and the code that the next output preserves. The source supplies the amount rule separately. The compiler can also omit a duplicate code fragment from the witness. It links the two positions and checks that their emitted byte ranges match. The lock restores the omitted copy before hashing the successor and the transaction preimage. The replay includes a forged successor with matching tampered witness data to check that the actual input's code still governs the spend.

## Spend and verify on regtest

On Linux x86-64, install curl, Rust/Cargo, and a C toolchain for the pinned chain-gang package. The node launcher downloads and verifies BSV Node. [Regtest infrastructure](../../docs/infrastructure.md)

```sh
bash tools/setup-workspaces.sh
export PYTHONPATH=src:.
counter=projects/pels-counter/pels_counter.py
python3 -m venv projects/pels-counter/workspace/venv
. projects/pels-counter/workspace/venv/bin/activate
python -m pip install ecdsa -r tools/requirements-chronicle.txt

report=projects/pels-counter/workspace/build/pels-counter.json
bash tools/verify_node.sh --profile default -- python "$counter" replay --output "$report"
```

The replay deploys state `0`, then spends it as `0 → 1 → 2`. The outputs hold 1,020,000, 1,019,000, and 1,018,000 sat, respectively. For each update, the report records the transaction hex, both engines' verdicts, and the mined block. The rejection cases include a wrong count, changed successor code or amount, an extra output, and a changed locktime with the old witness. Add `--compare` to replay every candidate in one run.

To build the first spend separately, pass the raw deployment transaction to the `spend` command. The following command uses `jq` to read it from the replay report.

```sh
python3 "$counter" spend --parent "$(jq -r '.deployment.raw' "$report")"
```

The result includes `transaction_hex`, the input and output counter values, the fee, and the transaction ID. With the replay's deployment it reconstructs the first spend byte for byte. The parent lock determines the witness layout, including for deployments built with the original 705-byte lock.

In the lock, `OP_CODESEPARATOR` places the counter data outside `scriptCode`. The original witness carries the full BIP143 ALL preimage. Reconstructed witnesses supply the version, outpoint, `scriptCode`, previous amount, sequence, and locktime. Script builds the required successor and inserts its hash into the preimage. Every layout authenticates the full preimage against the actual spend with native `OP_CHECKSIG`. [PELS construction](https://patents.google.com/patent/EP4374535A1/en)

## Declare a fee constraint

The default source fixes the fee at 1,000 sat. PELS sources can declare an inclusive interval with `pels-fee: 1000 2000 ;`. Equal endpoints let the compiler derive the fee from the rule. Distinct endpoints let the spender supply a fee. Script checks that value, derives the positive successor amount, and binds the entire successor to the actual transaction.

```sh
source=projects/pels-counter/pels-counter-bounded-fee.fth
python3 "$counter" --source "$source" build
bash tools/verify_node.sh --profile default -- \
  python "$counter" --source "$source" replay --compare \
  --output projects/pels-counter/workspace/build/pels-counter-bounded-fee.json
```

Use the same `--source` with `spend --parent <raw-tx> --fee 1500` to construct a spend inside that interval. The replay checks both fee bounds, rejects claims outside the interval, and rejects a changed successor that disagrees with an allowed fee.

## Compare the core PELS rule

Use the Python environment from the regtest section.

```sh
bash tools/setup-workspaces.sh
export PYTHONPATH=src:.
counter=projects/pels-counter/pels_counter.py
source=projects/pels-counter/pels-counter-core.fth
python3 "$counter" --source "$source" build
bash tools/verify_node.sh --profile default -- \
  python "$counter" --source "$source" replay --compare \
  --output projects/pels-counter/workspace/build/pels-counter-core.json
```

Pass `--amount <satoshis>` with `spend --parent <raw-tx>` to supply the amount of the sole successor. Replay evaluates different amounts, then rejects mutations that disagree with the witness, the increment, or the preserved code.
