# P2PKH-Schnorr v0.13.0

[简体中文](README.zh-CN.md) · [4thGraph](../../README.md) · [Project index](../README.md) · [Versions](versions/index.json)

**Experimental payment template.** Pay to a BIP340 x-only public-key hash on BSV. A wallet fills one 20-byte owner field in a fixed locking script. Its external signer returns a standard 64-byte BIP340 signature.

Two parties can use BIP327 MuSig2 to spend through the same signer interface. The existing lock accepts the aggregate x-only key and resulting BIP340 signature. The reference fixtures cover an interrupted signing session and compare the same all-participants policy against native `CHECKMULTISIG`. [MuSig2 and native 2-of-2](docs/threshold-comparison.en.md)

**[Wallet SDK quickstart](docs/sdk.en.md#quickstart)** · [Payment protocol](docs/spec.en.md) · [Validate](#validate-the-baseline) · [Transaction costs](#measured-sizes) · [BIP340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)

## Build from Forth

The payment example imports the 4thGraph standard-library verifier with `REQUIRE stdlib/bip340.fth`. Its `schnorr-lock` word combines the library verifier with the owner check and the current-input binding. Its `schnorr-unlock` word builds the unlocking script for each spend. [Payment example source](reference/schnorr.fth) · [4thGraph BIP340 library](../../src/fourthgraph/stdlib/bip340.fth)

From the repository root, run `PYTHONPATH=src:. python projects/p2pkh-schnorr/reference/generate_template.py --check` to verify the current lock and layout. Use `--write` to regenerate them. The wallet creates v0.13.0 outputs by default and also recognizes and spends v0.6.0 through v0.12.0 outputs. [Version catalog](versions/index.json)

The wallet uses libsecp256k1 to verify the external signature, then supplies the approved preimage and public witness to `schnorr-unlock` to construct the unlocking script. [Wallet SDK](docs/sdk.en.md#quickstart)

v0.13.0 reverses the four coordinate fields, the signature scalar and the BIP340 challenge hash as a batch. It reuses the group order for both scalar operations and reduces the detached verifier from 23,873 to 23,245 bytes. [Challenge preparation](docs/spec.en.md)

## Validate the baseline

From the repository root, create a Python 3.12 project environment. The tests use public fixture keys and run against the pinned chain-gang build. The BSV Node replay runs on an isolated regtest.

```sh
bash tools/setup-workspaces.sh
python3.12 -m venv projects/p2pkh-schnorr/workspace/p2pkh-schnorr
projects/p2pkh-schnorr/workspace/p2pkh-schnorr/bin/python -m pip install -r projects/p2pkh-schnorr/reference/requirements.txt
export SCRIPT_LAB_SDK_PYTHON="$PWD/projects/p2pkh-schnorr/workspace/p2pkh-schnorr/bin/python"
PYTHONPATH=src:. "$SCRIPT_LAB_SDK_PYTHON" projects/p2pkh-schnorr/reference/generate_template.py --check
PYTHONPATH="$PWD/src:$PWD:$PWD/projects/p2pkh-schnorr/reference" \
  bash tools/verify_node.sh -- "$SCRIPT_LAB_SDK_PYTHON" -m unittest -v test_schnorr test_musig2
bash tools/verify_node.sh -- bash sdk/verify_wallet.sh p2pkh-schnorr
```

The acceptance suite checks all 19 official BIP340 verification vectors, including empty and variable-length messages, through libsecp256k1 and both Script engines. It also regenerates the eight official signing vectors with test keys and auxiliary randomness. The payment matrix covers all 12 paired BIP143 and Chronicle OTDA modes for transaction versions 1 and 2. It rejects locktime changes and checks the expected output commitments for ALL, NONE, and SINGLE. Separate cases cover malformed coordinates, key ownership, fee balance, inactive Chronicle, and both lookup tables, scalar decomposition, and results at infinity.

## Measured sizes

Each v0.13.0 output lock is **24,055 bytes**, saving 628 bytes over v0.12.0. Its owner field starts at byte offset **189**. The table measures two inputs creating two Schnorr outputs. The unlocking scripts push the complete signing preimage, BIP340 signature, and coordinate witnesses.

| Mode | Each output lock | Each input unlock | Complete transaction | Extra input | Extra output | Fund and exit | One turnover | Peak stack payload |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| BIP143 ALL | 24,055 | 329 | 48,886 | 372 | 24,066 | 49,111 | 97,997 | 3,396 |
| Chronicle OTDA ALL | 24,055 | 48,401 | 145,030 | 48,567 | 72,206 | 49,125 | 194,155 | 96,634 |

All sizes are in bytes. Stack payload is the approximate combined main and alternate stack payload for the first input from the development evaluator. BSV Node 1.2.3 and chain-gang verify each complete input with supplied prevouts. OTDA ALL includes the literal signed outputs in each preimage. [Layout and fingerprint](versions/v0.13.0/layout.json) · [Replayed measurements](versions/v0.13.0/measurements.json) · [Benchmark method](../../docs/benchmark.md)

In the one-input fixture that pays one ordinary P2PKH output, v0.12.0 and v0.13.0 both measure 416 bytes for BIP143 ALL and 348 bytes for OTDA ALL. The smaller Schnorr lock reduces the size of the transaction that creates the UTXO. The standalone BIP340 vectors exercise the same point arithmetic with no payment preimage. [Verifier and exit measurements](versions/v0.13.0/measurements.json)

```sh
PYTHONPATH=src:. bash tools/verify_node.sh -- "$SCRIPT_LAB_SDK_PYTHON" -m fourthgraph.benchmark.run \
  --project p2pkh-schnorr --venvs-dir projects/p2pkh-schnorr/workspace --output projects/p2pkh-schnorr/workspace/build/benchmark
```

Under BSV Node 1.2.3's default regtest policy, funding, turnover, and exit entered the mempool and were mined for BIP143 ALL and OTDA ALL.

```sh
PYTHONPATH=src:. bash tools/verify_node.sh --profile default -- "$SCRIPT_LAB_SDK_PYTHON" -m fourthgraph.benchmark.admission \
  p2pkh-schnorr --template v0.13.0 --turnover --output projects/p2pkh-schnorr/workspace/build/admission.json
```

The [sCrypt comparison](docs/scrypt-comparison.en.md) includes the 2021 article's linked verifier and a sCrypt BIP340 implementation with a common witness layout. The [native 2-of-2 comparison](docs/threshold-comparison.en.md) measures the full transaction lifecycle and the amount of signing data produced off-chain.
