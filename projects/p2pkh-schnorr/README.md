# P2PKH-Schnorr v0.6.0

[简体中文](README.zh-CN.md) · [BSV Script Lab](../../README.md)

**Experimental payment template.** Pay to a BIP340 x-only public-key hash on BSV. A wallet fills one 20-byte owner field in a fixed locking script. Its external signer returns a standard 64-byte BIP340 signature.

Two parties can use BIP327 MuSig2 to spend through the same signer interface. The existing lock accepts the aggregate x-only key and resulting BIP340 signature. The reference fixtures cover an interrupted signing session and compare the same all-participants policy against native `CHECKMULTISIG`. [MuSig2 and native 2-of-2](docs/threshold-comparison.en.md)

**[Wallet SDK quickstart](docs/sdk.en.md#quickstart)** · [Payment protocol](docs/spec.en.md) · [BIP340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)

## Build from Forth

The payment example imports the 4thGraph standard-library verifier with `REQUIRE stdlib/bip340.fth`. Its `schnorr-lock` word combines the library verifier with the owner check and the current-input binding. Its `schnorr-unlock` word builds the unlocking script for each spend. [Payment example source](reference/schnorr.fth) · [4thGraph BIP340 library](../../src/fourthgraph/stdlib/bip340.fth)

From the repository root, run `PYTHONPATH=src:. python projects/p2pkh-schnorr/reference/generate_template.py --check` to verify the checked-in lock and layout. Use `--write` to regenerate them. Earlier templates are available in Git history.

The wallet SDK uses the compiled template to recognize existing outputs and create receive locks. After verifying the external signature, it supplies the approved preimage and public witness to `schnorr-unlock` and inserts the result into the input. [Wallet SDK](docs/sdk.en.md#quickstart)

The verifier uses 64 two-bit windows over four 128-bit components. It splits the signature scalar into two limbs and applies the secp256k1 endomorphism to the challenge scalar. The fixed-base table stores affine points and uses a specialized addition kernel. The detached verifier compiles to 29,415 bytes. [Scalar decomposition and window construction](docs/spec.en.md#joint-scalar-multiplication)

## Validate the baseline

From the repository root, create a Python 3.12 project environment. The tests use public fixture keys and run against the pinned chain-gang build. The BSV Node replay runs on an isolated regtest.

```sh
python3.12 -m venv .venv/p2pkh-schnorr
.venv/p2pkh-schnorr/bin/python -m pip install -r projects/p2pkh-schnorr/reference/requirements.txt
export SCRIPT_LAB_SDK_PYTHON="$PWD/.venv/p2pkh-schnorr/bin/python"
PYTHONPATH=src:. "$SCRIPT_LAB_SDK_PYTHON" projects/p2pkh-schnorr/reference/generate_template.py --check
PYTHONPATH="$PWD:$PWD/projects/p2pkh-schnorr/reference" \
  bash tools/verify_node.sh -- "$SCRIPT_LAB_SDK_PYTHON" -m unittest -v test_schnorr test_musig2
bash tools/verify_node.sh -- bash sdk/verify_wallet.sh p2pkh-schnorr
```

The acceptance suite checks all 19 official BIP340 verification vectors, including empty and variable-length messages, through libsecp256k1 and both Script engines. It also regenerates the eight official signing vectors with test keys and auxiliary randomness. The payment matrix covers all 12 paired ForkID and Chronicle OTDA modes for transaction versions 1 and 2. It rejects locktime changes and checks the expected output commitments for ALL, NONE, and SINGLE. Separate cases cover malformed coordinates, key ownership, fee balance, inactive Chronicle, and both lookup tables, scalar decomposition, and results at infinity.

## Measured sizes

The fixed lock is **30,398 bytes**. Its owner field starts at byte offset **238**. These two-input, two-output fixtures create two Schnorr outputs. The first-input unlock includes the signing preimage, its BIP340 signature, and the coordinate witnesses.

| Mode | Each output lock | Each input unlock | Complete transaction | Extra input | Extra output | Fund and exit | One turnover | Peak stack payload |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| ForkID ALL | 30,398 | 329 | 61,572 | 372 | 30,409 | 61,798 | 123,369 | 3,325 |
| Chronicle OTDA ALL | 30,398 | 61,087 | 183,088 | 61,253 | 91,235 | 61,811 | 244,899 | 122,006 |

All sizes are in bytes. Stack payload is the approximate combined main and alternate stack payload for the first input from the development evaluator. BSV Node 1.2.3 and chain-gang verify each complete input with supplied prevouts. OTDA ALL includes the literal signed outputs in each preimage. [Layout and fingerprint](template/layout.json) · [Benchmark method](../../docs/benchmark.md)

```sh
bash tools/verify_node.sh -- "$SCRIPT_LAB_SDK_PYTHON" -m fourthgraph.benchmark.run \
  --project p2pkh-schnorr --venvs-dir .venv --output /tmp/p2pkh-schnorr-benchmark
```

Under BSV Node 1.2.3's default regtest policy, funding and exit transactions entered the mempool and were mined in both ForkID ALL and OTDA ALL runs.

```sh
bash tools/verify_node.sh --profile default -- "$SCRIPT_LAB_SDK_PYTHON" -m fourthgraph.benchmark.admission \
  p2pkh-schnorr --output /tmp/p2pkh-schnorr-admission.json
```

The [sCrypt comparison](docs/scrypt-comparison.en.md) includes the 2021 article's linked verifier and a sCrypt BIP340 implementation with a common witness layout. The [native 2-of-2 comparison](docs/threshold-comparison.en.md) measures the full transaction lifecycle and the amount of signing data produced off-chain.
