# P2PKH-Schnorr v0.1.0

[简体中文](README.zh-CN.md) · [BSV Script Lab](../../README.md)

**Experimental payment template.** Pay to a BIP340 x-only public-key hash on BSV. A wallet fills one 20-byte owner field in a fixed locking script. Its external signer returns a standard 64-byte BIP340 signature.

The first use case is a baseline for cooperative spending. A future BIP327 MuSig2 integration can pass an aggregate key and an aggregate signature through the same signer interface. The eventual comparison should use the same all-participants policy as native CHECKMULTISIG and include funding, spending, and interactive signing costs. [BIP327](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki)

**[Wallet SDK quickstart](docs/sdk.en.md#quickstart)** · [Payment protocol](docs/spec.en.md) · [BIP340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)

## Validate the baseline

From the repository root, create a Python 3.12 project environment. The tests use public fixture keys and run against the pinned chain-gang build. The BSV Node replay runs on an isolated regtest.

```sh
python3.12 -m venv .venv/p2pkh-schnorr
.venv/p2pkh-schnorr/bin/python -m pip install -r projects/p2pkh-schnorr/reference/requirements.txt
export SCRIPT_LAB_SDK_PYTHON="$PWD/.venv/p2pkh-schnorr/bin/python"
PYTHONPATH=. "$SCRIPT_LAB_SDK_PYTHON" projects/p2pkh-schnorr/reference/generate_template.py --check
PYTHONPATH="$PWD:$PWD/projects/p2pkh-schnorr/reference" \
  bash shared/verify_node.sh -- "$SCRIPT_LAB_SDK_PYTHON" -m unittest -v test_schnorr
bash shared/verify_node.sh -- bash shared/sdk/verify_wallet.sh p2pkh-schnorr
```

The acceptance suite checks 19 official BIP340 vectors, including empty and variable-length messages, through libsecp256k1 and both Script engines. The payment matrix covers all 12 paired ForkID and Chronicle OTDA modes for transaction versions 1 and 2. It rejects locktime changes and checks the expected output commitments for ALL, NONE, and SINGLE. Separate cases cover malformed coordinates, key ownership, fee balance, and inactive Chronicle.

## Measured sizes

The fixed lock is **126,018 bytes**. Its owner field starts at byte offset **238**. These two-input, two-output fixtures create two Schnorr outputs. The first-input unlock includes the signing preimage, its BIP340 signature, and the coordinate witnesses.

| Mode | Each output lock | Each input unlock | Complete transaction | Extra input | Extra output | Fund and exit | One turnover | Peak stack payload |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| ForkID ALL | 126,018 | 329 | 252,816 | 372 | 126,031 | 253,041 | 505,858 | 3,341 |
| Chronicle OTDA ALL | 126,018 | 252,333 | 756,828 | 252,501 | 378,093 | 253,056 | 1,009,883 | 504,494 |

All sizes are in bytes. Stack payload is the approximate combined main and alternate stack payload for the first input from the development evaluator. BSV Node 1.2.3 and chain-gang verify each complete input with supplied prevouts. OTDA ALL includes the literal signed outputs in each preimage. [Layout and fingerprint](template/layout.json) · [Benchmark method](../../shared/benchmark.md)

```sh
bash shared/verify_node.sh -- "$SCRIPT_LAB_SDK_PYTHON" -m shared.benchmark \
  --project p2pkh-schnorr --venvs-dir .venv --output /tmp/p2pkh-schnorr-benchmark
```

Under BSV Node 1.2.3's default regtest policy, funding and exit transactions entered the mempool and were mined in both ForkID ALL and OTDA ALL runs.

```sh
bash shared/verify_node.sh --profile default -- "$SCRIPT_LAB_SDK_PYTHON" -m shared.benchmark_admission \
  p2pkh-schnorr --output /tmp/p2pkh-schnorr-admission.json
```

The next milestone is a two-party MuSig2 spend and a measured native 2-of-2 baseline, including the cost of a signing session interrupted before all parties respond.
