<!-- Generated from manifest.yaml with Copier. -->

# P2PKH-Schnorr v0.17.0

[简体中文](README.zh-CN.md) · [4thGraph](../../README.md) · [Project index](../README.md) · [Versions](versions/index.json)

## Developer resources

**[Wallet SDK quickstart](docs/sdk.en.md#quickstart)** · [Unified wallet SDK](../../sdk/README.md#quickstart)

Create a BSV payment lock from the HASH160 of a BIP340 x-only public key. The key is 32 bytes, the owner hash is 20 bytes, and the external signer returns a 64-byte BIP340 signature. This is an experimental payment template. [BIP340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)

[Protocol](docs/spec.en.md) · [Algorithm and execution](#algorithm-and-execution) · [Reproduce the checks](#reproduce-the-checks) · [Complete transactions and stack measurements](#complete-transactions-and-stack-measurements) · [Measurements data](versions/v0.17.0/measurements.json)

| Entry point | Purpose |
| --- | --- |
| `bip340-verify ( script -- script )` | Build a detached verifier. At execution it accepts a byte message, public key x and y, a BIP340 signature, and the nonce point's y coordinate. |
| `schnorr-lock ( script bytes -- script )` | Build a payment lock from a 20-byte owner hash. The lock checks ownership, verifies the BIP340 signature, and binds the signed digest to the current input. |
| `schnorr-unlock` | Build the input script from the signed preimage, mode selector, signature, and public coordinate witnesses. |

## Use cases and trade-offs

The detached verifier covers BIP340 signer interoperability with empty and variable-length messages. The payment wrapper uses the same algorithm with the 32-byte SHA256d of the current input's signing preimage as the message. The BIP340 equation, the current-input binding, and funded node admission have separate checks. [Payment protocol](docs/spec.en.md) · [Reproduction](#reproduce-the-checks)

Two parties can use BIP327 MuSig2. The lock commits to the aggregate x-only key and verifies the final BIP340 signature through the same wallet interface. The fixtures cover signing-session interruptions and compare the same all-participants policy with native `CHECKMULTISIG`. [MuSig2 and native 2-of-2](docs/threshold-comparison.en.md)

Each Schnorr output carries a 22,435-byte lock. With literal OTDA ALL, every input witness also carries the serialized outputs, so the cost of adding an output grows with the number of inputs. The measured one-input exit to ordinary P2PKH is 416 bytes under BIP143 ALL and 348 bytes under OTDA ALL for both v0.16.0 and v0.17.0. The lock reduction saves bytes in the transaction that creates the Schnorr UTXO. [Recorded measurements](versions/v0.17.0/measurements.json)

## Algorithm and execution

1. Parse the BIP340 signature as `r || s`. The wallet derives the even y coordinates of the public key point `P` and nonce point `R` from public data. Script checks the ranges, parity, and the public point's curve equation.
2. Compute the BIP340 tagged challenge from the original `r`, public key x, and message, then reduce it modulo the group order `n` to obtain `e`.
3. Compute `sG − eP`, reject the point at infinity, and compare both projective coordinates with the even nonce point `R`. The coordinate witnesses let Script use field congruences for this comparison without a square root or inversion.

[BIP340 verification](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) · [Witness and challenge checks](docs/spec.en.md) · [Forth payment example](reference/schnorr.fth) · [BIP340 standard-library source](../../src/fourthgraph/stdlib/bip340.fth)

### secp256k1 arithmetic

v0.15.0 introduced a coordinate map that sends `(X:Y:Z)` to `(u²X:u³Y:Z)` with `21u⁶ = 1 mod p`. It preserves the group law and maps `y² = x³ + 7` to `y² = x³ + 1/3`. The scaled curve uses simpler complete addition formulas. The paired doubling kernel reduces the X coordinate once after both doublings. The challenge still uses the original BIP340 coordinates. [Coordinate scaling and doubling](docs/spec.en.md#coordinate-scaling)

For joint multiplication, the verifier splits `s` at bit 128 and applies the secp256k1 endomorphism `φ(P) = λP` to split `k = n − e` into `k1 + λk2 ≡ k mod n`. The bounds give `|k1|, |k2| < 2¹²⁸`. The verifier accumulates the four components in 64 two-bit windows. v0.16.0 reuses two GLV lattice constants during rounding and reconstruction, and passes the group order from challenge reduction to the split. [Joint multiplication and bound](docs/spec.en.md#joint-scalar-multiplication) · [Reusable kernels](../../src/fourthgraph/stdlib/secp256k1.fth)

v0.17.0 applies the point-at-infinity identity in the first window. When the variable selector is nonzero, the verifier loads that projective point directly into the accumulator. With a zero selector it keeps infinity. The fixed point uses complete affine addition when selected. [First window](docs/spec.en.md#joint-scalar-multiplication)

The same kernels apply to Script paths that explicitly multiply secp256k1 points by runtime scalars. The current PELS Counter uses fixed public parameters `d = k = 1` for transaction binding. With the candidate preimage digest `H` and the fixed generator coordinate `r`, Script computes `s = (H + r) mod n`, applies low-S normalization, encodes DER, and delegates ECDSA verification to native `OP_CHECKSIG`. All three PELS Counter builds produced byte-identical locks across v0.16.0 and v0.17.0. [PELS Counter](../pels-counter/README.md) · [Fixed-key binding](../../src/fourthgraph/bsv/pushtx.py)

## Reproduce the checks

<a name="validate-the-baseline"></a>

Run from the repository root with Python 3.12. The SDK replay also uses Node.js 24, Go, and Rust/Cargo. The suites use public fixture keys and replay against pinned chain-gang and an isolated BSV Node regtest.

```sh
bash tools/setup-workspaces.sh
python3.12 -m venv projects/p2pkh-schnorr/workspace/p2pkh-schnorr
projects/p2pkh-schnorr/workspace/p2pkh-schnorr/bin/python -m pip install -r projects/p2pkh-schnorr/reference/requirements.txt
. projects/p2pkh-schnorr/workspace/p2pkh-schnorr/bin/activate
export SCRIPT_LAB_SDK_PYTHON="$VIRTUAL_ENV/bin/python"
```

```sh
PYTHONPATH=src:. python projects/p2pkh-schnorr/reference/generate_template.py --check
PYTHONPATH=src:. bash tools/verify_node.sh --profile raised -- python -m unittest discover -s projects/p2pkh-schnorr/reference
```

```sh
PYTHONPATH="$PWD/tests" REGTEST_CHRONICLE_HEIGHT=5 \
  bash tools/verify_node.sh -- "$SCRIPT_LAB_SDK_PYTHON" -m unittest -v test_secp256k1_library
bash tools/verify_node.sh -- bash sdk/verify_wallet.sh p2pkh-schnorr
```

The acceptance suite checks all 19 official BIP340 verification vectors through libsecp256k1 and both Script engines, and regenerates eight signing vectors with public test data. Payment cases cover all 12 paired BIP143 and Chronicle OTDA sighash modes in transaction versions 1 and 2. They cover stale locktime, ALL/NONE/SINGLE output commitments, malformed coordinates, ownership, fee balance, and Chronicle activation. The verifier tests exercise both lookup tables and infinity. The curve tests compare scaled point operations and GLV rounding with independent references and replay correct and incorrect results in both engines. [Payment tests](reference/test_schnorr.py) · [Curve tests](../../tests/test_secp256k1_library.py)

The high-level Forth experiment compares the plain binary verifier, the automatic 64-window GLV verifier, and the v0.17.0 hand-tuned build. [Build and replay](docs/high-level-forth.en.md) · [64-window results](docs/high-level-forth.en.md#64-window-lowering) · [Joint lowering candidates](docs/high-level-forth.en.md#joint-lowering-candidates) · [Dataflow iteration](docs/high-level-forth.en.md#dataflow-iteration)

## Script sizes

| Component | v0.16.0 | v0.17.0 |
| --- | ---: | ---: |
| Detached BIP340 verifier | 21,705 B | 21,625 B |
| Complete payment lock | 22,515 B | 22,435 B |

The owner field starts at byte offset 189. The release record includes paired measurements on chain-gang and BSV Node for the detached verifier and both native P2PKH exit modes. The sCrypt report compares v0.6.0 with the legacy verifier and a separate BIP340 implementation using the same witness layout. [Layout and fingerprint](versions/v0.17.0/layout.json) · [Recorded measurements](versions/v0.17.0/measurements.json) · [sCrypt comparison](docs/scrypt-comparison.en.md)

## Developer and wallet integration

1. Create a receive lock with `createLock` using the x-only key or its HASH160. Before spending, recognize the authenticated funding output, check the outpoint and amount, and approve the destinations and fee. The SDK defaults to v0.17.0 and recognizes and spends all releases from v0.6.0 to v0.17.0.
2. Use `signPayment` for a single-input payment or `signInput` for a prepared transaction. The signer callback takes the supplied 32 bytes as the BIP340 message and returns the standard 64-byte signature. The SDK verifies it with libsecp256k1 and derives the two public y coordinates.
3. The SDK provides the approved preimage and public witness. In eligible Chronicle version-2 spends it uses a constructor when that shortens the input script. Both encodings put the same complete preimage on the stack. The lock verifies BIP340 and binds the digest to the actual input with PUSHTX and native `OP_CHECKSIG`.

[SDK quickstart](docs/sdk.en.md#quickstart) · [Payment protocol](docs/spec.en.md) · [Current-input binding](../../src/fourthgraph/bsv/pushtx.py)

### Build from Forth

Load `REQUIRE stdlib/bip340.fth` to reuse the detached verifier. The payment example composes it with the ownership and input-binding checks. Run the template check above to confirm the frozen lock and its layout. Use `--write` to regenerate them. [Forth source](reference/schnorr.fth) · [Version catalog](versions/index.json)

## Complete transactions and stack measurements

<a name="measured-sizes"></a>

The v0.17.0 literal fixtures spend two Schnorr outputs and create two Schnorr outputs. BSV Node 1.2.3 and pinned chain-gang verify complete inputs with explicit prevouts. The development evaluator measures stack peaks for input zero. The main and alternate item peaks and combined payload peak are recorded independently. Transaction and payload sizes are in bytes. [Recorded measurements](versions/v0.17.0/measurements.json) · [Benchmark method](../../docs/benchmark.md)

| Mode | Inputs × outputs | Previous locks | Unlocks | New locks | Total | Main / alt items | Stack payload |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| BIP143 ALL (`0x41`) | 2 × 2 | 22,435 × 2 | 329 × 2 | 22,435 × 2 | 45,646 | 90 / 13 | 3,401 |
| Chronicle OTDA ALL (`0x61`) | 2 × 2 | 22,435 × 2 | 45,161 × 2 | 22,435 × 2 | 135,310 | 90 / 13 | 90,154 |

```sh
PYTHONPATH=src:. bash tools/verify_node.sh -- "$SCRIPT_LAB_SDK_PYTHON" -m fourthgraph.benchmark.run \
  --project p2pkh-schnorr --venvs-dir projects/p2pkh-schnorr/workspace --output projects/p2pkh-schnorr/workspace/build/benchmark
```

For the same two-input, two-output OTDA ALL payment, the constructor reduces each unlock from 45,161 to 4,819 bytes and the transaction from 135,310 to 54,626 bytes. The reconstructed payment was mined on default-policy regtest. [Constructor comparison](docs/high-level-forth.en.md#otda-constructor)

Under BSV Node 1.2.3's default regtest policy, funding, turnover, and exit entered the mempool and were mined in both modes.

```sh
PYTHONPATH=src:. bash tools/verify_node.sh --profile default -- "$SCRIPT_LAB_SDK_PYTHON" -m fourthgraph.benchmark.admission \
  p2pkh-schnorr --template v0.17.0 --turnover --output projects/p2pkh-schnorr/workspace/build/admission.json
```

## Marginal and lifecycle costs

Each added-input or added-output cell gives the change from 2 × 2 in **total bytes (new output locks / input unlocks / other serialization)**. Previous locks are counted in the transaction that funds the UTXO. Both lifecycle totals include native P2PKH funding and exit. One turnover adds a payment between Schnorr outputs.

| Mode | Added-input shape | Added-input bytes | Added-output shape | Added-output bytes | Fund and exit | One turnover |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| BIP143 ALL (`0x41`) | 3 × 2 | 372 (0 / 329 / 43) | 2 × 3 | 22,446 (22,435 / 0 / 11) | 45,872 | 91,518 |
| Chronicle OTDA ALL (`0x61`) | 3 × 2 | 45,327 (0 / 45,284 / 43) | 2 × 3 | 67,346 (22,435 / 44,896 / 15) | 45,886 | 181,195 |

[Unified benchmark and reproduction](../../docs/benchmark.md) · [Native 2-of-2 lifecycle comparison](docs/threshold-comparison.en.md)
