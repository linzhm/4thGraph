<!-- Generated from manifest.yaml with Copier. -->

# P2PKH-SM2 v1.10.0

[简体中文](README.zh-CN.md) · [4thGraph](../../README.md) · [Project index](../README.md) · [Versions](versions/index.json)

## Developer resources

**[Wallet SDK quickstart](docs/sdk.en.md#quickstart)** · [Unified wallet SDK](../../sdk/README.md#quickstart)

Choose a raw SM2 or SignedData signer. The wallet automatically selects a shorter OTDA unlocking script for eligible payments.

[Protocol](docs/spec.en.md) · [Algorithm and execution](#algorithm-and-execution) · [Reproduce the checks](#reproduce-the-checks) · [Complete transactions and stack measurements](#complete-transactions-and-stack-measurements) · [Measurements data](versions/v1.10.0/measurements.json)

| Entry point | Purpose |
| --- | --- |
| `locking_script_from_public_key` | Build a payment lock from the uncompressed SM2 public key. |
| `sign_input` | Request and verify an external signature for a selected input and sighash mode. |

## Use cases and trade-offs

Evaluate P2PKH-SM2 when a wallet already uses an SM2 signing service. A provider that exposes a raw SM2 API returns the signature directly. A GB/T 35275-2026 provider can return a direct single-signer SignedData envelope under the wallet's trusted signer configuration. The SDK checks that off-chain envelope and writes the extracted 64-byte signature into the transaction. Track which provider operation the wallet uses and validate the exact message and user ID at integration time. [Signing contract](docs/sdk.en.md)

For payments that create other SM2 outputs, compare BIP143 and OTDA using the same input and output counts. On eligible Chronicle spends, the wallet shortens the OTDA unlock by reconstructing the signed preimage. Each new output also carries the full lock for its selected template. [Reconstruction measurements](#otda-constructor)

## Algorithm and execution

[v1.11.0 candidate](#v1110)

[Protocol](docs/spec.en.md) · [Security](docs/developer.en.md#security) · [Verify](#developer-checks-and-cost-analysis) · [Transaction costs](#complete-transactions-and-stack-measurements)

P2PKH-SM2 lets a payer lock a BSV output to the HASH160 of the recipient’s
uncompressed SM2 public key. To spend the output, the recipient reveals the
public key and supplies one SM2 signature for the current input. Bitcoin Script
uses SM3 to compute the SM2 identity digest ZA and the message digest. It
verifies the SM2 signature and binds the authorization to the spending
transaction through PUSHTX and native `OP_CHECKSIG`.

### Project version and locking template

Version 1.1.0 enables OTDA reconstruction by default for locking template `1` from the first public release, v1.0.0. Versions 1.2.0 through 1.7.0 correspond to templates `2` through `7`. Versions 1.9.0 through 1.11.0 add templates `8` through `10`. The wallet recognizes and spends all ten templates from the previous output's exact bytes.

| Property | Value |
| --- | --- |
| Recipient identifier | HASH160 of the 65-byte public key `04 \|\| X_BE32 \|\| Y_BE32` |
| SM2 user ID | The fixed ASCII value `1234567812345678` |
| Locking script | 144,925 bytes for template `1`, 131,565 for `2`, 125,616 for `3`, 121,847 for `4`, 110,747 for `5`, 100,663 for `6`, 98,362 for `7`, 96,616 for `8`, 95,790 for `9`, and 94,355 for `10` |
| Unlocking script | 291 bytes with BIP143, 294 bytes with unpaired OTDA SINGLE, and transaction-dependent for other OTDA modes |
| Unlocking stack | Signing preimage, uncompressed public key, and 64-byte `r \|\| s` signature |
| Signature modes | BIP143 and Chronicle OTDA, each with ALL, NONE, or SINGLE and optional ANYONECANPAY |

The current source includes the [layout manifest](versions/v1.0.0/layout.json),
[standard SM2 vector](versions/v1.0.0/sm2-standard.json),
[complete payment vector](versions/v1.0.0/spend-all.json), and
[16 signing preimages](versions/v1.0.0/sighash-modes.json). [v1.0.0 release](https://github.com/linzhm/bsv-script-lab/releases/tag/p2pkh-sm2-v1.0.0)

<a name="otda-constructor"></a>

### Reconstruct OTDA outputs

The constructor is part of `scriptSig`. It uses 12,703 bytes for template `1`, 11,816 for `2`, 11,807 for `3`, 11,618 for `4`, 11,549 for `5`, 9,363 for `6`, 9,447 for `7`, 7,644 for `8`, 7,718 for `9`, and 7,424 for `10`. Templates `2` through `10` select reusable fragments from the initial encoding and place frequently used fragments near the top of the stack. The constructor reconstructs the exact signing preimage and fills each eligible output's HASH160 slot. The signing callback receives the same message and SM2 user ID as the literal encoding. Use the final signed transaction ID to build a child.

After Chronicle activation, version-2 OTDA ALL can reconstruct matching outputs in their original order. Paired OTDA SINGLE can reconstruct the same-index output and preserve the preceding null outputs in the preimage. Both support `ANYONECANPAY`. Other output templates keep their literal bytes. BIP143, NONE, unpaired SINGLE, version 1 and non-smaller encodings continue with the literal unlocking script. [SDK options](docs/sdk.en.md) · [Constructor and generator](reference/README.md#otda-constructor)

| OTDA ALL, bytes | Literal | Reconstructed |
| --- | ---: | ---: |
| Two inputs and two outputs | 870,194 | 316,018 |
| First input's unlocking script | 290,109 | 13,023 |
| Add one input | 290,277 | 13,189 |
| Add one output | 434,814 | 145,022 |
| Fund and exit | 290,794 | 290,794 |
| Fund, turn over once, and exit | 1,160,988 | 606,812 |

Both encodings use the same fixture keys and amounts and pass BSV Node 1.2.3 and the pinned chain-gang build. The table uses benchmark profile `v1.1.0` for template `1` with automatic reconstruction and `v1.0.0` for the literal encoding.

## Reproduce the checks

Run the release commands from the repository root with Python 3.12, Rust, and OpenSSL with SM2 and SM3 support.

```sh
export PYTHONPATH=src:.
python -m pip install -r projects/p2pkh-sm2/reference/requirements.txt
```

```sh
PYTHONPATH=src:. python projects/p2pkh-sm2/reference/point_kernels.py --affine /tmp/sm2-affine-kernel.json && python projects/p2pkh-sm2/reference/generate_otda_constructor.py --version 9 /tmp/sm2-otda-v9.hex
bash projects/p2pkh-sm2/reference/verify.sh
```

### Developer checks and cost analysis

From the reference directory, install the pinned dependencies and run the
Linux node replay.

```sh
cd projects/p2pkh-sm2/reference
python -m pip install -r requirements.txt
bash verify.sh
```

For SignedData integration, pin the signer key and DER issuer-and-serial
identifier in trusted wallet configuration. Verify the actual funding
outpoint, its value, required confirmations and the recipient's lock before
asking the signer to approve a payment. The GB/T envelope is processed by
the off-chain adapter. The unlock carries the extracted raw signature.

In the 2×2 fixture, BIP143 ALL uses a 291-byte unlock. The literal OTDA ALL encoding serializes
both outputs into each input's signing preimage and raises the unlock to
290,109 bytes. A third output adds 144,925 bytes of output lock and also
changes both existing OTDA unlocks. The marginal table shows those costs
separately. Transaction version and the two SignedData version fields apply to their own encodings.

## Script sizes

<a name="v1110"></a>

### v1.11.0 candidate

Template `10` carries the field prime and `3b` across the scalar windows and reuses the projective addition kernel in the public-key table. The 4thGraph `0.2.7` compiler at revision `64624db` compared 21 pass and rule plans on 16 fixed comparisons per plan. The selected plan uses `rewrite`, `share`, `stack`, and `search`. The new byte-layout compiler binds a packed reversal for six 32-byte fields. The PUSHTX DER encoder shares that reversal. The OTDA generator initializes cache entries from slices of earlier entries, then compares a bounded batch of dictionary substitutions. Each candidate reconstructs the same lock bytes.

| Measured bytes | v1.10.0 | v1.11.0 |
| --- | ---: | ---: |
| Locking script | 95,790 | 94,355 |
| OTDA constructor | 7,718 | 7,424 |
| BIP143 ALL, 2 inputs and 2 outputs | 192,284 | 189,414 |
| OTDA ALL, 2 inputs and 2 outputs | 207,778 | 204,320 |
| OTDA ALL, 12 inputs and 1 output | 197,213 | 192,250 |
| OTDA ALL, 24 inputs and 1 output | 310,421 | 301,930 |
| OTDA ALL, 40 inputs and 1 output | 479,733 | 466,538 |

In the 34 shared construction cases, 33 shrink and the native-only destination case stays at 719 bytes. The 36-case matrix adds 12-input and 24-input payments. The 7,424-byte constructor saves 330 bytes per reconstructed input compared with the initial template 10 candidate. In the 2×2 case, against v1.10.0, peak stack payload rises by 29 bytes for BIP143 ALL and falls by 5,740 bytes for OTDA ALL.

Select template `10` with `--version 10` or SDK `template: "v1.11.0"`. [Compiler tuning](reference/README.md#window-tuning) · [Byte bindings](reference/README.md#byte-tuning) · [Template fingerprint](versions/v1.11.0/layout.json) · [Measurements](versions/v1.11.0/measurements.json) · [Constructor tuning](versions/v1.11.0/constructor-tuning.json) · [36 transaction cases](versions/v1.11.0/latest-template-coverage.json)

<a name="p2pkh-sponsorship"></a>

#### P2PKH interactions and zero-fee sponsorship

Funded regtest exercised P2PKH funding of template `10`, a same-template SM2 payment with a P2PKH fee input, and an SM2 exit to P2PKH with sponsor change. Under the launcher's default policy profile, the BIP143 and OTDA cases all admitted and mined those funded transactions.

| Scenario | Funded regtest result |
| --- | --- |
| Append a P2PKH fee input before submission | The BIP143 `0xc1` and OTDA `0xe1` SM2 witnesses remained valid with the same outputs. A separately confirmed P2PKH UTXO paid 150,000 sat and the completed transactions mined. |
| Plan a sponsor change output | The approved transaction paid the full 10,000,000 sat principal to a template `10` or P2PKH output, returned 50,000 sat to the sponsor and paid a 150,000 sat fee. Adding a change output after signing ALL invalidated the SM2 witness. |
| Submit zero fee first, then try a sponsored replacement | The zero-fee transaction entered the mempool and stayed unmined in three blocks. The same-input sponsored transaction returned `txn-mempool-conflict`. |
| Pay from a child transaction | Both zero-fee parents included a P2PKH output. A P2PKH child spending that output and a sponsor UTXO paid 150,000 sat. Each parent and child mined in the same block. |

The isolated node used a 0.5 sat/B mining floor. The raised-profile run also checks the complete scripts on BSV Node and chain-gang and rejects an appended input with ordinary ALL. [Default policy replay](versions/v1.11.0/p2pkh-default.json) · [Raised policy replay](versions/v1.11.0/p2pkh-raised.json) · [Reproduction](reference/README.md#p2pkh-sponsorship)

<a name="v1100"></a>

### v1.10.0 candidate

Template `9` stores fixed generator points as affine X and Y pairs and uses an addition kernel specialized for an affine second point. It also reverses 32-byte values by recursively splitting the input in half. The 2×2 OTDA ALL payment saves 1,504 bytes. Each reconstructed input carries a constructor that is 74 bytes larger. For a 12-input, one-output OTDA ALL payment, the total grows from 197,151 to 197,213 bytes.

| Measured bytes | v1.9.0 | v1.10.0 | Change |
| --- | ---: | ---: | ---: |
| Locking script | 96,616 | 95,790 | −0.9% |
| OTDA constructor | 7,644 | 7,718 | +1.0% |
| BIP143 ALL, 2×2 transaction | 193,936 | 192,284 | −0.9% |
| OTDA ALL, 2×2 transaction with reconstruction | 209,282 | 207,778 | −0.7% |

Select template `9` with `--version 9` or SDK `template: "v1.10.0"`. [Template fingerprint](versions/v1.10.0/layout.json) · [Measurements](versions/v1.10.0/measurements.json) · [34 latest-template cases](versions/v1.10.0/latest-template-coverage.json)

<a name="v190"></a>

### v1.9.0

Template `8` checks for infinity once per group of five doublings and reuses one copy of the SM2 field prime throughout the group. SM3 expands message words as compression rounds need them, with a rolling schedule of 16 words. The shorter scripts and their byte layout also reduce the OTDA constructor for a payment using template `8` throughout.

| Measured bytes | v1.7.0 | v1.9.0 | Change |
| --- | ---: | ---: | ---: |
| Locking script | 98,362 | 96,616 | −1.8% |
| OTDA constructor | 9,447 | 7,644 | −19.1% |
| BIP143 ALL, 2×2 transaction | 197,428 | 193,936 | −1.8% |
| OTDA ALL, 2×2 transaction with reconstruction | 216,380 | 209,282 | −3.3% |
| OTDA ALL, unlocking script per input in that transaction | 9,767 | 7,964 | −18.5% |

In the 34-case transaction matrix, 33 transactions are smaller and the native-only destination case has the same size. Six-input, two-output OTDA ALL falls from 256,604 to 242,294 bytes.

Select template `8` for new outputs with `--version 8` or SDK `template: "v1.9.0"`. [Template fingerprint](versions/v1.9.0/layout.json) · [Recorded measurements](versions/v1.9.0/measurements.json) · [34 latest-template cases](versions/v1.9.0/latest-template-coverage.json)

<a name="v180"></a>

### v1.8.0

The wallet uses a shared OTDA constructor when an ALL payment includes outputs of both templates `6` and `7`. It emits the common prefix once, then rebuilds both suffixes from shared byte spans. The same constructor applies with ANYONECANPAY. This release uses the existing locking templates and selects the shared encoding automatically when it is the shortest candidate.

| Measured bytes | v1.7.0 | v1.8.0 | Change |
| --- | ---: | ---: | ---: |
| Constructor for both templates | 18,810 | 9,681 | −48.5% |
| OTDA ALL, 2×2 transaction with mixed outputs | 237,409 | 219,151 | −7.7% |
| OTDA ALL, unlocking script per input in that transaction | 19,131 | 10,002 | −47.7% |

The comparison uses the same inputs, output order and signing preimages. [Constructor](versions/v1.8.0/mixed-otda-constructor.json) · [Reproduction](reference/README.md#mixed-otda-constructor) · [Recorded measurements](versions/v1.8.0/measurements.json)

<a name="latest-template-coverage"></a>

#### Payments using template 7

The matrix uses v1.7.0 for every SM2 prevout and recipient. The v1.7.0 and v1.8.0 wallet revisions produced identical transaction IDs and sizes for all 34 cases. The shared constructor requires both templates `6` and `7` among the signed outputs, so the additional savings in this matrix are zero.

The existing single-template OTDA constructor still reduces eligible transactions compared with literal preimages. BSV Node 1.2.3 and chain-gang verified both encodings in every case. The matrix covers all 12 sighash types, paired and unpaired SINGLE, different input and output counts, multiple prevouts from one funding transaction, native P2PKH inputs and outputs, and a transaction with 253 outputs. [Per-case sizes and transaction IDs](versions/v1.8.0/latest-template-coverage.json) · [Reproduction](reference/README.md#latest-template-coverage)

<a name="v170"></a>

### v1.7.0

The verifier computes `sG + tQ` with signed radix-32 digits. Each table holds magnitudes 0 through 16, with Y negated for negative digits. This reduces the unrolled window count from 64 to 52 and the scalar multiplication block from 40,158 to 37,854 bytes.

| Measured bytes | v1.6.0 | v1.7.0 | Change |
| --- | ---: | ---: | ---: |
| Locking script | 100,663 | 98,362 | −2.3% |
| BIP143 ALL, 2×2 transaction | 202,030 | 197,428 | −2.3% |
| OTDA ALL, 2×2 transaction with reconstruction | 220,814 | 216,380 | −2.0% |
| OTDA ALL, unlocking script per input in that transaction | 9,683 | 9,767 | +0.9% |

Select template `7` for a new output with `--version 7` or SDK `template: "v1.7.0"`. One OTDA ALL preimage can contain reconstructed outputs of all seven templates. [Forth lock](../../src/fourthgraph/stdlib/wallet/p2pkh-sm2.fth) · [Template fingerprint](versions/v1.7.0/layout.json) · [Recorded measurements](versions/v1.7.0/measurements.json)

<a name="v160"></a>

### v1.6.0

SM3 rotates a word left by multiplying it by the corresponding power of two, splitting the eight-byte product into two 32-bit halves, and combining them with `OP_OR`. Selected round words stay in five-byte form across bitwise operations. The ZA and message hash programs together save 10,084 bytes per output. The OTDA constructor finds reusable spans in the resulting bytecode.

| Measured bytes | v1.5.0 | v1.6.0 | Change |
| --- | ---: | ---: | ---: |
| Locking script | 110,747 | 100,663 | −9.1% |
| BIP143 ALL, 2×2 transaction | 222,198 | 202,030 | −9.1% |
| OTDA ALL, 2×2 transaction with reconstruction | 245,354 | 220,814 | −10.0% |
| OTDA ALL, unlocking script per input in that transaction | 11,869 | 9,683 | −18.4% |

Select template `6` for a new output with `--version 6` or SDK `template: "v1.6.0"`. One OTDA ALL preimage can contain reconstructed outputs of all six templates. [SM3 emitter](reference/sm3_script.py) · [Template fingerprint](versions/v1.6.0/layout.json) · [Recorded measurements](versions/v1.6.0/measurements.json)

<a name="v150"></a>

### v1.5.0

The Forth formula compiler schedules the same homogeneous point arithmetic over the SM2 field. The compiled point addition is 123 bytes and doubling is 74 bytes, down from 176 and 89. The generator uses the frozen kernels at build time. Their compiler test compares the exact signed coordinates produced by the previous kernels, including infinity, equal points, inverse points and negative representatives.

| Measured bytes | v1.4.0 | v1.5.0 | Change |
| --- | ---: | ---: | ---: |
| Locking script | 121,847 | 110,747 | −9.1% |
| BIP143 ALL, 2×2 transaction | 244,398 | 222,198 | −9.1% |
| OTDA ALL, 2×2 transaction with reconstruction | 267,692 | 245,354 | −8.3% |
| OTDA ALL, unlocking script per input in that transaction | 11,938 | 11,869 | −0.6% |

Select template `5` for a new output with `--version 5` or SDK `template: "v1.5.0"`. An OTDA ALL preimage can contain reconstructed outputs of all five templates. [Point formulas and reproduction](reference/README.md#point-kernels) · [Template fingerprint](versions/v1.5.0/layout.json) · [Recorded measurements](versions/v1.5.0/measurements.json)

<a name="v140"></a>

### v1.4.0

The SM3 emitter stores expanded message words and selected round state words as five-byte little-endian values. The high byte is zero. Bitwise operations reuse those bytes directly, while arithmetic reads use `OP_BIN2NUM`. Reversing each four-byte word by halves also shortens data loading and digest output. Both SM3 programs together save 3,769 bytes per lock.

| Measured bytes | v1.3.0 | v1.4.0 | Change |
| --- | ---: | ---: | ---: |
| Locking script | 125,616 | 121,847 | −3.0% |
| BIP143 ALL, 2×2 transaction | 251,936 | 244,398 | −3.0% |
| OTDA ALL, 2×2 transaction with reconstruction | 275,608 | 267,692 | −2.9% |
| OTDA ALL, unlocking script per input in that transaction | 12,127 | 11,938 | −1.6% |

Select template `4` for a new output with `--version 4` or SDK `template: "v1.4.0"`. An OTDA ALL preimage can contain reconstructed outputs of all four templates. [Template fingerprint](versions/v1.4.0/layout.json) · [Recorded measurements](versions/v1.4.0/measurements.json)

<a name="v130"></a>

### v1.3.0

The point-addition and doubling routines use one `OP_MOD` per coordinate and retain signed residues modulo the SM2 field prime. The verifier rejects a zero projective Z coordinate, then makes X and Z nonnegative before checking the two possible field x coordinates of the signature. This saves 5,949 bytes per output. The same OTDA ALL preimage can contain reconstructed outputs of all three templates.

| Measured bytes | v1.2.0 | v1.3.0 | Change |
| --- | ---: | ---: | ---: |
| Locking script | 131,565 | 125,616 | −4.5% |
| BIP143 ALL, 2×2 transaction | 263,834 | 251,936 | −4.5% |
| OTDA ALL, 2×2 transaction with reconstruction | 287,524 | 275,608 | −4.1% |
| OTDA ALL, unlocking script per input in that transaction | 12,136 | 12,127 | −0.1% |

Select template `3` for a new output with `--version 3` or SDK `template: "v1.3.0"`. [Template fingerprint](versions/v1.3.0/layout.json) · [Recorded measurements](versions/v1.3.0/measurements.json) · [Forth lock](../../src/fourthgraph/stdlib/wallet/p2pkh-sm2.fth)

<a name="v120"></a>

### v1.2.0

Template `2` consumes SM3 operands at their last use and reuses the stack slots of surviving state words across rounds. This saves 13,360 bytes per output. All templates apply the same SM2, ZA, sighash and transaction-binding rules.

| Measured bytes | v1.1.0 | v1.2.0 | Change |
| --- | ---: | ---: | ---: |
| Locking script | 144,925 | 131,565 | −9.2% |
| BIP143 ALL, 2×2 transaction | 290,554 | 263,834 | −9.2% |
| OTDA ALL, 2×2 transaction with reconstruction | 316,018 | 287,524 | −9.0% |
| OTDA ALL, unlocking script per input in that transaction | 13,023 | 12,136 | −6.8% |

BSV Node 1.2.3 and the pinned chain-gang build replayed the complete inputs with explicit prevouts. To opt in for new outputs, use `--version 2` or SDK `template: "v1.2.0"`. [Template fingerprint](versions/v1.2.0/layout.json) · [Recorded measurements](versions/v1.2.0/measurements.json) · [Forth lock](../../src/fourthgraph/stdlib/wallet/p2pkh-sm2.fth) · [Benchmark reproduction](../../docs/benchmark.md#run)

## Developer and wallet integration

### Generate a locking script

Run these commands from the repository root. The owner hash below is an
example. Substitute the recipient’s HASH160 for an actual output.

```sh
cd projects/p2pkh-sm2/reference
python3 generate_lock.py --owner-hash160 000102030405060708090a0b0c0d0e0f10111213
python3 generate_lock.py --owner-hash160 000102030405060708090a0b0c0d0e0f10111213 --format raw > scriptPubKey.bin
```

The first command reports the template version, byte length, and SHA-256 for
the supplied owner. The second writes the exact locking script bytes. Use
`--public-key` to supply the recipient’s uncompressed public key instead of
its hash. The generator validates the public key before hashing it.

### Authorize and verify a payment

Use `sign_payment` for a one-input BIP143 ALL payment (`0x41`). Use
`sign_input` to choose a signature mode for each input of a prepared
transaction. For OTDA, pass the Chronicle activation state for the actual
spend. The wallet calls an external signer and verifies the returned signature
before building the unlocking script. [Protocol specification](docs/spec.en.md)
· [Python reference and node tests](reference/README.md)

The wallet adapter accepts a direct SM2 signature from a single signer in a
GB/T 35275-2026 `SignedData` envelope. The envelope uses
`SignedData.version = 1` and `SignerInfo.version = 2`. The Python and Rust
command-line signers use dedicated test keys. [SignedData integration](reference/README.md#signeddata-payment-interop)
· [Python test signer](reference/interop/python-signer/README.md)
· [Rust test signer](reference/interop/rust-signer/README.md)

## Complete transactions and stack measurements

BSV Node 1.2.3 and the project's pinned chain-gang validate the complete inputs of these deterministic fixtures. The node replays scripts with supplied prevouts. Funded mempool and mining tests have separate records. Scripts and transactions are measured in bytes. Script sizes follow input and output order. `× n` indicates n equal sizes. Stack peaks refer to input zero, with independent peaks for main-stack items, altstack items, and combined payload. The development evaluator measures stack payload bytes on the successful path.

| Signing mode and unlocking encoding | Inputs×outputs | Previous locks | Unlocks | New locks | Total | Main / alt items | Stack payload |
| --- | --- | --- | --- | --- | --- | --- | --- |
| BIP143 ALL `0x41` | 2×2 | 144,925 × 2 | 291 × 2 | 144,925 × 2 | 290,554 | 122 / 133 | 4,147 |
| OTDA ALL `0x61`, v1.1.0 default | 2×2 | 144,925 × 2 | 13,023 × 2 | 144,925 × 2 | 316,018 | 122 / 133 | 580,080 |
| OTDA ALL `0x61`, v1.0.0 literal | 2×2 | 144,925 × 2 | 290,109 × 2 | 144,925 × 2 | 870,194 | 122 / 133 | 580,080 |

## Marginal and lifecycle costs

Each marginal cell shows the **change in total bytes (output locks / input unlocks / other bytes)**. Other bytes include values, outpoints, sequence numbers, and CompactSize fields. Previous locks identify the coins being spent and belong to their funding transactions. Both lifecycle totals include native P2PKH funding and exit. The second adds one payment between project outputs.

| Template and mode | Added-input shape | Added-input bytes | Added-output shape | Added-output bytes | Fund and exit | One turnover |
| --- | --- | --- | --- | --- | --- | --- |
| `v1.0.0` · `0x41` | 3×2 | 334 (0 / 291 / 43) | 2×3 | 144,938 (144,925 / 0 / 13) | 290,780 | 581,334 |
| `v1.0.0` · `0x61` | 3×2 | 290,277 (0 / 290,232 / 45) | 2×3 | 434,814 (144,925 / 289,876 / 13) | 290,794 | 1,160,988 |

[Unified benchmark and reproduction](../../docs/benchmark.md)
