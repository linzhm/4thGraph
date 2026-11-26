# P2PKH-SM2 v1.1.0 candidate

[简体中文](README.zh-CN.md) · [4thGraph](../../README.md) · [Project index](../README.md)

## Developer resources

**[Wallet SDK quickstart](docs/sdk.en.md#quickstart)** · [Unified wallet SDK](../../sdk/README.md#quickstart)

Choose a raw SM2 or SignedData signer. The wallet automatically selects a shorter OTDA unlocking script for eligible payments.

[Protocol](docs/spec.en.md) · [Security](docs/developer.en.md#security) · [Verify](#developer-checks-and-cost-analysis) · [Transaction costs](#complete-transactions-and-stack-measurements)

P2PKH-SM2 lets a payer lock a BSV output to the HASH160 of the recipient’s
uncompressed SM2 public key. To spend the output, the recipient reveals the
public key and supplies one SM2 signature for the current input. Bitcoin Script
uses SM3 to compute the SM2 identity digest ZA and the message digest. It
verifies the SM2 signature and binds the authorization to the spending
transaction through PUSHTX and native `OP_CHECKSIG`.

## Use cases and trade-offs

Evaluate P2PKH-SM2 when a wallet already uses an SM2 signing service. A provider that exposes a raw SM2 API returns the signature directly. A GB/T 35275-2026 provider can return a direct single-signer SignedData envelope under the wallet's trusted signer configuration. The SDK checks that off-chain envelope and writes the extracted 64-byte signature into the transaction. Track which provider operation the wallet uses and validate the exact message and user ID at integration time. [Signing contract](docs/sdk.en.md)

For payments that create other SM2 outputs, compare ForkID and OTDA using the same input and output counts. On eligible Chronicle spends, the v1.1.0 candidate shortens the OTDA unlock by reconstructing the signed preimage. The cost of creating a new SM2 output still includes the 144,925-byte lock. [Reconstruction measurements](#otda-constructor)

## Project version and locking template

The v1.1.0 candidate adds default OTDA reconstruction to the unlocking script. The generator and wallet use the same 144,925-byte locking template `1` as the first public release, v1.0.0.

| Property | Value |
| --- | --- |
| Recipient identifier | HASH160 of the 65-byte public key `04 \|\| X_BE32 \|\| Y_BE32` |
| SM2 user ID | The fixed ASCII value `1234567812345678` |
| Locking script | 144,925 bytes |
| Unlocking script | 291 bytes with ForkID, 294 bytes with unpaired OTDA SINGLE, and transaction-dependent for other OTDA modes |
| Unlocking stack | Signing preimage, uncompressed public key, and 64-byte `r \|\| s` signature |
| Signature modes | ForkID and Chronicle OTDA, each with ALL, NONE, or SINGLE and optional ANYONECANPAY |

The current source includes the [layout manifest](template/layout.json),
[standard SM2 vector](template/sm2-standard.json),
[complete payment vector](template/spend-all.json), and
[16 signing preimages](template/sighash-modes.json). [v1.0.0 release](https://github.com/linzhm/bsv-script-lab/releases/tag/p2pkh-sm2-v1.0.0)

## Generate a locking script

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

## Authorize and verify a payment

Use `sign_payment` for a one-input ForkID ALL payment (`0x41`). Use
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

## Developer checks and cost analysis

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

In the 2×2 fixture, ForkID ALL uses a 291-byte unlock. The literal OTDA ALL encoding serializes
both outputs into each input's signing preimage and raises the unlock to
290,109 bytes. A third output adds 144,925 bytes of output lock and also
changes both existing OTDA unlocks. The marginal table shows those costs
separately. Transaction version and the two SignedData version fields apply to their own encodings.

## Complete transactions and stack measurements

BSV Node 1.2.3 and the project's pinned chain-gang validate the complete inputs of these deterministic fixtures. The node replays scripts with supplied prevouts. Funded mempool and mining tests have separate records. Scripts and transactions are measured in bytes. Script sizes follow input and output order. `× n` indicates n equal sizes. Stack peaks refer to input zero, with independent peaks for main-stack items, altstack items, and combined payload. The development evaluator measures stack payload bytes on the successful path.

| Signing mode and unlocking encoding | Inputs×outputs | Previous locks | Unlocks | New locks | Total | Main / alt items | Stack payload |
| --- | --- | --- | --- | --- | --- | --- | --- |
| ForkID ALL `0x41` | 2×2 | 144,925 × 2 | 291 × 2 | 144,925 × 2 | 290,554 | 122 / 133 | 4,147 |
| OTDA ALL `0x61`, v1.1.0 default | 2×2 | 144,925 × 2 | 13,023 × 2 | 144,925 × 2 | 316,018 | 122 / 133 | 580,080 |
| OTDA ALL `0x61`, v1.0.0 literal | 2×2 | 144,925 × 2 | 290,109 × 2 | 144,925 × 2 | 870,194 | 122 / 133 | 580,080 |

## Marginal and lifecycle costs

Each marginal cell shows the **change in total bytes (output locks / input unlocks / other bytes)**. Other bytes include values, outpoints, sequence numbers, and CompactSize fields. Previous locks identify the coins being spent and belong to their funding transactions. Both lifecycle totals include native P2PKH funding and exit. The second adds one payment between project outputs.

| Template and mode | Added-input shape | Added-input bytes | Added-output shape | Added-output bytes | Fund and exit | One turnover |
| --- | --- | --- | --- | --- | --- | --- |
| `v1.0.0` · `0x41` | 3×2 | 334 (0 / 291 / 43) | 2×3 | 144,938 (144,925 / 0 / 13) | 290,780 | 581,334 |
| `v1.0.0` · `0x61` | 3×2 | 290,277 (0 / 290,232 / 45) | 2×3 | 434,814 (144,925 / 289,876 / 13) | 290,794 | 1,160,988 |

[Unified benchmark and reproduction](../../docs/benchmark.md)

<a name="otda-constructor"></a>

## Reconstruct OTDA outputs

The 12,703-byte constructor is part of `scriptSig`. It reuses SM3 round and message-expansion fragments, SM2 point addition and doubling, and repeated instruction runs to rebuild the same signing preimage. For each eligible output it fills the receiver's HASH160 slot in the 144,925-byte lock. The signing callback receives the same message and SM2 user ID as the literal encoding. Use the final signed transaction ID to build a child.

After Chronicle activation, version-2 OTDA ALL can reconstruct matching outputs in their original order. Paired OTDA SINGLE can reconstruct the same-index output and preserve the preceding null outputs in the preimage. Both support `ANYONECANPAY`. Other output templates keep their literal bytes. ForkID, NONE, unpaired SINGLE, version 1 and non-smaller encodings continue with the literal unlocking script. [SDK options](docs/sdk.en.md) · [Constructor and generator](reference/README.md#otda-constructor)

| OTDA ALL, bytes | Literal | Reconstructed |
| --- | ---: | ---: |
| Two inputs and two outputs | 870,194 | 316,018 |
| First input's unlocking script | 290,109 | 13,023 |
| Add one input | 290,277 | 13,189 |
| Add one output | 434,814 | 145,022 |
| Fund and exit | 290,794 | 290,794 |
| Fund, turn over once, and exit | 1,160,988 | 606,812 |

Both encodings use the same fixture keys and amounts and pass BSV Node 1.2.3 and the pinned chain-gang build. The unified benchmark uses the `v1.1.0` profile for automatic reconstruction and `v1.0.0` for the literal encoding.
