# WOTS+ (SHA-256)

[简体中文](README.zh-CN.md) · [4thGraph](../../README.md) · [Project index](../README.md) · [Versions](versions/index.json)

## Developer resources

**[Wallet SDK quickstart](docs/sdk.en.md#quickstart)** · [Unified wallet SDK](../../sdk/README.md#quickstart)

Choose a receive template and connect a durable one-time signer. The cached-step profile supports eligible OTDA reconstruction.

[Protocol](docs/developer.en.md#protocol) · [Security](docs/developer.en.md#security) · [Verify](#run-the-checks) · [Transaction costs](#complete-transactions-and-stack-measurements)

**Status** · v0.1.0 development baseline.

This experiment verifies a WOTS+ one-time signature in Bitcoin Script and binds
it to the current BSV transaction input. It uses the RFC 8391
`WOTSP-SHA2_256` hash chains, a 64-byte BSV public-key encoding and a
2,144-byte raw signature. The [specification](docs/spec.md) describes the encoding
and its relationship to XMSS.

Each key authorizes one signature for one UTXO. The reference wallet accepts an
external signing callback. A persistent signer must reserve and consume the key
before returning a signature, even if the spend is never broadcast or confirmed.
The reference `OneTimeSigner` enforces this rule within one process for testing.

Use `locking_script(key)` for transaction-bound tests. The detached verifier
from `locking_script(key, transaction=False)` accepts a caller-provided digest
and is only for testing the primitive. The payment lock supports the twelve
BIP143 and Chronicle OTDA modes, with BIP143 `ALL` (`0x41`) as the wallet default.

## Use cases and trade-offs

Use WOTS+ to compare SHA-256 one-time signatures when witness size matters. The raw signature is 2,144 bytes, while a Lamport signature here is 8,192 bytes. A fair transaction comparison includes both the payment locks and the unlocking scripts. WOTS+ offers a canonical lock and two cache presets. Use the published measurements to examine how the smaller cached-step lock and eligible OTDA reconstruction affect funding, turnover and exit. [Measured costs](#complete-transactions-and-stack-measurements)

The payment workflow requires a fresh key per UTXO, including change. Reserve that key durably before returning a signature. A wallet investigating repeated turnover should test key reservation and rebroadcast alongside script verification. [Wallet integration](docs/sdk.en.md)

## Run the checks

Run from the repository root in a Python virtual environment.

```sh
python -m pip install -r projects/wots-plus/reference/requirements.txt
python -m unittest discover -s projects/wots-plus/reference -p test_wots.py -v
(cd projects/wots-plus/reference && python -m unittest -v test_node.ChainGangTests test_acceptance)
```

Use `bash projects/wots-plus/reference/verify.sh` for the isolated BSV Node
runner on Linux x86-64, or `bash projects/wots-plus/reference/verify_apple.sh`
with Apple Container. The complete-input checks use synthetic funds and compare
the BSV Node result with chain-gang. The bounded matrix checks 1,230 rows
against separately specified sighash outcomes. A separate complete-input
test exercises a one-bit mutation in each of the 67 signature chains.

See the [validation record](docs/validation.md) for completed checks, test
limits and the script-size comparison with Lamport OTS. The 16 reproducible
payment vectors are in [vectors.json](versions/v0.1.0/vectors.json).

### Cached-constants candidate

`locking_script(key, cached_constants=True)` opts in to a 36,283-byte
payment lock. Each WOTS+ step uses the same SHA-256 inputs as the existing
script. The generator keeps the two key-and-mask address fields and the
zero function prefix on the stack and retrieves them as needed. The raw
signature is 2,144 bytes, and the ordinary BIP143 unlocking script is
2,310 bytes. Use a fresh one-time key for each UTXO across both formats.

In signed payments with two WOTS+ inputs and two WOTS+ outputs, the
candidate saves 11,966 bytes under BIP143 ALL and 35,898 bytes under
Chronicle OTDA ALL. The acceptance tests run the 1,230-row matrix and
mutations across all 67 signature chains for both formats.

The full lifecycle starts with one native P2PKH input funding two WOTS+
outputs and ends with both outputs spent to native P2PKH. The turnover
path adds a WOTS+ two-input, two-output payment in between.

| Path | Existing format | Cached constants |
| --- | ---: | ---: |
| BIP143 ALL, fund and exit | 89,496 B | 77,530 B |
| BIP143 ALL, one turnover | 178,765 B | 154,833 B |
| Chronicle OTDA ALL, fund and exit | 89,510 B | 77,543 B |
| Chronicle OTDA ALL, one turnover | 347,775 B | 299,911 B |

Exit costs the same in both formats because the exit outputs are ordinary
P2PKH and the WOTS+ signature and witness format are identical.

### Step table candidate

`locking_script(key, cached_constants="steps")` builds a 33,956-byte lock.
It adds fifteen four-byte step indices to the existing stack cache. The
steps feed exactly the same addresses into SHA-256. The ordinary signature
and 2,310-byte BIP143 witness keep their existing encodings. The two-in,
two-out BIP143 ALL example saves 4,654 bytes compared with the
36,283-byte cache. Chronicle OTDA ALL saves 13,962 bytes.

The development evaluator measured a main stack peak of 28 items, up from
13 with the previous cache, with 67 altstack items in both. The same 1,230
payment cases and 67 signature-chain mutations run against both engines.
Use a fresh key across all formats.
The [benchmark guide](../../docs/benchmark.md) describes the optional
durable signer wrapper used for the synthetic keys.

### OTDA output reconstruction

Use `compress_otda=True` with `sign_spend` or `sign_payment` only when
Chronicle functional unlocking is available. Version 2 OTDA ALL and paired
OTDA SINGLE use the [prebuilt reconstruction program](versions/v0.1.0/cached-steps-layout.json)
to recreate cached-steps outputs. SINGLE covers only its same-index output.
Earlier null outputs stay in the signed prefix, and unpaired SINGLE
uses the existing companion authorization. Mixed transactions copy
unrecognized outputs literally. The wallet chooses the shorter encoding,
signs once, and preserves the preimage and the signer's original signature.
Other modes and version 1 use their existing encoding.

| 2 WOTS+ inputs and 2 WOTS+ outputs, OTDA ALL | Literal | Reconstructed |
| --- | ---: | ---: |
| Transaction | 208,406 B | 79,090 B |
| Extra input | 70,354 B | 5,696 B |
| Extra output | 101,901 B | 34,145 B |

Paired OTDA SINGLE with two WOTS+ inputs and two WOTS+ outputs measures
78,921 bytes, down from 140,473 bytes. Adding an input with no corresponding
output costs 2,440 bytes. Adding a cached-steps output without a matching
input costs 33,967 bytes.

The full-input tests verify both ANYONECANPAY settings, mixed outputs,
byte-for-byte witness stack equivalence and the literal fallback.
From the repository root, check the checked-in artifacts with
`python projects/wots-plus/reference/generate_reconstruction.py --check`.

### Lean conformance

Build the [bsv-script-lean evaluator](https://github.com/Calhooon/bsv-script-lean#try-it)
and run the same synthetic spend fixtures through its complete-input API.

```sh
python projects/wots-plus/reference/test_lean.py /path/to/bsv-script-lean/eval/bsvs
```

The runner checks the transaction gate and the selected input's Script verdict
for the sighash matrix and malformed witnesses. It also checks a BIP143 `ALL`
spend at Genesis-era heights before Chronicle. This is a separate executable
specification check alongside BSV Node and chain-gang.

## Developer and wallet integration

Authenticate the chosen funding outpoint and match its transaction-bound
script against the selected key and layout. Arrange the recipients, change
and fee before using `sign_payment` for a single input or `sign_spend` for a
prepared input. The signer receives a 32-byte digest and returns one
2,144-byte signature. Keep the one-time reservation durable before the
callback returns a signature. Generate a fresh key for every output,
including change. [Payment implementation](reference/payment.py)

The output cache reduces the bytes paid at funding and at every same-template
output. OTDA output reconstruction reduces repeated copies in the input.
In the paired SINGLE fixture, the two-stack payload peak is 70,280 bytes with
either witness encoding, even as the signed transaction falls from 140,473
to 78,921 bytes.

## Complete transactions and stack measurements

These deterministic fixtures use commit `beeb4dd`. BSV Node 1.2.3 and the project's pinned chain-gang validate the complete inputs. The node replays scripts with supplied prevouts. Funded mempool and mining tests have separate records. Scripts and transactions are measured in bytes. Script sizes follow input and output order. `× n` indicates n equal sizes. Stack peaks refer to input zero, with independent peaks for main-stack items, altstack items, and combined payload. The development evaluator measures stack payload bytes on the successful path.

| Template and mode | Inputs×outputs | Previous locks | Unlocks | New locks | Total | Main / alt items | Stack payload |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `canonical` · `0x41` | 2×2 | 42,266 × 2 | 2,310 × 2 | 42,266 × 2 | 89,270 | 11 / 67 | 2,599 |
| `canonical` · `0x61` | 2×2 | 42,266 × 2 | 86,806 × 2 | 42,266 × 2 | 258,266 | 11 / 67 | 171,454 |
| `cached-constants` · `0x41` | 2×2 | 36,283 × 2 | 2,310 × 2 | 36,283 × 2 | 77,304 | 13 / 67 | 2,639 |
| `cached-constants` · `0x61` | 2×2 | 36,283 × 2 | 74,840 × 2 | 36,283 × 2 | 222,368 | 13 / 67 | 147,522 |
| `cached-steps` · `0x41` | 2×2 | 33,956 × 2 | 2,310 × 2 | 33,956 × 2 | 72,650 | 28 / 67 | 2,699 |
| `cached-steps` · `0x61` | 2×2 | 33,956 × 2 | 70,186 × 2 | 33,956 × 2 | 208,406 | 28 / 67 | 138,214 |
| `cached-steps-reconstructed` · `0x41` | 2×2 | 33,956 × 2 | 2,310 × 2 | 33,956 × 2 | 72,650 | 28 / 67 | 2,701 |
| `cached-steps-reconstructed` · `0x61` | 2×2 | 33,956 × 2 | 5,530 × 2 | 33,956 × 2 | 79,090 | 28 / 67 | 138,214 |
| `cached-steps-reconstructed` · `0x63` · before | 2×2 | 33,956 × 2 | 36,217 / 36,226 | 33,956 × 2 | 140,473 | 28 / 67 | 70,280 |
| `cached-steps-reconstructed` · `0x63` · after | 2×2 | 33,956 × 2 | 5,441 / 5,450 | 33,956 × 2 | 78,921 | 28 / 67 | 70,280 |
| `cached-steps-reconstructed` · `0xe3` · before | 2×2 | 33,956 × 2 | 36,176 / 36,185 | 33,956 × 2 | 140,391 | 28 / 67 | 70,198 |
| `cached-steps-reconstructed` · `0xe3` · after | 2×2 | 33,956 × 2 | 5,399 / 5,408 | 33,956 × 2 | 78,837 | 28 / 67 | 70,198 |
| `cached-steps-reconstructed` · `0xe1` · after | 2×2 | 33,956 × 2 | 5,488 × 2 | 33,956 × 2 | 79,006 | 28 / 67 | 138,132 |

## Marginal and lifecycle costs

Each marginal cell shows the **change in total bytes (output locks / input unlocks / other bytes)**. Other bytes include values, outpoints, sequence numbers, and CompactSize fields. Previous locks identify the coins being spent and belong to their funding transactions. Both lifecycle totals include native P2PKH funding and exit. The second adds one payment between project outputs.

| Template and mode | Added-input shape | Added-input bytes | Added-output shape | Added-output bytes | Fund and exit | One turnover |
| --- | --- | --- | --- | --- | --- | --- |
| `canonical` · `0x41` | 3×2 | 2,353 (0 / 2,310 / 43) | 2×3 | 42,277 (42,266 / 0 / 11) | 89,496 | 178,766 |
| `canonical` · `0x61` | 3×2 | 86,974 (0 / 86,929 / 45) | 2×3 | 126,831 (42,266 / 84,554 / 11) | 89,510 | 347,776 |
| `cached-constants` · `0x41` | 3×2 | 2,353 (0 / 2,310 / 43) | 2×3 | 36,294 (36,283 / 0 / 11) | 77,529 | 154,833 |
| `cached-constants` · `0x61` | 3×2 | 75,008 (0 / 74,963 / 45) | 2×3 | 108,882 (36,283 / 72,588 / 11) | 77,543 | 299,911 |
| `cached-steps` · `0x41` | 3×2 | 2,353 (0 / 2,310 / 43) | 2×3 | 33,967 (33,956 / 0 / 11) | 72,876 | 145,525 |
| `cached-steps` · `0x61` | 3×2 | 70,354 (0 / 70,309 / 45) | 2×3 | 101,901 (33,956 / 67,934 / 11) | 72,889 | 281,295 |
| `cached-steps-reconstructed` · `0x41` | 3×2 | 2,353 (0 / 2,310 / 43) | 2×3 | 33,967 (33,956 / 0 / 11) | 72,875 | 145,525 |
| `cached-steps-reconstructed` · `0x61` | 3×2 | 5,696 (0 / 5,653 / 43) | 2×3 | 34,145 (33,956 / 178 / 11) | 72,889 | 151,979 |
| `cached-steps-reconstructed` · `0x63` · before | 3×2 | 2,440 (0 / 2,397 / 43) | 2×3 | 33,967 (33,956 / 0 / 11) | 72,830 | 213,303 |
| `cached-steps-reconstructed` · `0x63` · after | 3×2 | 2,440 (0 / 2,397 / 43) | 2×3 | 33,967 (33,956 / 0 / 11) | 72,831 | 151,751 |
| `cached-steps-reconstructed` · `0xe3` · before | 3×2 | 2,358 (0 / 2,315 / 43) | 2×3 | 33,967 (33,956 / 0 / 11) | 72,749 | 213,139 |
| `cached-steps-reconstructed` · `0xe3` · after | 3×2 | 2,358 (0 / 2,315 / 43) | 2×3 | 33,967 (33,956 / 0 / 11) | 72,749 | 151,585 |
| `cached-steps-reconstructed` · `0xe1` · after | 3×2 | 5,531 (0 / 5,488 / 43) | 2×3 | 34,145 (33,956 / 178 / 11) | 72,808 | 151,814 |

[Unified benchmark and reproduction](../../docs/benchmark.md)
