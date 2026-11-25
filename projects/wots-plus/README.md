# WOTS+ (SHA-256)

**Status** · v0.1 development baseline.

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
ForkID and Chronicle OTDA modes, with ForkID `ALL` (`0x41`) as the wallet default.

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
payment vectors are in [template/vectors.json](template/vectors.json).

### Cached-constants candidate

`locking_script(key, cached_constants=True)` opts in to a 36,283-byte
payment lock. Each WOTS+ step uses the same SHA-256 inputs as the existing
script. The generator keeps the two key-and-mask address fields and the
zero function prefix on the stack and retrieves them as needed. The raw
signature is 2,144 bytes, and the ordinary ForkID unlocking script is
2,310 bytes. Use a fresh one-time key for each UTXO across both formats.

In signed payments with two WOTS+ inputs and two WOTS+ outputs, the
candidate saves 11,966 bytes under ForkID ALL and 35,898 bytes under
Chronicle OTDA ALL. The acceptance tests run the 1,230-row matrix and
mutations across all 67 signature chains for both formats.

The full lifecycle starts with one native P2PKH input funding two WOTS+
outputs and ends with both outputs spent to native P2PKH. The turnover
path adds a WOTS+ two-input, two-output payment in between.

| Path | Existing format | Cached constants |
| --- | ---: | ---: |
| ForkID ALL, fund and exit | 89,496 B | 77,530 B |
| ForkID ALL, one turnover | 178,765 B | 154,833 B |
| Chronicle OTDA ALL, fund and exit | 89,510 B | 77,543 B |
| Chronicle OTDA ALL, one turnover | 347,775 B | 299,911 B |

Exit costs the same in both formats because the exit outputs are ordinary
P2PKH and the WOTS+ signature and witness format are identical.

### Step table candidate

`locking_script(key, cached_constants="steps")` builds a 33,956-byte lock.
It adds fifteen four-byte step indices to the existing stack cache. The
steps feed exactly the same addresses into SHA-256. The ordinary signature
and 2,310-byte ForkID witness keep their existing encodings. The two-in,
two-out ForkID ALL example saves 4,654 bytes compared with the
36,283-byte cache. Chronicle OTDA ALL saves 13,962 bytes.

The development evaluator measured a main stack peak of 28 items, up from
13 with the previous cache, with 67 altstack items in both. The same 1,230
payment cases and 67 signature-chain mutations run against both engines.
Use a fresh key across all formats.
The [benchmark guide](../../shared/benchmark.md) describes the optional
durable signer wrapper used for the synthetic keys.

### OTDA output reconstruction

Use `compress_otda=True` with `sign_spend` or `sign_payment` only when
Chronicle functional unlocking is available. Version 2 OTDA ALL uses the
[prebuilt reconstruction program](template/cached-steps-layout.json) to
recreate cached-steps outputs. Mixed transactions copy other outputs
literally. The wallet chooses the shorter encoding, signs once, and
preserves the preimage and the signer's original signature. Other modes
and version 1 use their existing encoding.

| 2 WOTS+ inputs and 2 WOTS+ outputs, OTDA ALL | Literal | Reconstructed |
| --- | ---: | ---: |
| Transaction | 208,406 B | 79,090 B |
| Extra input | 70,354 B | 5,696 B |
| Extra output | 101,901 B | 34,145 B |

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
for the sighash matrix and malformed witnesses. It also checks a ForkID `ALL`
spend at Genesis-era heights before Chronicle. This is a separate executable
specification check alongside BSV Node and chain-gang.
