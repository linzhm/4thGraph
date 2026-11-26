# Reference implementation

The wallet creates outputs from [the v0.2.0 template](../template/v0.2.0/template.hex) by default. The [v0.1.0 template](../template/template.hex) remains available for historical outputs. Its assembly is reproduced independently from [lock.asm](./asm/lock.asm). Conformance compares three owner vectors, validates three consecutive ordinary payments, and exercises the twelve paired sighash modes and four unpaired SINGLE modes. Both BSV Node and chain-gang must accept each valid complete input, including the two OTDA companion cases. This is input-level regtest validation with supplied UTXOs and explicit script flags.

Use Python 3.12 on Linux x86-64 with Git and a Rust toolchain available to build the pinned Python extension. Install the dependencies from requirements.txt before running the node comparison. It pins tx-engine to [8b60b71a12](https://github.com/linzhm/chain-gang/commit/8b60b71a12a69fdcb465d3e627dbf6f43d6ed081) from the fork's `fix/otda-complete-validation` branch. CI checks the installed Git commit before executing the full-input tests. The unified wallet SDK uses this reference environment for R1.

Set `R1_OWNER_HASH160` to the recipient’s 20-byte HASH160 in hex. The canonical template’s embedded owner, layout vector C, and the [payment fixture](../template/spend-all.json) use the same publicly known test key. Outputs using that key are for offline and regtest use only.

```sh
cd projects/p2pkh-r1/reference
python -m pip install -r requirements.txt
python generate_lock.py --owner-hash160 "${R1_OWNER_HASH160:?Set the recipient HASH160}"
bash verify.sh
```

The regtest script downloads BSV Node 1.2.3 and checks the archive against a repository-pinned SHA-256 digest. It runs a local node with no peers and submits only verification RPCs. The software signer in the test uses publicly known test scalars. Integrations should supply a device callback to [wallet.py](./wallet.py). The current release draft awaits physical-device verification, independent review and relay/fee measurements.

The [input acceptance matrix](acceptance.md) runs through the same verification entry point. It records the finite domain, the expected field commitments from the specification, and the coverage check.

## Experimental field AST compiler

Use the Python generator to opt in to the 47,510-byte lock. The Python
wallet recognizes this candidate by comparing all fixed bytes from the
prebuilt template. This profile serves as a compiler comparison.

```sh
python generate_lock.py --compiled-curve --owner-hash160 "${R1_OWNER_HASH160:?Set the recipient HASH160}"
```

The compiler starts with named expressions for the existing projective
point addition and doubling formulas. It counts uses and moves values on
their last read, selects shallow stack instructions, and compares operand
orders for commutative expressions by encoded cost. Coordinates in the
window use signed representatives modulo the field prime. Addition,
subtraction and multiplication preserve congruence, and the only branch
inside the window tests whether the already reduced projective `Z` is zero.
The compiler restores nonnegative `X` and `Z` before the integer comparisons
in the final ECDSA check. It leaves key validation, inversion verification,
sighash branching and native transaction binding in the literal assembly.
The arithmetic bounds are 1,529 bits for addition and 1,547 bits for doubling
before each output reduction. [Field expression compiler](curve_compiler.py)

| Change | Point addition | Doubling | Whole lock |
| --- | ---: | ---: | ---: |
| Literal implementation | 191 B | 104 B | 59,582 B |
| AST stack scheduling with positive residues | 169 B | 92 B | 53,456 B |
| Stack scheduling and signed field residues | 154 B | 77 B | 47,510 B |

For each lifecycle below, one ordinary P2PKH input funds two R1 outputs.
Both R1 inputs eventually pay to two ordinary P2PKH outputs. The turnover
path adds one two-input, two-output R1 payment in between. Byte counts cover
the complete signed transactions.

| Path | Original lock | Compiled lock |
| --- | ---: | ---: |
| BIP143 ALL, fund and exit | 120,159 B | 96,015 B |
| BIP143 ALL, one turnover | 240,093 B | 191,805 B |
| Chronicle OTDA ALL, fund and exit | 120,173 B | 96,029 B |
| Chronicle OTDA ALL, one turnover | 478,367 B | 381,791 B |

The ordinary BIP143 unlocking script is 326 bytes for both locks. At two
R1 inputs and two R1 outputs, OTDA ALL witnesses shrink from 119,454 to
95,310 bytes each because the preimage serializes both output scripts.
Tests compare each kernel with literal assembly, exercise the rare `r+n`
point candidate and infinity rejection, run the 1,296-row input acceptance
matrix for each lock, and spend a two-input, two-output compiled payment in
both independent engines.

## Optimized full-mode template

The [candidate layout](../template/candidates/layout.json) pins the script
bytes, SHA-256 fingerprint, owner HASH160 offset and signing modes. The
wallet fills the 20-byte owner field to create the lock and compares all
fixed bytes when recognizing an output. The assembler and field compiler
run when building the wallet artifacts.

```sh
python generate_templates.py --check
python generate_lock.py --compiled-curve --owner-hash160 "${R1_OWNER_HASH160:?Set the recipient HASH160}"
```

The 47,510-byte lock supports all twelve original types and the existing
companion checks for unpaired OTDA SINGLE. The published template remains
the default for the wallet generator and the existing SDKs.

| 2 R1 inputs and 2 R1 outputs | Unlock per input | Transaction | Extra R1 input | Extra R1 output |
| --- | ---: | ---: | ---: | ---: |
| BIP143 ALL | 326 B | 95,790 B | 369 B | 47,521 B |
| OTDA ALL, literal preimage | 95,310 B | 285,762 B | 95,478 B | 142,563 B |
| OTDA ALL, reconstructed preimage | 6,176 B | 107,490 B | 6,342 B | 47,601 B |

Call `sign_spend(..., compress_otda=True)` when Chronicle functional
unlocking is available. For version 2 transactions with OTDA ALL
(`0x61` or `0xe1`), the wallet starts with the
[precomputed reconstruction program](../template/candidates/otda-all-reconstruct.hex)
and fills the output fields in transaction order. Only outputs matching
the optimized template may use its reconstruction data. Other outputs
are serialized literally. The wallet uses the literal preimage when the
reconstruction is unavailable or takes at least as many bytes. The
signature digest and final unlocking stack are identical for both
encodings. Other sighash types and version 1 use literal preimages.

The test runner verifies complete payments with BSV Node 1.2.3 and
chain-gang. Candidate support across the other SDKs and miner relay policy
require separate validation.

### Shared-kernel reconstruction candidate

Use `compress_otda="shared-kernels"` to select the prebuilt 3,921-byte
reconstruction program. It caches point addition and doubling byte sequences
on the stack before assembling the fixed output script. The resulting preimage
and raw P-256 signature are identical to those from the 5,825-byte reconstruction.
The transaction still uses the 47,510-byte full-mode output template.

| Chronicle OTDA ALL with 2 R1 inputs and 2 R1 outputs | Previous | Shared kernels |
| --- | ---: | ---: |
| Unlock per input | 6,176 B | 4,272 B |
| Full transaction | 107,490 B | 103,682 B |
| Extra R1 input | 6,342 B | 4,438 B |
| Extra R1 output | 47,601 B | 47,601 B |

The reference checks byte-for-byte stack equality, two independent engines
and the version 1 and other-mode fallbacks. The TypeScript, Rust and Go SDKs
recognize the compiled lock and replay its deterministic BIP143 ALL vector
with the existing signer callback. The Python reference provides the complete
sighash and reconstruction experiments.

### Signature-mode sizing experiment

The compiled universal lock measures 47,510 bytes. With the same curve
arithmetic, the BIP143-only experiment measures 47,262 bytes and the
OTDA-only experiment 47,480 bytes. The savings are 248 and 30 bytes per
output, respectively. The fixture checks each family's allowed modes
and the other family's rejection, including unpaired SINGLE. These figures
support keeping the full-mode template for the SDK candidate.

### P2PKH-R1 v0.2.0

The [versioned layout](../template/v0.2.0/layout.json) fixes the 46,302-byte lock
and its 3,913-byte reconstruction program. The generator defaults to v0.2.0.
Use `--version 0.1.0` to reproduce an older output.
The owner HASH160 occupies the same 20-byte field. The Python, TypeScript,
Rust and Go SDKs recognize the prebuilt template. The three non-Python
SDKs replay its [BIP143 ALL payment vector](../template/v0.2.0/spend-all.json)
with their ordinary signer callbacks.

In the Python reference wallet, `sign_spend(..., compress_otda="paired")`
enables reconstruction with version 2 Chronicle OTDA ALL and with paired
OTDA SINGLE (`0x63` and `0xe3`). SINGLE reconstructs the same-index output
and preserves the preceding null outputs in the preimage. Version 1,
unpaired SINGLE, and unrecognized outputs use their existing encodings.
The wallet passes the original digest to the signer and includes the returned
signature bytes in the witness. For version 2 OTDA ALL, the 47,510-byte
compiled and 46,302-byte v0.2.0 templates can share an unlocking script.
The wallet compares a single-template program, a program containing both
templates and the literal preimage by encoded byte count. Outputs are
recreated in their signed order. Other scripts in the transaction are
copied literally.

| 2 R1 inputs and 2 R1 outputs | Transaction | Extra R1 input | Extra R1 output |
| --- | ---: | ---: | ---: |
| OTDA ALL | 101,250 B | 4,430 B | 46,393 B |
| OTDA SINGLE | 101,179 B | 455 B | 46,313 B |

The extra SINGLE input in the comparison has no same-index output. The
acceptance tests verify individual output binding, full replays with both
engines, byte-for-byte witness stack equivalence, and the existing 1,296-case
authorization matrix for v0.2.0.

With one compiled research output and one v0.2.0 R1 output and two R1 inputs, OTDA ALL
takes 110,302 bytes using both templates. Reconstructing only one template
takes 195,028 bytes. The added-input and added-output costs from this shape
are 8,352 and 46,393 bytes, respectively. The extra output uses the v0.2.0
template.
