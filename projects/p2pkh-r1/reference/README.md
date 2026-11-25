# Reference implementation

The wallet creates outputs from [the canonical template](../template/template.hex) by default. The assembler rebuilds those bytes independently from the literal blocks in [lock.asm](./asm/lock.asm). Conformance compares three owner vectors, validates three consecutive ordinary payments, and exercises the twelve paired sighash modes and four unpaired SINGLE modes. Both BSV Node and chain-gang must accept each valid complete input, including the two OTDA companion cases. This is input-level regtest validation with supplied UTXOs and explicit script flags.

Use Python 3.12 on Linux x86-64 with Git and a Rust toolchain available to build the pinned Python extension. Install the dependencies from requirements.txt before running the node comparison. It pins tx-engine to [8b60b71a12](https://github.com/linzhm/chain-gang/commit/8b60b71a12a69fdcb465d3e627dbf6f43d6ed081) from the fork's `fix/otda-complete-validation` branch. CI checks the installed Git commit before executing the full-input tests. The ordinary TypeScript, Rust and Go SDKs are independent of this dependency.

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
prebuilt template. The published 59,582-byte template is the default for
the Python generator and the published SDKs.

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
| ForkID ALL, fund and exit | 120,159 B | 96,015 B |
| ForkID ALL, one turnover | 240,093 B | 191,805 B |
| Chronicle OTDA ALL, fund and exit | 120,173 B | 96,029 B |
| Chronicle OTDA ALL, one turnover | 478,367 B | 381,791 B |

The ordinary ForkID unlocking script is 326 bytes for both locks. At two
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
| ForkID ALL | 326 B | 95,790 B | 369 B | 47,521 B |
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
