# Matched P2PKH-R1 and sCrypt comparison

[简体中文](scrypt-matched.zh-CN.md) · [Project overview](../README.md) · [Historical upstream comparison](scrypt-comparison.md)

The historical single-entry verifier from the public `scrypt-ts-lib` R1 library was **2,248,716 bytes**. It uses affine point arithmetic, separate scalar multiplications, and inline modular inversion ASM. The eight-entry arithmetic test contract was 4,485,650 bytes. That run replayed the two detached verifiers and the then-current payment lock using a public payment vector. These sizes describe the pinned builds and replay conditions. [Upstream R1 source](https://github.com/sCrypt-Inc/scrypt-ts-lib/blob/fc71404fb82bc513dba3908bf47fc231a169787c/src/ec/secp256r1.ts) · [Upstream ASM overrides](https://github.com/sCrypt-Inc/scrypt-ts-lib/blob/fc71404fb82bc513dba3908bf47fc231a169787c/.asm/asm.json)

## The same payment template with two point arithmetic backends

The Script Lab v0.2.0 baseline uses the existing wallet signing entry point and fixed template. The high-level sCrypt port uses the same P-256 projective addition, specialized `a = −3` doubling, and signed residues. We compile it with `scryptc 1.20.0 --asm -O`. The harness extracts the arithmetic and adds instructions that load the field constants from the stack, then inserts the kernels into the same four-bit window, transaction binding, and witness layout. The sCrypt kernel sizes include those adapter instructions. Each build uses an OTDA reconstruction program generated from its kernels. [sCrypt arithmetic source](../reference/comparison/projective.scrypt) · [Compiler extraction and replay](../reference/compare_scrypt.py)

| Component | Script Lab v0.2.0 | sCrypt `-O` arithmetic |
| --- | ---: | ---: |
| Point addition, 135 static copies | 147 B | 215 B |
| Point doubling, 263 static copies | 76 B | 117 B |
| Complete payment lock | **46,302 B** | **66,265 B** |
| OTDA reconstruction program | 3,913 B | 4,022 B |

The harness marks each point addition and doubling site during assembly. It expands both full locks from the same marked script and checks them byte for byte. The 6,469 bytes outside the kernels match. The two kernels account for the **19,963-byte** gap by `135 × 68 + 263 × 41`. The Script Lab generator consumes stack values on their last use, schedules independent expressions, and shares field constants. The figures apply to these two kernel implementations and their stack adapters. [Script Lab arithmetic lowering](../reference/curve_compiler.py)

## Transaction costs and acceptance

The 2×2 case creates two R1 outputs of the same build. The input and output marginals come from 3×2 and 2×3 runs. The lifecycle starts with ordinary P2PKH funding and ends with an exit to ordinary P2PKH. One turnover inserts a 2×2 R1 transfer. The same benchmark runner builds the transactions and measures their serialized sizes.

| Mode | Implementation | Unlock per input | 2×2 transaction | Extra input | Extra output | Fund and exit | With one turnover |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| ForkID ALL | Script Lab | 326 | 93,374 | 369 | 46,313 | 93,599 | 186,974 |
| ForkID ALL | sCrypt arithmetic | 326 | 133,304 | 369 | 66,278 | 133,530 | 266,833 |
| OTDA ALL | Script Lab | 4,264 | 101,250 | 4,430 | 46,393 | 93,613 | 194,863 |
| OTDA ALL | sCrypt arithmetic | 4,377 | 141,406 | 4,543 | 66,362 | 133,544 | 274,949 |

All sizes are in bytes. The sCrypt candidate crosses 65,535 bytes, increasing the output's CompactSize script length from three to five bytes. OTDA reconstruction reuses the expanded template, so the unlock grows by 113 bytes per input. Peak stack payload for the first input is 3,474 / 4,216 bytes under ForkID and 185,613 / 265,473 under OTDA, in Script Lab / sCrypt order. These are combined main and alternate stack payloads from the development evaluator. [Benchmark method](../../../docs/benchmark.md)

The 2×2 ForkID case took 10.4 / 11.0 ms in chain-gang and 41.4 / 47.2 ms through BSV Node loopback RPC, in Script Lab / sCrypt order. For OTDA the figures were 10.1 / 11.4 ms and 42.0 / 50.0 ms. All results use an AMD EPYC 9V74 Linux host and the median of 15 runs after a warmup. They include input preparation and verification.

The arithmetic differential covers 450 deterministic and boundary-coordinate samples. Each build replays 96 payment cases across transaction versions 1 and 2, all 12 paired sighash modes, unpaired SINGLE, and locktime and output value mutations. The harness also executes all 64 valid input witnesses per build, checks the resulting preimage byte for byte, and confirms the 50 literal, 10 reconstructed, and four companion paths. BSV Node 1.2.3 checks each input in the `verifyscript` context with Chronicle active and the prevout created after activation. The pinned chain-gang evaluator checks the complete transaction. [Acceptance runner](../reference/compare_scrypt.py)

In a separate run with the default script and transaction size policies on isolated regtest, all eight funded transactions entered the mempool and were mined. The run covers funding and direct exit for both builds under ForkID ALL and OTDA ALL. The sCrypt build's funding transactions were about 133 KB each. Turnover figures in the table come from `verifyscript`. [Funding and mining fixture](../../../src/fourthgraph/benchmark/admission.py) · [Node configuration](../../../tools/verify_node.sh)

The public implementation has room to move scalar multiplication to projective coordinates and windows, with the single ECDSA scalar inverse provided and checked as a witness. Further reductions to this sCrypt candidate can target the repeated doubling kernel, reuse of point-addition temporaries, and the stack cleanup generated for general function bodies.

## Reproduce

Set up the [project Python environment](developer.en.md) and run from the repository root.

```sh
bash tools/setup-workspaces.sh
python3.12 -m venv projects/p2pkh-r1/workspace/comparison-venv
projects/p2pkh-r1/workspace/comparison-venv/bin/python -m pip install \
  -r projects/p2pkh-r1/reference/requirements.txt 'ecdsa==0.19.1'
scratch=$(mktemp -d)
gh release download v1.20.0 --repo sCrypt-Inc/compiler_dist \
  --pattern 'scryptc-1.20.0-Linux-x86_64' --dir "$scratch"
chmod +x "$scratch/scryptc-1.20.0-Linux-x86_64"
GHCRTS=-N2 PYTHONPATH=src:. bash tools/verify_node.sh -- \
  projects/p2pkh-r1/workspace/comparison-venv/bin/python projects/p2pkh-r1/reference/compare_scrypt.py \
  --compiler "$scratch/scryptc-1.20.0-Linux-x86_64" --output projects/p2pkh-r1/workspace/build/scrypt-comparison.json
GHCRTS=-N2 PYTHONPATH=src:. bash tools/verify_node.sh --profile default -- \
  projects/p2pkh-r1/workspace/comparison-venv/bin/python projects/p2pkh-r1/reference/compare_scrypt.py \
  --compiler "$scratch/scryptc-1.20.0-Linux-x86_64" --admission \
  --output projects/p2pkh-r1/workspace/build/scrypt-admission.json
```
