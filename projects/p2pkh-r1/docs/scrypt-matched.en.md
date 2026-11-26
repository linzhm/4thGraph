# Matched P2PKH-R1 and sCrypt comparison

[简体中文](scrypt-matched.zh-CN.md) · [Project overview](../README.md) · [Historical upstream comparison](scrypt-comparison.md)

The historical single-entry verifier from the public `scrypt-ts-lib` R1 library was **2,248,716 bytes**. It uses affine point arithmetic, separate scalar multiplications, and inline modular inversion ASM. The eight-entry arithmetic test contract was 4,485,650 bytes. That run replayed the two detached verifiers and the then-current payment lock using a public payment vector. These sizes describe the pinned builds and replay conditions. [Upstream R1 source](https://github.com/sCrypt-Inc/scrypt-ts-lib/blob/fc71404fb82bc513dba3908bf47fc231a169787c/src/ec/secp256r1.ts) · [Upstream ASM overrides](https://github.com/sCrypt-Inc/scrypt-ts-lib/blob/fc71404fb82bc513dba3908bf47fc231a169787c/.asm/asm.json)

## The same payment template with two point arithmetic backends

The baseline is Script Lab v0.2.0. The high-level sCrypt port uses the same P-256 projective addition, specialized `a = −3` doubling, and signed residues. We compile it with `scryptc 1.20.0 --asm -O`. The harness strips its ABI argument copies, boundary marker and return cleanup, then inserts the arithmetic into the same four-bit window, transaction binding, and witness layout. Both builds generate OTDA reconstruction from their respective kernels. The point arithmetic uses high-level source. The harness marker ASM is excluded from the payment lock. [sCrypt arithmetic source](../reference/comparison/projective.scrypt) · [Compiler extraction and replay](../reference/compare_scrypt.py)

| Component | Script Lab v0.2.0 | sCrypt `-O` arithmetic |
| --- | ---: | ---: |
| Point addition, 135 static copies | 147 B | 215 B |
| Point doubling, 263 static copies | 76 B | 117 B |
| Complete payment lock | **46,302 B** | **66,265 B** |
| OTDA reconstruction program | 3,913 B | 4,022 B |

The two arithmetic kernels account for the entire **19,963-byte** lock gap by `135 × 68 + 263 × 41`. The Script Lab generator consumes stack values on their last use, schedules independent expressions, and shares field constants. The sCrypt candidate uses the same projective algorithm and transaction layout, so this comparison isolates how the two point arithmetic kernels are generated. [Script Lab arithmetic lowering](../reference/curve_compiler.py)

## Transaction costs and acceptance

The 2×2 case creates two R1 outputs of the same build. The input and output marginals come from 3×2 and 2×3 runs. The lifecycle starts with ordinary P2PKH funding and ends with an exit to ordinary P2PKH. One turnover inserts a 2×2 R1 transfer. The same benchmark runner builds the transactions and measures their serialized sizes.

| Mode | Implementation | Unlock per input | 2×2 transaction | Extra input | Extra output | Fund and exit | With one turnover |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| ForkID ALL | Script Lab | 326 | 93,374 | 369 | 46,313 | 93,599 | 186,974 |
| ForkID ALL | sCrypt arithmetic | 326 | 133,304 | 369 | 66,278 | 133,530 | 266,833 |
| OTDA ALL | Script Lab | 4,264 | 101,250 | 4,430 | 46,393 | 93,613 | 194,863 |
| OTDA ALL | sCrypt arithmetic | 4,377 | 141,406 | 4,543 | 66,362 | 133,544 | 274,949 |

All sizes are in bytes. The sCrypt candidate crosses 65,535 bytes, increasing the output's CompactSize script length from three to five bytes. OTDA reconstruction reuses the expanded template, so the unlock grows by 113 bytes per input. Peak stack payload for the first input is 3,474 / 4,216 bytes under ForkID and 185,613 / 265,473 under OTDA, in Script Lab / sCrypt order. These are combined main and alternate stack payloads from the development evaluator. [Benchmark method](../../../shared/benchmark.md)

The 2×2 ForkID case took 9.7 / 10.6 ms in chain-gang and 37.2 / 47.0 ms through BSV Node loopback RPC, in Script Lab / sCrypt order. For OTDA the figures were 10.4 / 11.2 ms and 37.1 / 47.6 ms. All results use an AMD EPYC 9V74 Linux host and the median of 15 runs after a warmup. They include input preparation and verification.

The arithmetic differential covers 450 deterministic and boundary-coordinate samples. Each build replays 96 payment cases across transaction versions 1 and 2, all 12 paired sighash modes, unpaired SINGLE, and locktime and output value mutations. Both match expected verdicts in BSV Node 1.2.3 `verifyscript` on isolated regtest and pinned chain-gang. [Acceptance runner](../reference/compare_scrypt.py)

The public implementation has room to move scalar multiplication to projective coordinates and windows, with the single ECDSA scalar inverse provided and checked as a witness. Further reductions to this sCrypt candidate can target the repeated doubling kernel, reuse of point-addition temporaries, and the stack cleanup generated for general function bodies.

## Reproduce

Set up the [project Python environment](developer.en.md) and run from the repository root.

```sh
python3.12 -m venv .venv/p2pkh-r1
.venv/p2pkh-r1/bin/python -m pip install \
  -r projects/p2pkh-r1/reference/requirements.txt 'ecdsa==0.19.1'
scratch=$(mktemp -d)
gh release download v1.20.0 --repo sCrypt-Inc/compiler_dist \
  --pattern 'scryptc-1.20.0-Linux-x86_64' --dir "$scratch"
chmod +x "$scratch/scryptc-1.20.0-Linux-x86_64"
GHCRTS=-N2 PYTHONPATH=. bash shared/verify_node.sh -- \
  .venv/p2pkh-r1/bin/python projects/p2pkh-r1/reference/compare_scrypt.py \
  --compiler "$scratch/scryptc-1.20.0-Linux-x86_64" --output /tmp/r1-scrypt-comparison.json
```
