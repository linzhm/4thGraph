# CPN partition, batching and activation experiments

[简体中文](cpn-experiments.zh-CN.md) · [Workflow and verification design](README.md)

These measurements come from the earlier workspace prototype based on `8af1e1c`. The prototype added `--explore-partitions`, `--partition-cut`, `--optimize reuse` and standalone batching and activation fixtures. The current workflow compiler compares implemented boundaries via `--search --explain`. The prototype's source and exact commands were captured in local snapshot `94de5cdf49fd586b920b0e938478f0e385c48d1b` and its untracked-files parent. The prototype was never released with the current CLI. [Current report and reproduction command](README.md#cpn-exploration-and-report)

## The same Forth across layouts

The prototype compiled `advance` and `decide`, each with 128 fixed-width operations, to 1,544 B and 1,556 B. With initial state 19, `--optimize stack`, and BIP143 ALL, all three layouts produced `next = 2918881427`, the same settlement and receipt. Funded results used BSV Node 1.2.3 and chain-gang. Path size includes deployment. The development evaluator measures combined main- and altstack payload.

| Layout | Largest lock | Largest transaction | Whole path | Peak stack payload | Spends after deployment |
| --- | ---: | ---: | ---: | ---: | ---: |
| Fused, one input | 3,705 B | 3,839 B | 4,186 B | 260 B | 1 |
| Atomic, two inputs | 2,151 B | 4,446 B | 5,109 B | 552 B | 1 |
| Serial | 4,170 B | 4,304 B | 9,352 B | 7,318 B | 2 |

A 2,500 B lock budget leaves the two-input candidate. Adding a 4,000 B transaction limit eliminates that candidate too. Splitting the first word into more stages exposed the cost of embedding the successor script and authenticating raw ancestors. These estimates use placeholder ECDSA signatures.

| Pieces in first word | Total spends | Deployment lock | Last transaction | Whole path |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 2 | 4,170 B | 2,667 B | 9,359 B |
| 2 | 3 | 4,743 B | 10,183 B | 24,961 B |
| 4 | 5 | 5,997 B | 70,629 B | 147,099 B |
| 8 | 9 | 8,937 B | 1,982,433 B | 3,973,627 B |

The prototype found 127 possible cuts carrying one `u32` and built nine. At `advance:384`, after 64 operations, its maximum transaction estimate rose from 4,306 B to 10,183 B and the measured fixture stack payload from 7,325 B to 16,269 B. With that explicit cut, both engines accepted three spends and rejected an incorrect intermediate value. Composing adjacent affine transforms modulo 2³² reduced the two words to 32 B and 44 B. The prototype's fused lock then measured 681 B under the same 2,500 B budget. The candidate changed because the optimizer composed the transforms before applying the boundary.

## Batched calculation and deferred activation

The batching fixture used the same `mix-128` word on an ordered vector and authenticated the transaction once. Both engines rejected a changed result after the preimage was regenerated.

| Items | Computation script | Lock | Spend | Whole path | Path per item |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 1,544 B | 2,002 B | 273 B | 2,410 B | 2,410 B |
| 2 | 3,212 B | 3,692 B | 280 B | 4,107 B | 2,053.5 B |
| 4 | 6,548 B | 7,072 B | 302 B | 7,509 B | 1,877.25 B |

Batching four items saved about 22% per item compared with four separate deployments and spends. The Script backend still inlined the operation for each item. The activation fixture committed the ordered output vector through `hashOutputs`, deployed a small first lock, and placed the complete calculation in the activation transaction. Both engines rejected changed code or amount even with a reconstructed preimage.

| Four-item activation layout | First lock | Computation lock | Whole path |
| --- | ---: | ---: | ---: |
| Direct deployment | 7,072 B | 7,072 B | 7,508 B |
| Deferred with output hash | 407 B | 7,072 B | 8,035 B |
| Arithmetic reuse, direct | 658 B | 658 B | 1,095 B |
| Arithmetic reuse and deferred | 407 B | 658 B | 1,620 B |

The 7,508 B activation-fixture baseline and 7,509 B batching row came from separate signed runs. Signature lengths can vary. Deferred activation reduces the bytes deployed up front and adds a transaction. Bounded checkpoints would also need bounded state provenance. [Current deferred deployment project](../../projects/p2pkh-r1-deferred/README.md)

## Historical source and reproduction

The original tables, commands and assumptions are recorded in `projects/4thgraph/docs/experiments/cpn-decomposition.md` in the saved workspace. The fixtures are `examples/cpn-partition.fth`, `examples/cpn_batch.py` and `examples/cpn_commitment.py` relative to that project's former path. Replaying these figures requires that snapshot and its matching dependencies. Use the current worktree for the Script-only report and the active release manifests for Groth16. [Repository layout](../repository-layout.md) · [Groth16 history](../../projects/groth16-bls12-381/README.md)
