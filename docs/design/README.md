# 4thGraph workflow and verification design

[简体中文](README.zh-CN.md) · [Documentation index](../README.md) · [CPN experiment history](cpn-experiments.md)

4thGraph uses typed Forth to define computation, composable transaction assertions to constrain spends, and a colored Petri net (CPN) to explore how transitions fit into transactions. The compiler checks semantic constraints before comparing costs. The selected plan fixes the deployed locks, witness interfaces, and transaction boundaries.

## Implementation baseline

| Surface | Available in the compiler |
| --- | --- |
| Forth | The typed Core subset and BSV extensions express bounded computation, ranges, byte encoding, host actions, and Script construction. [Language](../language/README.md) · [Libraries](../language/stdlib.md) |
| `stage:` | Declares a word, input, output and signing role. The compiler builds a typed dependency graph, supports fused, atomic two-input and serial layouts for two stages, with Script or stage proofs, and supports serial and prefix fusion for eligible three-stage graphs. The Gforth frontend records ordered resources, selectors, signing context and policy. Its executable backend is limited to supported Script layouts. [Workflow builds](../toolchain.md#可执行交易图) · [Gforth frontend](../../projects/workflow-examples/gforth/README.md) |
| `relation:` | Compiles a public `u32 -- u32` transition and `u32 -- route` decision as one spend. The planner can compare Script, transparent R1CS and BLS12-381 Groth16 with a matching external setup. The circuit emitter can infer the same pair from two `stage:` declarations. That circuit still includes both words. [Planner](../../src/fourthgraph/verification/plan.py) · [Circuit emitter](../../src/fourthgraph/verification/circuit_backend.py) |
| Layout search | `--search --explain` compares supported transaction boundaries and witness layouts, and explains authorization, independent submission and applicable size constraints. `--cpn-plan` emits the canonical selected plan. The earlier `--explore-partitions` and `--partition-cut` prototype found typed cuts in one linear word. Those options and its `reuse` pass were in the older workspace snapshot. [Search](../toolchain.md#有界候选搜索) · [Historical experiments](cpn-experiments.md) |
| Verifiers | The BLS12-381 project supplies fixed, mixed and dynamic public-input verification. The separate BN254 project has a fixed-statement, owner-authorized replay with a different binding interface. BLS12-381 stage circuits and mixed layouts use the shared workflow binding. [BLS12-381 release history](../../projects/groth16-bls12-381/README.md) · [BN254 project](../../projects/groth16-bn254/README.md) |
| STARK | The counter proves a bounded public relation with Winterfell on the host. The separate SHA-256 profile verifies selected trace openings with compiled Script. The full Script verifier and transaction envelope still need integration. [Winterfell SHA-256 STARK](../../projects/stark-winterfell-sha256/docs/verification.en.md) |

## State and transaction assertions

A place specifies a state type, disclosure policy, encoding, and provenance. A transition has ordered input and output places, one typed Forth relation, evidence and authorization requirements, and a transaction assertion. The physical plan maps each transition to a transaction and input index. Actual spendable tokens carry the outpoint, amount, script, and validated state or commitment.

| State carrier | What the next computation can read |
| --- | --- |
| Same-input stack | Fused stages can pass checked values directly. The Script result must satisfy the applicable success and stack rules. Stack lifetime ends with that input. |
| Spendable successor | The parent creates `<state> <body>` or embeds a commitment. The next spend reads data from its new lock and checks the real predecessor and required provenance. |
| Public tail or receipt | A supported top-level `OP_RETURN` can terminate a spendable lock with a true top value and leave serialized metadata in the script. A separate `OP_FALSE OP_RETURN <data>` receipt is an unspendable output. Hosts can read both. A later Script can verify bytes from an authenticated parent transaction. |

PELS expresses successor constraints on state, amount and code. A logical cycle such as `A → B → C → A` consumes new outpoints each time. A branch can exit after any authorized state, and a timeout can compete for the same UTXO. The finite execution plan records actual dependencies. The standalone PELS builder and the dynamic same-code successor template already support bounded cases. [PELS locks and witness assembly](../pels-locks.md) · [CPN execution model](../../src/fourthgraph/workflow/cpn.py)

Each assertion requests the fields it needs. Examples include one paired output, all ordered outputs, a previous amount, a locktime, or a permitted successor program. PUSHTX is the fixed-key secp256k1 ECDSA mechanism that authenticates a supplied or reconstructed preimage against the node's actual spend. PELS uses authenticated fields to enforce continuation. An owner's ECDSA or BIP340 signature provides application authorization where the selected lock implements it. Workflow roles in the first version use ECDSA. Keep the library's declared stack order and sign the final `scriptCode`. [Forth interfaces](../language/stdlib.md) · [Fixed-key binding](../../src/fourthgraph/bsv/pushtx.py)

| Sighash | Coverage required of the assembler |
| --- | --- |
| BIP143 ALL, `0x41` | Authenticate the current outpoint, amount and sequence, linked `scriptCode`, and the input, sequence and ordered output hashes. Reconstruct and compare the required input and output vectors. |
| Chronicle OTDA ALL, `0x61` | Authenticate the applicable serialized input and output vectors. An assertion that reads the spent amount needs separate authenticated parent evidence because OTDA omits the previous-output amount. Check Chronicle activation and the target input shape. |
| `SINGLE`, `NONE`, `ANYONECANPAY` | Check that a claimed paired slot exists. Full output coverage requires appropriate evidence with `SINGLE` or `NONE`. Full input-vector assertions need additional evidence with `ANYONECANPAY`. |

Share one preimage authentication per input where the modes, linked script, and fields agree. Assembly can use a complete preimage, an eligible reconstructed one, or a precomputed ordered output hash for deployment-known successors. Reconstructions must produce the same bytes. A shorter witness and a shorter lock are separate objectives. [Transaction commitments](../toolchain.md#按断言生成交易承诺) · [Serialization](../../src/fourthgraph/bsv/transaction.py)

## Stage declarations and policy

Keep the existing five-argument `stage:` and `relation:` forms. The following extended declarations use the joint planner. A place's type and visibility apply to its state. `witness:` adds a public operand, and `private-witness:` adds a proving-only operand. Witness operands follow state inputs in declaration order. The last argument to `stage:` is the signing role.

```forth
REQUIRE BSV

: advance ( u32 -- u32 ) 1 cell>u32 u32+ ;
: decide ( u32 -- route ) #20 cell>u32 u32<
    IF route-review ELSE route-settle THEN ;

workflow-input: a u32 ;
place: a u32 public ;
place: b u32 public ;
place: c route public ;

stage: ab advance a b operator ;
stage: bc decide b c bob ;
policy: ab allow-direct ;
policy: bc require-zk ;
atomic: ab bc ;
```

Replace the `bc` declaration with this variant to pass a private operand. A public operand uses `witness: bc delta u32 ;` with the same stack order. An application requiring a particular delta must also bind it to its input or commitment.

```forth
range: small-delta u32 1 5 ;
: decide-with-delta ( u32 u32 -- route )
    check-range small-delta u32+ decide ;

stage: bc decide-with-delta b c bob ;
private-witness: bc delta u32 ;
policy: bc require-zk ;
```

| Policy | Candidate eligibility |
| --- | --- |
| `allow-direct` | Direct Script or proof. Every operand published in a Script witness requires disclosure permission. Transparent R1CS requires `assignment-disclosure: STAGE allow ;` for the full assignment, including intermediate wires. |
| `require-proof` | Evidence must come from a proof backend. Transparent R1CS is eligible when the full assignment can be public. |
| `require-zk` | Use a matching zero-knowledge circuit and setup. Chain-visible arithmetic assistance must derive from the proof, public signals and parameters. Public results and information inferable from them remain visible. |

A private witness excludes direct Script and transparent R1CS under every policy. The existing single-relation `require-groth16` selects a proof system. Its presence alone gives no visibility declaration to a Forth stage. `atomic:` requires one transaction and permits multiple inputs. `independent-submit:` retains a separate submission. Report any conflict at the declarations. Stage output constructors can compose specific assertions for amount, script, ordered outputs or fees through the same authenticated fields. [Existing syntax](../language/syntax.en.md#3-declarations-and-parsing)

## A to B to C

`ab` computes `b = (a + 1) mod 2^32` in Script. The Groth16 circuit for `bc` proves `r = decide(b)`, with a 32-bit `b` and a one-bit `r`. Its public-input ABI is `[r, b, bindLo, bindHi]`. The compiler checks the `.zkey` against the generated BLS12-381 R1CS and phase-two setup and pins the verification key and slot order in the lock. The assembler may generate a proof after the actual inputs and ordered outputs are known. The final transaction ID is not an input to its own proof.

For the first version, use the complete canonical BIP143 ALL preimage `P_i` for the input that verifies `bc`, with the final linked `scriptCode`. Use a domain and the canonical semantic descriptor digest. The descriptor contains the stage, typed relation, ordered public slots, and binding format. Compute it before setup, without the verification key or emitted lock bytes. The linked script containing the verification key is covered by `P_i`.

```text
domain = ASCII("4thGraph/stage-bind/v1") || 0x00
d = HASH256(domain || stage_descriptor_sha256 || P_i)
bindLo = uint128_le(d[0:16])
bindHi = uint128_le(d[16:32])
```

Range-check both digest limbs and retain them as constrained public inputs. The verifier and transaction assertion read the same canonical packet. The lock authenticates `P_i` using fixed-key ECDSA, checks the limbs, compares the packet's `b` with the authenticated intermediate, and checks `hashOutputs` against exactly `[payment(r), receipt(root,b)]`. Signatures for the roles authorize the final transaction with the same required coverage. The existing single-relation implementation supplies the precursor to this interface with `[next, route, current, bindLo, bindHi]` and an undomained preimage hash. [Proof envelope](../../src/fourthgraph/verification/plan.py) · [Public packet encoding](../groth16-bls12-381.md#见证布局)

| Layout | Intermediate value and atomicity |
| --- | --- |
| Fused, one input | The A lock runs `ab` and compares its stack result with `b` in the packet, then verifies the proof and the same payment and receipt. Both roles sign. The verifier must preserve or be isolated from live envelope values and the altstack context. One lock pass completes both stages. |
| Atomic, two inputs | Deploy ordered sibling outputs with an A lock and a `bc` guard. Each input authenticates its own preimage, the ordered sibling outpoints and the same full output vector. The A lock commits the computed `b` in the receipt and the guard checks the proof's `b` against that receipt. Any input failure rejects the whole transaction. |
| Serial | `T_AB` constrains the slot, amount and full script of spendable B. `T_BC` spends `(txid(T_AB), vout_B)`, checks the origin and reads the actual B state or commitment. For commitments, the producer validates the commitment and the consumer proof verifies the same opening. B can confirm separately and must retain any specified exit or refund. Replacing a parent changes the child's binding and requires new evidence. |

A backend swap preserves the transaction assertion when the two backends implement the same typed relation and failure semantics over the same authenticated values, check the same authorized spend and ordered output bytes, and meet the same disclosure and submission constraints. Recompile and bind each deployment's actual outpoint and script. Runtime backend selection requires an already deployed lock with all acceptable branches and an equivalent envelope on each branch.

## CPN exploration and report

1. Find typed cut points using liveness, range information and failure order. Move data across transaction boundaries only with an encoding and provenance check. Preserve authorization, public effects, recovery and declared submission boundaries.
2. Combine per-stage evidence backends, transaction layouts, and admissible sighash assemblers. Filter on authorization availability, privacy, atomicity, state provenance, circuit and setup availability, target node rules, and resource limits. Count deployment, any refunds, and any embedded successor or ancestor data.
3. Report eligible and rejected candidates before deployment. Record maximum lock and transaction bytes, path bytes, main and altstack payload peaks and limits, witness size, proving time and memory, verification time and engine, and unmeasured fields. Keep estimates, complete-input replays, policy checks, and mined spends identifiable.

Useful candidates include local arithmetic reuse before splitting, one transaction processing several ordered items under one binding, and deferred activation with a short `hashOutputs` commitment. Batching still validates each input and result. A short commitment requires a later spend to reveal and authenticate code or validate computation evidence. Serial splitting bounds a stage only if the state hand-off also bounds its provenance witness. Test checkpoint sequences at 2, 4 and 8 advances before adding that layout. A checkpoint commits the flow root, rule version, step, state and permitted exit. [Historical sizes and limitations](cpn-experiments.md)

The current linker explores named stages and the transaction layouts it can emit. It compares BIP143 ALL verification plans and can still compare eligible Chronicle assembly for direct Script with `--sighash-family auto`. General cut discovery, batch construction and repeated-history estimates are further exploration work. Cost estimates from the compiler count deployment and successor data. The funded replay records signed transaction bytes, main and altstack payload peaks, proof and witness preparation time, both Script-engine verdicts, and mining. Preparation time includes tool startup and the prover-side check. Prover memory is unmeasured.

### Named paths and proof dependencies

A transaction path assigns a backend and a role to each typed stage. In a fused spend the stages share a value on the stack. With two inputs they share a checked value in the receipt. In a serial path the successor UTXO carries that value. For the two-stage linker, a first-stage proof currently requires the atomic two-input layout and a public state operand. A terminal proof can run in all three layouts. Transparent R1CS requires explicit permission to publish the entire assignment. Groth16 supports a private terminal witness. Committed private state between stages and arbitrary circuit cuts need separate lowerings.

A proof dependency can express several proof systems in the same path. One node may prove a trace with STARK, another may check that exact proof and emit a SNARK, and a third may consume the SNARK's statement for settlement. Roles describe purpose. The planner checks which statement each edge requires, that all nodes contribute to the terminal stage, and that dependencies are acyclic. The current linker can verify independent stage proofs against the same authenticated transaction. Nested proof graphs are reported with `composed_verifier_unavailable` until an adapter constrains the predecessor proof, its parameters and public inputs. The SHA-256 opening verifier is a component for such an adapter.

### Build, select and replay

The `4thgraph cpn` commands expose the same planner and replay path for direct Script and proof-backed stages. `cpn tune` also compares lowering profiles. `cpn verify` checks a funded replay against the selected plan and reruns validation offline with pinned chain-gang. [Runnable agent guide](../../skills/4thgraph/references/cpn.md)

The public counter declares the stages `advance` and `decide`. Export either circuit with `4thgraph-circuit --stage STAGE --output FILE`. Supply external setup files for the exact circuit compiled with the BLS12-381 field. Paths in the following catalog are relative to the catalog file. `workflow_paths` names selectable stage allocations, and `evidence_paths` describes proof dependencies.

```json
{
  "groth16-bls12-381": {
    "decide": {"zkey": "setup/decide.zkey", "ptau": "setup/phase2.ptau"}
  },
  "workflow_paths": {
    "direct": {"layout": "fused", "stages": {
      "advance": {"role": "advance state", "backend": "script"},
      "decide": {"role": "authorize the selected payout", "backend": "script"}
    }},
    "settle": {"layout": "atomic", "stages": {
      "advance": {"role": "advance state", "backend": "script"},
      "decide": {"role": "authorize the selected payout", "backend": "groth16-bls12-381"}
    }}
  },
  "evidence_paths": {
    "wrap-trace": {"stage": "decide", "terminal": "wrapper", "nodes": {
      "trace": {"role": "prove trace", "backend": "winterfell-sha256", "proves": "bounded-trace", "requires": {}},
      "wrapper": {"role": "verify trace proof", "backend": "groth16-bls12-381", "proves": "decide",
                  "requires": {"trace": "bounded-trace"}}
    }}
  }
}
```

```sh
export PYTHONPATH=src:.
SOURCE=projects/proof-counter/workflow.fth
python -m fourthgraph.verification.circuit_backend "$SOURCE" --stage decide --output decide.circom
python -m fourthgraph.workflow.protocol "$SOURCE" --keys "$KEYS" --current 19 \
  --target both --sighash-family bip143 --optimize stack --backend-catalog "$CATALOG" \
  --search --explain > report.json
python -m fourthgraph.workflow.protocol "$SOURCE" --backend-catalog "$CATALOG" \
  --select-candidate report.json path/settle --cpn-plan > selected.json
REGTEST_MIN_MINING_FEE=0.00000001 bash tools/verify_node.sh --profile long-script -- \
  python -m fourthgraph.replay.proof_workflow "$SOURCE" --candidate path/settle \
  --backend-catalog "$CATALOG" --report report.json --output replay.json
```

Rebuilding verifies the source and import digests, candidate allocation, artifact and canonical plan. Keep the original catalog and setup files. The replay uses deterministic test-role keys and produces a separate measurement by funding and mining the chosen path on loopback regtest. It uses the same keys as the report when `KEYS` is generated with `TestKeys().public` from the replay module and the values are encoded as hex. See the private-witness example for `--witness delta=1`. [Public workflow](../../projects/proof-counter/workflow.fth) · [Private workflow](../../projects/proof-counter/workflow-private.fth) · [Replay entry point](../../src/fourthgraph/replay/proof_workflow.py)

This sample used `current=19`, BIP143 ALL and the stack optimizer, with no additional atomicity constraint in the public workflow. Deployment and all listed spends were mined on isolated BSV Node 1.2.3 regtest with a reduced mining fee floor. Byte counts include signatures.

| Layout and backends for `advance → decide` | Deployment (B) | Spend(s) (B) |
| --- | ---: | ---: |
| Fused, Script → Script | 1,052 | 347 |
| Fused, Script → transparent R1CS | 14,927 | 856 |
| Fused, Script → Groth16 | 348,709 | 1,550 |
| Atomic, Script → Groth16 | 349,605 | 1,755 |
| Atomic, transparent R1CS → Groth16 | 363,423 | 2,160 |
| Atomic, Groth16 → Groth16 | 707,015 | 2,857 |
| Serial, Script → Groth16 | 349,473 | 348,892 + 350,376 |
| Fused, Script → Groth16 with private witness | 348,711 | 1,548 |

To build the R1CS → Groth16 path, add `assignment-disclosure: advance allow ;` to the public workflow in the same directory and set the `advance` backend to `r1cs` in the `settle` path. That spend peaked at 32,769 B of combined stack payload. One replay recorded 5.67 s of proof and witness preparation and 145 ms for the BSV Node verification RPC.

<a name="spv-token-cpn"></a>

## SPV Token as a CPN compilation example

Start with one executable Forth relation and CCTP's accepted transaction fixtures. The logical graph includes issuance into a holding place, transfer back to the holding place, and authorized exits such as burn. A holding carries the asset, the original issuance `txid:vout`, the applicable rule identity, the owner, and the quantity or its commitment. A transfer consumes the actual token inputs and authorizes the complete ordered outputs. The input and output totals use checked integer units. Minting and burning have explicit supply rules, and carrier satoshis are accounted for separately. [CCTP transaction relation](https://github.com/linzhm/4thGraph/blob/11c919ab9f87de22ddbbb94bf701f61f6ab2d874/projects/spv-token/docs/actual-transaction-relation.md)

Checks can run in Script, in a proof, or in the receiving wallet according to the source policy. The receiving wallet checks inclusion and confirmation against its adopted header chain. It uses a separate view of spends and conflicts when deciding whether a receipt is spendable. The compiler preserves those evidence requirements when comparing transaction layouts. [SPV Token verification model](https://github.com/linzhm/4thGraph/blob/11c919ab9f87de22ddbbb94bf701f61f6ab2d874/projects/spv-token/README.md#design-conditions)

### One source relation and three candidate builds

| Candidate | Generated checks and required data |
| --- | --- |
| PELS with deterministic constructors | Authenticate the direct parent and its authorized creation rule through the actual outpoint. Build successors from an approved template and bounded state. Demonstrate a bound on required parent data as well as emitted lock bytes. |
| PELS with a parent checkpoint proof | Prove the opening of the selected parent fields against its actual outpoint. Use Script for spend authorization, conservation, and exact ordered successors. CCTP has a mined two-payment baseline for this layout. |
| Recursive proof with PELS settlement | Verify the applicable predecessor proofs and extend their claims with the current transition. Check that each predecessor claim names the actual consumed output and carries the same original issuance anchor and authorized rule identity. Bind the resulting statement to the actual spend with PELS. |

For a linear proof, the zero-step case proves the authorized issuance anchor. A recursive step verifies a prior proof under the expected verification key, checks continuity of the original issuance anchor and rule identity, and requires the current edge to join the authenticated prior tip to the new tip. For a merge, apply this check to each distinct token input. Pin the rule or bind its identifier in the authenticated statement. The tip is a canonical `txid:vout`. Derive it from finalized transaction bytes during proving and from the authenticated current spend when the claim is consumed. Confirmed chain inclusion and wallet spend status have their own checks. [CCTP recursive provenance](https://github.com/linzhm/4thGraph/blob/11c919ab9f87de22ddbbb94bf701f61f6ab2d874/projects/spv-token/docs/recursive-provenance.md) · [Universal TCP predicate](https://github.com/nchain-innovation/transaction_chain_proof/blob/beffd037078bfecaa22b47ca19cd0569d9b776eb/src/predicates/universal_tcp.rs#L96)

The supported fixed-slot declaration identifies the two edges of a single-input lineage step. Run `4thgraph-circuit SOURCE --lineage token-lineage --output statement.json` to inspect the public slots, base and step requirements, and statement digest. A proof that verifies the predecessor must be supplied by a compatible adapter.

```forth
: token-edge ( transaction -- outpoint outpoint )
    dup #0 tx-input-prevout swap #1 tx-output-outpoint ;
recursive: token-lineage token-edge ;
```

Apply three gates before ranking. Check reachable states, feasible authorizations, required evidence, and declared exits under the model's stated bounds. Check the generated transaction and constructor dependencies for cycles, and measure lock, witness, and required history across repeated transfers of the same shape. Follow each Forth assertion to its emitted check and its authenticated operands. The report identifies the source word, the Script fragment or proof constraint, its data producer, and the matching rejections. Changing a parent, output index, or output order must fail at the corresponding binding even when the submitted proof validates for its own statement.

For a cut within a transaction, all parts bind the same actual inputs and ordered outputs. Splitting a circuit at an authenticated commitment also requires both proofs to constrain the same typed intermediate and context. For a cut across transactions, the consumer authenticates the actual continuation outpoint, its state or commitment, and the remaining obligations. Respect atomicity and declared exits. Compare costs over the whole path, including deployment and verifier funding, reconstruction bytes, circuit constraints, proving cost, stack peaks, and confirmation depth. Pin the circuit fingerprint, public-input order and encoding, verification key, and output locks in the selected plan. Recheck setup compatibility when the circuit changes.

### Compilation and replay evidence

The isolated conservation entry below is supported Forth. It checks positive unsigned 64-bit quantities and a checked total. The surrounding contract must supply amounts from authenticated inputs and outputs.

```forth
REQUIRE BSV
range: token-quantity script-int 1 18446744073709551616 ;
range: zero script-int 0 1 ;

lock: conserve-2x2 ( in-a:token-quantity in-b:token-quantity out-a:token-quantity out-b:token-quantity )
    in-a in-b OP_ADD check-range token-quantity
    out-a out-b OP_ADD OP_SUB check-range zero drop
    1 verify ;
```

At CCTP revision `11c919a`, two archived 2→2 payments used 4,075 B each. The shared verifier funding and both payments used 913,547 B in total. An independent replay of the archived transactions and parents accepted all three inputs of each payment on BSV Node and chain-gang. The Forth entry above emitted a 115 B Script with the stack optimizer. In isolated spends both engines accepted `300 + 200 → 275 + 225` and `275 + 150 → 350 + 75` and rejected an extra unit, a zero output, and aggregate overflow. [Pinned CCTP replay and sizes](https://github.com/linzhm/4thGraph/blob/11c919ab9f87de22ddbbb94bf701f61f6ab2d874/projects/spv-token/docs/covenant-backtrace.md) · [Archived results](https://github.com/linzhm/4thGraph/blob/11c919ab9f87de22ddbbb94bf701f61f6ab2d874/projects/spv-token/fixtures/covenant-backtrace-2x2-summary.json)

An independent Script replay of the CCTP BSB22 archive at the same revision accepted all nine inputs of the two certified mints and two transfer transactions with BSV Node 1.2.3 and pinned chain-gang. The four transactions ranged from 2,124,650 B to 15,081,190 B. These sizes include the transaction context and predecessor evidence carried by that layout. [CCTP continuity archive summary](https://github.com/linzhm/4thGraph/blob/11c919ab9f87de22ddbbb94bf701f61f6ab2d874/projects/spv-token/fixtures/v3-continuity-regtest-summary.json)

Independent local component trials also linked the typed Forth edge to the slot parameters of nChain's MNT4/MNT6 backend. That backend accepted zero, one, and two hops and rejected a changed issuance root and a valid proof for the wrong predecessor. A separate 656 B PELS fragment extracted the 36 B current outpoint from byte offset 68 of the BIP143 ALL preimage. Both Script engines rejected the wrong vout of the same transaction and a stale preimage. The compiler emits the typed recursive statement with `--lineage`. Candidates that require this statement are excluded until an on-chain recursive verifier is linked. Use the gated workflow example to replay the existing CPN graph, candidate report, and selected plan. [Runnable CPN examples](../../projects/workflow-examples/README.md#compile-and-replay-a-cpn)

## First release and validation

The bounded implementation supports two-stage Script and BLS12-381 Groth16, disclosed R1CS assignments, terminal private witnesses, and fused, atomic or serial layouts within the stated limits. The next adapters are BN254 with the shared ABI, nested proof verification, and recursive provenance with the original issuance and rule pinned. Confirmed-UTXO recovery and bounded build commitments remain in the toolchain roadmap. [Toolchain roadmap](../toolchain.md#路线图)

In the counter check, both engines accepted Script and Groth16 at all four values below. Both rejected reordered outputs, a valid proof for the wrong `b` using the same preimage, a valid proof from another deployment, and a proof for identical public inputs under a different verification key. With a private witness the planner excluded Script and transparent R1CS. Two private deltas that yielded the same route produced identical public packets and unsigned transactions, and both proofs verified.

| Test | Acceptance |
| --- | --- |
| Differential and boundary | Feed Script and circuit the same inputs `18, 19, 0xfffffffe, 0xffffffff`. Both yield `19, 20, 0xffffffff, 0` and `review, settle, settle, review`. Check the payment, amount, receipt and exact slot order. |
| Invalid hand-off and output | Build a valid proof for the wrong `b`. Alter a payout, amount, receipt, output order or output count, then rebuild the transaction evidence and require rejection on the relevant assertion. |
| Wrong context and key | Move a proof to a second deployment with the same state. Try the old packet with the new preimage, then new public digest limbs with the old proof. Reject a mismatched `.zkey` at build time and a proof from a different setup against the deployed key. Check malformed or noncanonical public inputs. |
| Authorization and privacy | Reject missing or wrong role signatures, a disallowed sighash or era, a private witness sent to direct Script or transparent R1CS, and a proof-required policy with no eligible candidate. Inspect the Groth16 public ABI, witness and receipt for actual disclosure. |
| Complete spends | Replay with BSV Node and pinned chain-gang. Record per-input verdicts, mempool and mining outcomes. Exercise failure of either atomic input and, for serial extensions, replacement parents, wrong origin, pause, exit and refund competition. |

[Existing relation replay](../../src/fourthgraph/verification/plan.py) · [Existing workflow replay](../toolchain.md#可执行交易图) · [Groth16 replay plan](../../projects/groth16-bls12-381/docs/replay-plan.en.md)
