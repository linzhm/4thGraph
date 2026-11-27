# 4thGraph architecture and acceptance

[简体中文](architecture.zh-CN.md) · [Forth baseline](language/README.md)

4thGraph compiles a high-level Forth program into BSV Script and, for supported workflows, a transaction plan. A program states how values arise, who authorizes a spend, which state and outputs must be committed, and where atomicity or independent submission matters. The compile target supplies the applicable transaction versions, chain rules, required signing coverage, and cost policy.

| Layer | Responsibility |
| --- | --- |
| Forth and standard library | The [Forth baseline](language/README.md) defines source semantics, syntax, and public words. PELS is a family of transaction commitment templates. R1 is an owner-authorization example that binds a public-key hash and verifies a signature for the current spend. |
| Compiler and planner | Verify the source contract, compare eligible transaction boundaries, select compatible implementations from proved call-site facts, and link each lock. Emit exact Script bytes and the metadata for the selected build entry point. |
| Assembler and wallet | Bind the plan to actual parent outputs, prepare the selected path's signing material, obtain host authorization when required, and assemble its witness. Consume the exact Script and manifest selected at compile time. The wallet may use a paired project WASM module. |
| Independent evaluation | Evaluate pure formula fixtures on fixed vectors. Verify complete spends against their actual parents with pinned chain-gang. Record BSV Node cross-checks when requested. Treat estimates, offline verification, admission, and confirmation as distinct measurements. |

## Development and tuning

Start with the highest-level Forth and freeze its semantics, target, dependencies, and acceptance fixtures. Explore choices independently so each effect can be attributed. Axis A compares formula passes and bounded pass orders with source and module bindings fixed. Axis B compares Forth algorithms that satisfy the same contract with the compiler plan fixed. Call-site selection compares eligible implementations with high-level source and internal passes fixed. Transaction layout compares eligible transactions and witness layouts under the same coverage contract. An Agent chooses a bounded batch in each space. Fixed evaluators decide validity and report measured costs. Combine shortlisted choices when their dependencies and contracts are compatible, then rerun the same caller or complete spend.

The typed AST and dependency graph record how a result arises. Record a separate hash for the source snapshot, normalized constraints, build plan, exact linked Script, and emitted fragments. A byte hash identifies an artifact. Its source and build records explain which changes produced it and permit replay. Keep multiple plans traceable even when they emit identical bytes.

### Select implementations at call sites

Forth names the operation through a public word. After resolving the word and its input facts, the compiler binds each call site to a registered implementation, then optimizes its graph, schedules its stack, and links it. Two calls to the same word can bind different implementations. Evaluate specialized kernels for known constants, ranges, or coordinate representations, shared representations across adjacent calls, and alternatives for unrolling, table lookup, or reusing intermediates in repeated calls. The first slice selects a specialized kernel at an individual call site.

- **Operation and implementation contracts.** Identify the public word by its semantic operation and argument domain. Point addition, for example, identifies its curve, field, and result equivalence. Register each implementation's version and digest, input and output representations, stack effect, applicable targets, preconditions, and observable failures. Record the source location and expansion instance of a call and include representation adapters or guards in the candidate when needed. Preserve any result encoding the caller can observe.
- **Optimization paths and composition.** Match the signature scheme and curve independently. ECDSA verification on P-256 and on secp256k1 resolves to separate curve paths. General arithmetic rules can apply inside the selected kernel when its semantics and ranges meet their preconditions. Each plan selects one implementation path per call site or region. Choices that cover the same region are alternatives, and a guarded implementation counts as one path containing all its branches. Combine candidates for regions the program actually uses when their representations, input and output contracts, and required coverage are compatible. Then link, verify, and measure the combined result again.
- **Check eligibility before costing.** Constants and table construction, runtime checks that dominate the call on the relevant path, and ranges derived from those facts can prove preconditions. Declarations state constraints and input distribution hints guide exploration. Eligibility requires verifiable evidence. Keep the general implementation when the facts are insufficient. A guarded specialization must cover the other paths and preserve edge behavior. Include the kernel, conversions, guards, extra stack slots, static expansion count, and repeated data in estimated costs. Count executions by path. Shortlist with estimates, then measure linked Script, stack peaks, compile time, and whole-transaction paths where applicable.
- **Plan and receipt.** Record the call site, semantic operation, evidence, candidates and exclusions, and selected implementation version and digest. Link the existing formula and stack plans, exact Script, and receipt. An Agent can suggest what to compare, and the fixed evaluator decides the verdict. Replay the fixed bindings so builds from the same source can be traced to their different module choices.

The repository already has a project-level P-256 example. R1's split-table construction proves `Z=1` for nonzero fixed-generator entries and handles infinity separately at index zero. Joint-table entries containing the variable point lack the same proof, which excludes that affine substitution. The recorded `split-4-affine-g` comparison saves 448 B in the lock and adds 128 B to the OTDA reconstruction program, so measure the complete target after a local substitution. The project compiler implements this case explicitly and provides evidence for the generic design. [P-256 scan and selection](../projects/p2pkh-r1/forth/msm_compiler.py) · [Recorded construction comparison](../projects/p2pkh-r1/forth/history.md)

For independent acceptance, use a neutral point-addition caller and reuse the standard library's complete projective addition and its affine-right implementation. Freeze the high-level Forth, compiler passes, and fixture. Give one call site proof of a finite right operand with `Z=1` and another call site insufficient evidence or a possible infinity operand. Compile both the general and specialized bindings at the first site, and verify that the second excludes the specialized binding. Also verify rejection when a plan supplies a kernel for the wrong curve or two bindings for the same site. Check each eligible path against an independent group result, including equal points, inverses, infinity, representation conversions, and stack effects. Rerun the complete spend with the same caller and pinned chain-gang, recording exclusions and a replayable binding plan. [Existing standard-library point addition](../src/fourthgraph/stdlib/secp256k1.fth)

## Build and spend boundary

- **Standalone compilation.** `4thgraph SOURCE --entry WORD` emits the Script bytes, stack signature, and build metadata such as source and artifact hashes.
- **Workflow builds.** The build report describes the selected layout, transaction graph, and output Script. Use `--cpn-plan` to export the canonical transaction plan.
- **Wallet project bundles.** A versioned bundle pairs the exact lock template and instruction listing with a WASM module, manifest, and executable fixtures. The manifest records template parameter slots and signing anchors where applicable. The bundle's verification run produces a test receipt.

The wallet module uses actual prevouts and the selected named path through `recognize`, `prepare_spend`, and `assemble_unlock`. The host checks the request and signs when required. Final independent validation uses the completed transaction and its real parents.

The functional profile identifies a supported family. A template version identifies the exact accepted bytes and witness layout. The candidate identifies one proposed spend. Keep approved versions available for earlier outputs and record the applicable digest algorithm, chain context, and `scriptCode` per path.

## Acceptance by independent change

| Area | Evidence at the baseline | What closes the remaining work |
| --- | --- | --- |
| Forth baseline | The language semantics, bilingual syntax, and standard library references are indexed together. | Record the exact compiler revision and capabilities with builds. Change the relevant reference and add behavior tests when the supported source contract changes. |
| Call-site selection | The curve library has general and specialized kernels. The R1 project demonstrates selection from call-site facts. | Call sites in frozen source admit or exclude candidates based on proved facts. Fixed fixtures verify behavior and linked cost, and replay recovers the binding plan with its versions and evidence. |
| PELS compile targets | Main has a BIP143 PELS reference and staged Workflow support for BIP143, OTDA, and dual mode. | Verify an independent standard-library lock from unchanged Forth under single and dual modes and compiler auto-selection. For each path preserve its input/output commitment, signing mode, and witness identity. Extend to dynamic successors and additional eligible output shapes with their own contracts and fixtures. |
| Transaction plans | Workflow supports fused, serial, and atomic layouts within its supported shapes. | Any broader cutting rule must preserve authorization, ordering, state, and atomicity. Test real parent links, intermediate states, and required independent submissions before ranking whole paths. |
| Agent exploration and provenance | The formula compiler already exposes explicit pass sets. Existing workflow reports identify compiled plans. | Expose bounded independent source and compiler experiments with fixed verdicts and request replay. For broader cross-transaction provenance carry semantic node, plan, linked Script and receipt identities through each stage. |
| Wallet and examples | The R1 and PELS examples on main have distinct authorization and successor rules. | Verify exact Script/WASM pairing at the project boundary. Add multimode recognition, preparation, and assembly per approved path before treating a dual-mode build as a wallet package. Run R1 with test keys as an integration example. |

Move an item to complete when its code, build command, and observed acceptance result are linked. Compiler changes can be reviewed with neutral fixtures. Project-specific payment code and WASM releases have their own review and verification.

## Combined acceptance and review status

The baseline dependencies in PRs #86 through #90 are on main. The following reviews have separate acceptance gates. After they merge, rebuild and replay from one commit. Land the experiment runner before retargeting call-site selection to main.

| Acceptance area | Review and evidence |
| --- | --- |
| Forth baseline and build identity | The bilingual baseline and wheel replay receipt record the commit, artifact digest, and capability list. |
| Call-site selection | The same point-addition caller covers constant bindings, the guarded path, and incompatible choices. [#93](https://github.com/linzhm/4thGraph/pull/93) |
| PELS compile targets | A non-counter static lock covers single, dual, and automatic selection. A dynamic state-label fixture replays two spends against their actual parents. [#87](https://github.com/linzhm/4thGraph/pull/87) · [#95](https://github.com/linzhm/4thGraph/pull/95) |
| Transaction plans | A three-stage source compares serial and prefix fusion, verifies parents and authorization, and checks the same terminal state. [#92](https://github.com/linzhm/4thGraph/pull/92) |
| Agent exploration and provenance | Fixed vectors verify source and pass comparisons, complete spends, stack plans, and replay. [#94](https://github.com/linzhm/4thGraph/pull/94) |
| Wallets and examples | The neutral dual-mode bundle replays both paths. The existing R1 bundle exercises host signing. [#91](https://github.com/linzhm/4thGraph/pull/91) · [#89](https://github.com/linzhm/4thGraph/pull/89) |

Run `bash tools/verify_architecture_acceptance.sh workspace/architecture-acceptance` in a clean checkout that contains the reviewed implementations. Use the existing Python, Go, Node.js WASI, and pinned chain-gang environment. The `PYTHON`, `WHEEL_PYTHON`, and `GO` variables select executables. The installed wheel takes precedence over any additional modules supplied in `PYTHONPATH`. The script replays outside the checkout and writes `acceptance.json` with evidence and wheel digests. [Combined replay runner](../tools/verify_architecture_acceptance.sh)

### Baseline reviews

- Typed PELS compile targets, literal-count unrolling, and byte provenance. The standalone settlement fixture verifies both paths of the same lock. [Compiler PR #87](https://github.com/linzhm/4thGraph/pull/87)
- Bounded Agent selection and fixed evaluation with replayable formula reports. The homepage diagram and skill document the same loop. [Tuning PR #88](https://github.com/linzhm/4thGraph/pull/88)
- BIP143 ALL project WASM packages, with R1 and PELS Counter as fixture examples. [Wallet examples PR #89](https://github.com/linzhm/4thGraph/pull/89)
- Exact-byte promotion of the existing dynamic BIP143 successor into the standard library. The state-label fixture uses two linked spends. R1 consumes the same library as an integration example. [Dynamic successor PR #90](https://github.com/linzhm/4thGraph/pull/90)

From the combined review branches, one wheel supplied the formula fixtures, the WASI runtime, and both PELS library entry points. Outside the checkout, the installed package passed all 625 Bézier vectors under both plans and replayed one R1 fixture spend with chain-gang 0.13.2. [Pinned commits, build commands, and replay results](architecture-wheel-replay.md)
