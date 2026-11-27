# 4thGraph architecture and acceptance

[简体中文](architecture.zh-CN.md) · [Forth baseline](language/README.md)

4thGraph compiles a high-level Forth program into BSV Script and, for supported workflows, a transaction plan. A program states how values arise, who authorizes a spend, which state and outputs must be committed, and where atomicity or independent submission matters. The compile target supplies the applicable transaction versions, chain rules, required signing coverage, and cost policy.

| Layer | Responsibility |
| --- | --- |
| Forth and standard library | The [Forth baseline](language/README.md) defines source semantics, syntax, and public words. PELS is a family of transaction commitment templates. R1 is an owner-authorization example that binds a public-key hash and verifies a signature for the current spend. |
| Compiler and planner | Verify the source contract, compare eligible transaction boundaries, choose compatible Script fragments, and link each lock. Keep exact Script bytes, parameter layout, signature anchors, and any symbolic transaction plan. |
| Assembler and wallet | Bind the plan to actual parent outputs, prepare the selected path's signing material, obtain host authorization when required, and assemble its witness. Consume the exact Script and manifest selected at compile time. The wallet may use a paired project WASM module. |
| Independent evaluation | Evaluate pure formula fixtures on fixed vectors. Verify complete spends against their actual parents with pinned chain-gang. Record BSV Node cross-checks when requested. Treat estimates, offline verification, admission, and confirmation as distinct measurements. |

## Development and tuning

Start with the highest-level Forth and freeze its semantics, target, dependencies, and acceptance fixtures. List reproducible candidate paths side by side. Vary Forth implementations with the compiler plan fixed, compare compiler plans and bounded pass orders with the source fixed, and check eligible transaction or witness layouts under the same coverage contract. An Agent selects a bounded batch. Fixed evaluators decide validity and report Script size, stack peaks, timing, and whole-path bytes where measured. Use the report to choose the next batch or replay a selected build without a model.

The typed AST and dependency graph record how a result arises. Record a separate hash for the source snapshot, normalized constraints, build plan, exact linked Script, and emitted fragments. A byte hash identifies an artifact. Its source and build records explain which changes produced it and permit replay. Keep multiple plans traceable even when they emit identical bytes.

## Build and spend boundary

Every lock build exposes exact Script bytes, a listing, parameter layout, signing anchors, and the selected plan. For wallet use the same project build pairs the Script with WASM, a manifest, executable fixtures, and the test receipt. The module consumes actual prevouts and the selected named path through `recognize`, `prepare_spend`, and `assemble_unlock`. The host checks the request and signs when required. Final independent validation uses the completed transaction and its real parents.

The functional profile identifies a supported family. A template version identifies the exact accepted bytes and witness layout. The candidate identifies one proposed spend. Keep approved versions available for earlier outputs and record the applicable digest algorithm, chain context, and `scriptCode` per path.

## Acceptance by independent change

| Area | Evidence at the baseline | What closes the remaining work |
| --- | --- | --- |
| Forth baseline | The language semantics, bilingual syntax, and standard library references are indexed together. | Record the exact compiler revision and capabilities with builds. Change the relevant reference and add behavior tests when the supported source contract changes. |
| PELS compile targets | Main has a BIP143 PELS reference and staged Workflow support for BIP143, OTDA, and dual mode. | Verify an independent standard-library lock from unchanged Forth under single and dual modes and compiler auto-selection. For each path preserve its input/output commitment, signing mode, and witness identity. Extend to dynamic successors and additional eligible output shapes with their own contracts and fixtures. |
| Transaction plans | Workflow supports fused, serial, and atomic layouts within its supported shapes. | Any broader cutting rule must preserve authorization, ordering, state, and atomicity. Test real parent links, intermediate states, and required independent submissions before ranking whole paths. |
| Agent exploration and provenance | The formula compiler already exposes explicit pass sets. Existing workflow reports identify compiled plans. | Expose bounded independent source and compiler experiments with fixed verdicts and request replay. For broader cross-transaction provenance carry semantic node, plan, linked Script and receipt identities through each stage. |
| Wallet and examples | The R1 and PELS examples on main have distinct authorization and successor rules. | Verify exact Script/WASM pairing at the project boundary. Add multimode recognition, preparation, and assembly per approved path before treating a dual-mode build as a wallet package. Run R1 with test keys as an integration example. |

Move an item to complete when its code, build command, and observed acceptance result are linked. Compiler changes can be reviewed with neutral fixtures. Project-specific payment code and WASM releases have their own review and verification.

## Changes under review

- Typed PELS compile targets, literal-count unrolling, and byte provenance. The standalone settlement fixture verifies both paths of the same lock. [Compiler PR #87](https://github.com/linzhm/4thGraph/pull/87)
- Bounded Agent selection and fixed evaluation with replayable formula reports. The homepage diagram and skill document the same loop. [Tuning PR #88](https://github.com/linzhm/4thGraph/pull/88)
- BIP143 ALL project WASM packages, with R1 and PELS Counter as fixture examples. [Wallet examples PR #89](https://github.com/linzhm/4thGraph/pull/89)
- Exact-byte promotion of the existing dynamic BIP143 successor into the standard library. The state-label fixture uses two linked spends. R1 consumes the same library as an integration example. [Dynamic successor PR #90](https://github.com/linzhm/4thGraph/pull/90)

The combined install check built one clean wheel from the review branches. It contained the formula fixtures, the WASI runtime, and both PELS library entry points. Outside the checkout, the installed formula runner replayed the Bézier baseline and stack plan on the same 625 vectors. The same installation replayed the packaged R1 receipt with pinned chain-gang 0.13.2.
