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

## Acceptance by independent change

| Area | Evidence at the baseline | What closes the remaining work |
| --- | --- | --- |
| Forth baseline | The language semantics, bilingual syntax, and standard library references are indexed together. | Record the exact compiler revision and capabilities with builds. Change the relevant reference and add behavior tests when the supported source contract changes. |
| PELS compile targets | Main has a BIP143 PELS reference and staged Workflow support for BIP143, OTDA, and dual mode. | Verify an independent standard-library lock from unchanged Forth under single and dual modes and compiler auto-selection. For each path preserve its input/output commitment, signing mode, and witness identity. Extend to dynamic successors and additional eligible output shapes with their own contracts and fixtures. |
| Transaction plans | Workflow supports fused, serial, and atomic layouts within its supported shapes. | Any broader cutting rule must preserve authorization, ordering, state, and atomicity. Test real parent links, intermediate states, and required independent submissions before ranking whole paths. |
| Agent exploration and provenance | The formula compiler already exposes explicit pass sets. Existing workflow reports identify compiled plans. | Expose bounded independent source and compiler experiments with fixed verdicts and request replay. For broader cross-transaction provenance carry semantic node, plan, linked Script and receipt identities through each stage. |
| Wallet and examples | The R1 and PELS examples on main have distinct authorization and successor rules. | Verify exact Script/WASM pairing at the project boundary. Add multimode recognition, preparation, and assembly per approved path before treating a dual-mode build as a wallet package. Run R1 with test keys as an integration example. |

Move an item to complete when its code, build command, and observed acceptance result are linked. Compiler changes can be reviewed with neutral fixtures. Project-specific payment code and WASM releases have their own review and verification.
