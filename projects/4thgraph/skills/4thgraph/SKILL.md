---
name: 4thgraph
description: Write, compile, optimize, and verify 4thGraph Forth for BSV Script and multi-transaction UTXO workflows. Use for 4thGraph source, stack effects, fused or split builds, transaction-version targets, and compiler decision or replay reports.
---

# 4thGraph

Use 4thGraph to turn a Forth word into a Script fragment or a workflow into locking scripts and a symbolic transaction plan. Return the actual build outputs and explain the constraints that affected their compilation.

## Before you write Forth

- Confirm the required outputs and failure conditions, integer widths and overflow behavior, signing roles, and which inputs and signers can be available together. Identify any step one party must be able to submit independently.
- Read the project's pinned compiler version and capabilities first. Run `4thgraph --version`, `4thgraph --capabilities`, and the installed `--help` as needed. From the BSV Script Lab root, the equivalent compiler entry point is `PYTHONPATH=. python3 projects/4thgraph/protocol.py`. For setup, see `projects/4thgraph/INSTALL.md` in the [BSV Script Lab checkout](https://github.com/linzhm/bsv-script-lab).
- Choose the optimization objective and boundary cases before changing the source. Keep a baseline build for comparison, and record which conditions and rejection behavior every candidate must preserve.
- Use the supported subset of Forth 2012. Place `bsv-effect: name inputs -- outputs ;` before each `: name ... ;` definition. Read stack signatures from bottom to top, with the top item on the right. Define callees before callers. `( ... )` is a comment. Both arms of `IF ... ELSE ... THEN` must leave the same ordered stack types.
- Numeric literals are `cell`. Standard `+` uses 64-bit signed cell representation and wraps modulo 2⁶⁴ in 4thGraph. `u32+` wraps modulo 2³². Convert explicitly with `cell>u32` or `u32>cell`. Standard Forth comparisons return `-1` or `0`. Preserve the full flag when it is returned to a caller.
- Check optional words against `--capabilities` before using `bsv-use`. Put UTXO lookup, external signing, and transaction submission in the host workflow. Write Script-bound definitions with supported words and static stack effects.

```forth
bsv-effect: inc-u32 u32 -- u32 ;
: inc-u32 1 cell>u32 u32+ ;
```

## Declare transaction constraints

- For the supported two-branch workflow, use `work: step input word role` with `u32 -- u32`, and `join: step left right word` with `u32 u32 -- route`. Check the left/right order and the requested terminal route. Declare the split signer with `split-authority:`. When a gate is needed, use `gate: step input word role` with `u32 -- cell`, where nonzero allows the workflow to continue.
- Use `independent-submit step` for a required transaction boundary. The availability flags describe which inputs and roles can participate together in this build. A repeated external input name declares the same value across uses and may require that value at an earlier step in a split plan. Check the emitted template's requirements and where data becomes public.
- Select `--mode fused`, `split`, or `auto` for transaction scheduling. Set `--target` separately for allowed transaction versions. For full-plan builds, supply the required roles' public keys and a 32-byte hexadecimal task ID. Leave signing to the external signer. Verify that the plan binds real parent outpoints and expected successor outputs when it is instantiated.

## Compile and optimize

1. Compile a single word with `4thgraph source.fth --entry word` to inspect its stack signature and Script. Use workflow compilation with `--explain` for transaction templates and selection reasons.
2. Keep source intent clear and use typed operations. Compare `--optimize baseline`, `safe`, and `stack` if available. `safe` uses range analysis and branch lowering. `stack` also uses last-use scheduling and shares computations when that is safe. Let the compiler report which rules fired before adding manual stack shuffles or changing arithmetic.
3. Hold the source, target, key roles, and test data fixed when comparing optimizations. Use the actual rewrite records and compare emitted bytes, whole-path bytes, peak stack payload, and measured validation cost when evidence is available. When using `--search`, describe the selected objective and its estimated metrics. `peak-validation` ranks static proxies such as signature checks and input script bytes.
4. Check results and rejection behavior on the relevant boundaries, including wraparound, both terminal routes, and any independent-submit constraint. For transaction changes, include the applicable negative cases for wrong parent outpoints or a wrong successor output. Use the checkout's regtest workflow for BSV Node and pinned chain-gang evidence.

## Deliver the result

Provide the source and the compiler's JSON or Script fragment, together with the chosen mode, target, and optimization. For a workflow, include the build digest and the reason for transaction boundaries. Use `4thgraph-report replay.json --output-dir decision` to check saved evidence against build digests and report which paths were replayed. From the checkout root, use `PYTHONPATH=. python3 projects/4thgraph/decision_report.py` with the same arguments. An offline compile establishes the build result and static eligibility. Label actual replay coverage separately.
