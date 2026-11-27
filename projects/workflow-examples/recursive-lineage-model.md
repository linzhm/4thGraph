# Recursive lineage: a logical CPN draft

This [model](recursive-lineage-model.json) describes an issuance followed by a
repeatable transfer. `state` denotes the state committed by a continuation UTXO;
`proof` denotes an off-chain proof artifact supplied again when needed. A CPN
token is a modeling construct: it does not mean that a Bitcoin Script stack or
a proof result persists across transactions. The issue and transfer evidence,
base case, state commitment, previous proof verification and actual transaction
binding are **requirements**, not compiled or verified implementations.

The intended recursive relation must authenticate the configured issuance in
its base case; each step must verify the previous proof, tie its public state
and origin to the consumed state, enforce the application transition and tie
the next public state and unchanged origin to the successor. An on-chain lock
must additionally bind the claim to the actual spent outpoint and ordered
outputs. This draft does not specify a proof system, verifying key, encoding,
transaction layout, or a privacy construction; all are needed before those
properties can be claimed. `require-zk` requests a privacy property but does
not itself provide one. Script assertions may complement a ZK proof; a direct
Script that exposes private assignments cannot satisfy that requirement.

The logical count analyzer can examine the structural loop; it cannot prove
that this loop is safe or usable. The current linear CPN lowering does not
support this branching/cyclic model or recursive evidence and must reject it.
Inspect declared state, constraints, evidence, recursion ports and the base-case
reference with the command below. This does not verify the recursion, a
transaction, or chain state.

```bash
4thgraph cpn inspect-evidence projects/workflow-examples/recursive-lineage-model.json
```

[中文说明](recursive-lineage-model.zh-CN.md)
