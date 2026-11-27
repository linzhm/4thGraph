# Project WASM packages and spend fixtures

[简体中文](project-contracts.zh-CN.md)

A project package pairs exact Script bytes, parameter slots, signing anchors, a fixture set, and a project WASM module. The manifest identifies the build and spending paths. The host opens the package approved by its digest and checks the actual parent output before requesting authorization. R1 ordinary payment and PELS Counter are the two fixture projects.

```sh
export PYTHONPATH=src:.
python3 tools/build_project_contract.py p2pkh-r1 workspace/r1-package --verify
python3 tools/build_project_contract.py pels-counter workspace/counter-package --verify
```

Verification uses pinned chain-gang and the repository's offline fixture keys. `--smoke` uses fresh R1 keys in memory. `--with-bsv-node` also checks a configured local regtest node. The host requires Node.js for the WASI preview1 runtime. A public replay can verify the receipt with the approved manifest hash and the actual transactions recorded in the receipt.

The generic ABI exposes `recognize`, `prepare_spend`, and `assemble_unlock`. The package versions in this change use BIP143 ALL. Each fixture documents its own output constraints and witness. [Detailed commands and failure behaviors](project-contracts.zh-CN.md) · [Host implementation](../src/fourthgraph/workflow/project_contract.py)
