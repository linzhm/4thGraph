# P2PKH-R1-Deferred v0.2.0

[简体中文](README.zh-CN.md) · [4thGraph](../../README.md) · [Project index](../README.md)

## Developer resources

**[Wallet SDK quickstart](docs/sdk.en.md#quickstart)** · [Unified wallet SDK](../../sdk/README.md#quickstart)

Create a short deposit lock, arrange its committed R1 target at the same index, and call `activate`. Spend the resulting R1 output through the ordinary R1 integration.

[Protocol](docs/spec.en.md) · [Security](docs/developer.en.md#security) · [Verify](#reproduce-and-integrate) · [Transaction costs](#measured-transaction-costs)

Deferred moves the creation of a full R1 locking script from funding to activation. A [1,435-byte funding lock](template/v0.2.0/template.hex) commits to a [46,302-byte P2PKH-R1 v0.2.0 target](../p2pkh-r1/template/v0.2.0/template.hex) at the same value. Existing short locks keep the target version they originally committed to.

## 4thGraph Forth comparison

The typed Forth lock implements the full activation check, including the BIP143 SINGLE output commitment, the optional selected BIP143 or OTDA digest, fixed-key signature construction, and both native signature checks. The `baseline`, `safe`, and `stack` builds use the same source with 4thGraph 0.2.7 from checkout `3133da7`. [Forth source](reference/deferred-activation.fth) · [Compiler report](reference/forth-results.json)

| Build | Funding lock | Funding transaction | Funding + BIP143 ALL activation | First activation input main / alt peak |
| --- | ---: | ---: | ---: | ---: |
| Published v0.2.0 assembly | 1,435 B | 2,953 B | 96,116 B | 7 / 34 |
| Forth `baseline` | 1,185 B | 2,453 B | 95,616 B | 10 / 1 |
| Forth `safe` | 1,087 B | 2,257 B | 95,420 B | 10 / 1 |
| Forth `stack` | **1,085 B** | **2,253 B** | **95,416 B** | 10 / 1 |

The fixture funds two Deferred outputs and a sponsor, then activates both outputs into the same 46,302-byte R1 locks. The `stack` build saves 350 bytes per short lock and 700 bytes across funding and activation. The standalone activation measures 93,089 bytes with direct BIP143 SINGLE or 93,163 bytes with BIP143 ALL or OTDA ALL for every build. Stack peaks come from the development evaluator. Peak combined payload on the BIP143 ALL path is 359 bytes for assembly and 360 bytes for Forth. [Fixture and results](reference/forth-results.json)

`safe` removes two 64-bit wrap sequences from DER length subtraction using nonnegative byte-length bounds. `stack` saves one more byte at each of those call sites. The Forth source reverses 32-byte values by splitting them into halves, which accounts for much of the size difference between assembly and the Forth baseline. BSV Node and pinned chain-gang matched the expected verdicts in the activation acceptance matrix. [Acceptance coverage](reference/acceptance.md)

Use `generate_lock.py --optimize stack` or pass `optimization="stack"` to the Python funding helpers to create a Forth lock. Omit the option to issue the released lock. Both use the usual recognition and activation path.

Run the comparison from the repository root to regenerate the report and all four fixture locks.

```sh
PYTHONPATH=src:. python projects/p2pkh-r1-deferred/reference/compare_forth.py \
  --output-dir projects/p2pkh-r1-deferred/workspace/forth
```

## Use cases and trade-offs

Evaluate Deferred for a deposit queue where customers receive many small locking scripts and the operator can schedule activation before withdrawals. Each short lock commits to the target R1 owner, template and full value. Any party with the data and a funded transaction can assemble that transition. Spending the resulting R1 output still requires the owner's signature.

Budget for an extra transaction and a fee sponsor. Several deposits can activate together if every activation input has its committed R1 output at the same index. Until activation confirms, the wallet tracks the short-lock UTXO. If the sponsor is unavailable, it remains in that state. Compare the complete deposit-to-exit workflow with ordinary R1 when users need to spend immediately or when fees are the main cost. [Activation costs](#measured-transaction-costs)

## Activation and later payment

1. Create the funding output with `funding_output` or `funding_output_from_owner_hash`. On receipt, verify the short lock, value and both target commitments. The Python `recognize` result includes `target_r1_version`. The unified client reports this version as `targetTemplate`.
2. Arrange the activation input and its same-index R1 output. Call `activate_input` and have the sponsor sign its own input if needed. The direct BIP143 SINGLE unlock is 160 bytes. The two-check path carries a second digest commitment and takes 197 bytes. All twelve activation sighash combinations require the same-index output.
3. Once activated, spend the full R1 output with the regular R1 wallet and signer. Chronicle OTDA reconstruction is available for supported later payments.

The activation witness already carries the target commitment through BIP143 SINGLE. In two-check modes, the selected mode contributes an extra digest. The full R1 target occupies the new transaction output.

## Reproduce and integrate

See the [protocol specification](docs/spec.en.md), [SDK guide](docs/sdk.en.md), [layout](template/v0.2.0/layout.json), [activation vector](template/v0.2.0/activation-single.json), [twelve-mode vectors](template/v0.2.0/sighash-modes.json), and [acceptance matrix](reference/acceptance.md).

```sh
python -m pip install -r projects/p2pkh-r1-deferred/reference/requirements.txt
PYTHONPATH=src:. python projects/p2pkh-r1-deferred/reference/generate_vectors.py
bash projects/p2pkh-r1-deferred/reference/verify.sh
```

## Measured transaction costs

These samples spend two short locks and one fee sponsor into two R1 v0.2.0 outputs. An added activation pair adds an input and its same-index target. The output-only comparison uses a larger sponsor input. Each row measures the serialized transaction in bytes.

| Activation mode | 3 inputs, 2 outputs | Added activation pair | Added output | Funding, activation and exit | With one turnover |
| --- | ---: | ---: | ---: | ---: | ---: |
| BIP143 ALL | 93,259 | 46,552 | 46,313 | 97,125 | 190,498 |
| OTDA ALL | 93,260 | 46,551 | 46,312 | 97,139 | 198,389 |

The two activation unlocks are 197 bytes each. The sponsor's native signature encoding accounts for the one-byte variation. For the first activation input, the development evaluator measures peaks of 7 main-stack items, 34 altstack items and 359 bytes of combined payload. [Benchmark method](../../docs/benchmark.md)
