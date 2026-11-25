# P2PKH-R1-Deferred v0.2.0

[简体中文](README.zh-CN.md) · [BSV Script Lab](../../README.md)

Deferred moves the creation of a full R1 locking script from funding to activation. A [1,435-byte funding lock](template/v0.2.0/template.hex) commits to a [46,302-byte P2PKH-R1 v0.2.0 target](../p2pkh-r1/template/v0.2.0/template.hex) at the same value. Existing short locks keep the target version they originally committed to.

## Developer resources

[Protocol specification](docs/developer.en.md#protocol) · [Security analysis](docs/developer.en.md#security) · [Validation and measurements](docs/developer.en.md#validation) · [SDK and reference interfaces](docs/developer.en.md#sdk)

## Activation and later payment

1. Create the funding output with `funding_output` or `funding_output_from_owner_hash`. On receipt, verify the short lock, value and both target commitments. The Python `recognize` result includes `target_r1_version`. With the source SDKs, match the output using the corresponding R1 template bytes.
2. Arrange the activation input and its same-index R1 output. Call `activate_input` and have the sponsor sign its own input if needed. The direct ForkID SINGLE unlock is 160 bytes. The two-check path carries a second digest commitment and takes 197 bytes. All twelve activation sighash combinations require the same-index output.
3. Once activated, spend the full R1 output with the regular R1 wallet and signer. Chronicle OTDA reconstruction is available for supported later payments.

The activation witness already carries the target commitment through ForkID SINGLE. In two-check modes, the selected mode contributes an extra digest. The full R1 target occupies the new transaction output.

## Reproduce and integrate

See the [protocol specification](docs/spec.en.md), [SDK guide](docs/sdk.en.md), [layout](template/v0.2.0/layout.json), [activation vector](template/v0.2.0/activation-single.json), [twelve-mode vectors](template/v0.2.0/sighash-modes.json), and [acceptance matrix](reference/acceptance.md).

```sh
python -m pip install -r projects/p2pkh-r1-deferred/reference/requirements.txt
PYTHONPATH=. python projects/p2pkh-r1-deferred/reference/generate_vectors.py
bash projects/p2pkh-r1-deferred/reference/verify.sh
```

## Measured transaction costs

These samples spend two short locks and one fee sponsor into two R1 v0.2.0 outputs. An added activation pair adds an input and its same-index target. The output-only comparison uses a larger sponsor input. Each row measures the serialized transaction in bytes.

| Activation mode | 3 inputs, 2 outputs | Added activation pair | Added output | Funding, activation and exit | With one turnover |
| --- | ---: | ---: | ---: | ---: | ---: |
| ForkID ALL | 93,259 | 46,552 | 46,313 | 97,125 | 190,498 |
| OTDA ALL | 93,260 | 46,551 | 46,312 | 97,139 | 198,389 |

The two activation unlocks are 197 bytes each. The sponsor's native signature encoding accounts for the one-byte variation. For the first activation input, the development evaluator measures peaks of 7 main-stack items, 34 altstack items and 359 bytes of combined payload. [Benchmark method](../../shared/benchmark.md)
