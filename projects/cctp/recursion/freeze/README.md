# Isolated freeze transition proof

Both circuits consume the same statement. It contains the actual spent outpoint, paired output index, paired SINGLE digest, and normalized prior and successor records. Each record has satoshis, asset ID, integer token amount, compressed owner key, freeze bit, and the SHA-256 of the full serialized lock field with its freeze bit normalized. The circuit checks byte ranges, a positive amount, preserved fields, and complementary freeze bits.

The [prototype BSV lock](../freeze_probe.py) authenticates the actual ForkID ALL preimage with PUSHTX and checks the native freeze-role signature. It checks the two actual outpoints, fixes the token at vin 0, and matches the exact single paired output to `hashOutputs`. It rebuilds the corresponding SINGLE digest for the common statement and passes the two public limbs to the configured proof verifier. The probe contains the test issuer path and supports a dedicated new asset. The [certified v3 Script path](../../docs/issuer-freeze.md) remains the reference for bridge operations.

| Circuit | R1CS constraints | Public limbs | BSB22 commitments |
|---|---:|---:|---:|
| Ordinary Groth16 with bitwise SHA-256 | 240,219 | 2 | 0 |
| Groth16 with gnark's lookup-based SHA-256 | 374,567 | 2 | 1 |

Both circuits solved the same freeze and unfreeze vectors and rejected 13 mutations. The plain profile uses the base Script verifier. The BSB22 profile uses the optional [shared adapter](../../../groth16/docs/bsb22.md). Each has separate test parameters.

The plain profile completed native proving and fresh spends on an independent Bitcoin SV 1.2.3 regtest. The freeze and unfreeze transactions were each 1,354,784 bytes, of which 903,586 bytes were the token input witness and 1,078 bytes were the proof witness. Native proving took 1.90 and 3.07 seconds. These timings exclude reloading test parameters. The node accepted and mined both valid transitions and rejected the existing proof against a re-authorized change to the paired satoshi value. [Plain proof regtest](../../fixtures/freeze-plain-proof-regtest-summary.json)

The one-lock BSB22 comparison also completed native proving and both spends on the independent node. The freeze transaction used 2,836,886 bytes and 7.43 seconds of native proving. It used the same statement fields and a separate circuit and verifying key. [BSB22 proof regtest](../../fixtures/freeze-bsb22-proof-regtest-summary.json)

## Separate verifier on the same plain parameters

The token at vin 0 checks its authorized issuer, the exact funding script identity at vin 1, and the matching transaction statement at vout 1. The [generic statement verifier](../../../groth16/reference/statement_receipt.py) derives the proof's public limbs from vout 1, authenticates the current transaction, and verifies Groth16. Both freeze and unfreeze use the identical verifier lock, each spending its own real funding outpoint. Both were mined and the node rejected a re-authorized change to the paired amount with the old proof. [Separate verifier receipt](../../fixtures/freeze-plain-split-verifier-regtest-summary.json)

| Bytes | One lock | Separate verifier |
|---|---:|---:|
| Token lock | 451,089 | 1,339 |
| Verifier lock | Included in token lock | 450,739 |
| Each transition transaction | 1,354,784 | 458,164 |
| Dedicated verifier funding transaction per transition | 0 | 450,803 |
| Each transition with its dedicated verifier funding | 1,354,784 | 908,967 |
| Setup, origin, verifier funding, freeze and unfreeze | 3,160,909 | 1,819,523 |

The split used about 33% fewer bytes per operation with dedicated verifier funding included. The full fixture used about 42% fewer bytes. Each operation used the same test fee sponsor value of 1,000,000 satoshis. The separate token and verifier preimages were 1,498 and 192 bytes respectively. The token witness still disclosed its 450,803-byte verifier funding transaction, which dominated the 453,879-byte token witness. The measurements use one token per transition. Wider reuse needs a statement that binds all selected inputs and outputs.

Run the circuit and CLI checks from `projects/cctp/recursion`.

```sh
GOMAXPROCS=4 go test -v ./freeze/...
go build -o /tmp/cctp-freeze-prover ./freeze/cmd
/tmp/cctp-freeze-prover -mode setup -profile plain -dir /tmp/cctp-freeze-plain-params
```

Run the native proof and independent node probe from the repository root. Use an unpeered regtest with sufficient script policy for the generated lock. For a BSB22 run, use separate parameters with `-profile bsb22` and a fresh report directory.

```sh
PYTHONPATH=.:projects/groth16/reference:projects/cctp/reference:projects/cctp/recursion \
  python projects/cctp/recursion/run_freeze_probe_regtest.py \
  --node-url "$REGTEST_URL" --cookie "$REGTEST_COOKIE" \
  --prover /tmp/cctp-freeze-prover --parameters /tmp/cctp-freeze-plain-params \
  --out /tmp/cctp-freeze-plain-regtest
```

Use `projects/cctp/recursion/run_freeze_split_regtest.py` with the same flags and parameters and a distinct report directory to reproduce the separate layout.
