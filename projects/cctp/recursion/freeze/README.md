# Isolated freeze transition proof

Both circuits consume the same statement. It contains the actual spent outpoint, paired output index, paired SINGLE digest, and normalized prior and successor records. Each record has satoshis, asset ID, integer token amount, compressed owner key, freeze bit, and the SHA-256 of the full serialized lock field with its freeze bit normalized. The circuit checks byte ranges, a positive amount, preserved fields, and complementary freeze bits.

The [prototype BSV lock](../freeze_probe.py) authenticates the actual ForkID ALL preimage with PUSHTX and checks the native freeze-role signature. It checks the two actual outpoints, fixes the token at vin 0, and matches the exact single paired output to `hashOutputs`. It rebuilds the corresponding SINGLE digest for the common statement and passes the two public limbs to the configured proof verifier. The probe contains the test issuer path and supports a dedicated new asset. The [certified v3 Script path](../../docs/issuer-freeze.md) remains the reference for bridge operations.

| Circuit | R1CS constraints | Public limbs | BSB22 commitments |
|---|---:|---:|---:|
| Ordinary Groth16 with bitwise SHA-256 | 240,219 | 2 | 0 |
| Groth16 with gnark's lookup-based SHA-256 | 374,567 | 2 | 1 |

Both circuits solved the same freeze and unfreeze vectors and rejected 13 mutations. The plain profile uses the base Script verifier. The BSB22 profile uses the optional [shared adapter](../../../groth16/docs/bsb22.md). Each has separate test parameters.

The plain profile completed native proving and fresh spends on an independent Bitcoin SV 1.2.3 regtest. The freeze and unfreeze transactions were each 1,354,784 bytes, of which 903,586 bytes were the token input witness and 1,078 bytes were the proof witness. Native proving took 1.90 and 3.07 seconds. These timings exclude reloading test parameters. The node accepted and mined both valid transitions and rejected the existing proof against a re-authorized change to the paired satoshi value. [Plain proof regtest](../../fixtures/freeze-plain-proof-regtest-summary.json)

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
