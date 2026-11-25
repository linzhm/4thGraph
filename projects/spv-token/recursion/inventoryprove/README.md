# Four-leaf private inventory payment

The plain BLS12-381 Groth16 circuit proves two ordered membership paths in one fixed four-leaf inventory, distinct wire outpoints, active token states and two conserving successor states. The circuit uses the same independent token and satoshi conservation checks as the existing transfer gadget. The two public scalars are the big-endian 128-bit halves of the payment digest. The BSV shared verifier authenticates the payer’s actual vin and outputs and the policy-specific inventory anchor separately. The origin proof relation is in [inventoryorigin](../inventoryorigin).

For SHA256d `H`, the leaf is `H(00 || scope32 || outpoint36 || state50)`. An internal node is `H(01 || left32 || right32)`. The payment statement is `02 || scope32 || root32 || vin2_outpoint36 || vin3_outpoint36 || vout0_state50 || vout1_state50`, with tag bytes hexadecimal and outpoints in wire order. Each state contains quantity LE64, satoshis LE64, the compressed owner key and the one-byte frozen flag. Each private opening contains its state, an 8-bit index in [0,3] and two sibling hashes starting at the leaf.

The [measured vectors](testdata/v3-inventory-payment-cost.json) use four real v3 output records subsequently spent by the archived 64-input payment. Each outpoint and its confirming block is recorded. The test-only scope binds the original asset identifier and continuity key. Both alternative selection proofs have been natively generated and verified and independently evaluated with chain-gang, including rejection of the other selection's payment digest. The wallet supplies a previously authenticated inventory root. The sample measures the payment proof component on historical inputs. Fresh outputs, spending authorizations and new block inclusion are exercised by the separate [node driver](../run_inventory_regtest.py).

Run from the CCTP recursion module with a fresh directory for test-only parameters.

```sh
go test ./inventoryprove
go build -o /tmp/cctp-inventory ./freeze/cmd
/tmp/cctp-inventory -mode setup -profile inventory-payment -dir "$INVENTORY_PARAMS"
/tmp/cctp-inventory -mode session -profile inventory-payment -dir "$INVENTORY_PARAMS"
```

After the JSON `ready` reply, send one JSON line per payment with `id`, `statement` (hex), `openings` (hex), and `out` (fresh local artifact path). The two hexadecimal inputs are recorded for each measured vector. A setup generates a fresh local key, so subsequent proofs use the new setup fingerprint. The endpoint native-verifies each proof before writing its artifact. Timings in the vectors separate setup, full command wall time, resident request wall time, proving time and native verification. Peak RSS uses macOS `time -l` maximum resident size in bytes.
