# One Groth16 proof for two token inputs

This isolated profile evaluates 2→2 conservation. The first spend starts from two independently created test outputs. The next spend consumes those two successors. The tests configure four fixture holder keys and use separate satoshi and token quantities.

| Position | Actual transaction constraint |
|---|---|
| vin 0 | Authenticate the canonical direct parents' exact token locks and verify a single plain Groth16 proof for the final receipt. Also bind the actual transaction and the position of this input through its compact `0x41` preimage. |
| vin 1 | Authenticate the exact verifier lock at vin 0 using the existing shared companion lock. The heavy verifier funding transaction is disclosed here once. |
| vin 2 and vin 3 | Each token lock independently authenticates its holder signature, exact outpoint, own prior state, both successors, the companion and the final receipt. |
| vout 0 and vout 1 | Canonical successor locks with the same asset and normalized policy, with independent recipient fields. |
| vout 2 | Zero-satoshi canonical Groth16 statement receipt. |

The verifier checks both actual prior locking scripts before passing the receipt to the generic proof verifier. This makes each required token input execute the expected holder and statement checks. The input binding authenticates a direct parent by its real txid and selects its actual vout. Each distinct parent is provided once, including when both slots consume separate outputs of one parent. The test origins are disposable BSV UTXOs. The experiment evaluates conservation and actual transaction binding under an issued-token assumption. Production issuance and recursive ancestry follow the separate CCTP continuity path.

The 585-byte statement includes version, authenticated prevout and sequence commitments, the digest of the two ordered successor outputs, locktime and four canonical state records. Each record contains satoshis, asset, quantity, holder, frozen flag and normalized policy hash. Metadata is cleared when hashing the locking policy. Its policy identity therefore stays the same when ownership and quantity change. The plain BLS12-381 circuit requires positive token and satoshi amounts, active flags, a shared asset and policy, and independent conservation of both sums. The sum of token quantities fits uint64. The public input is the statement SHA256d, split into two big-endian uint128 limbs.

The plain profile compiled to 382,157 constraints with zero BSB22 commitments. It shares the bitwise SHA-256 implementation with the plain freeze circuit and the generic statement receipt verifier. It uses its own test parameters. The previous two-input statement verifier and both freeze constraint fingerprints were checked for compatibility.

## Independent node results

Both payments used the same verifier key and locking policy. Bitcoin SV Node 1.2.3 mined the distinct-parent payment at height 527 and the spend of its two successors at height 530. A changed successor amount with current holder signatures and an earlier proof was rejected. The two independent holder witnesses used about 6.86 kB each. The companion carried the verifier funding transaction once.

| Stage | Proof count and bytes | Direct parent bytes | Payment bytes | Dedicated funding bytes | Native proving |
|---|---:|---:|---:|---:|---:|
| Two independent parents | 1 × 1,078 | 3,706 | 482,360 | 454,956 | 2.33 s |
| Two outputs of the previous payment | 1 × 1,078 | 482,360 | 961,015 | 454,956 | 3.57 s |

The token lock was 1,791 bytes. Each payment used a fixed 1,010,000-satoshi test sponsor. Dedicated funding counts both the verifier and the companion transactions. Native proving times exclude reloading test parameters. [BSV Node and proof evidence](../../fixtures/conservation-2x2-regtest-summary.json)

The successor transaction discloses its one direct parent once. That disclosure contains the earlier witnesses serialized in the parent. An offline SHA-256 checkpoint recomputed this parent's actual txid from a 32-byte state, 8-byte processed length, and 3,704-byte suffix. An authenticated parent proof is required before substituting those 3,744 bytes in the covenant. [Parent binding](../../docs/parent-binding.md)

## Repeated transfers with lossless parent records

The `--compressed-parents` profile moves direct-parent binding into the existing companion at vin1. It already reads the actual vin0 funding transaction. The companion extracts that verifier's script field and its own script field from the authenticated `0x41` preimage, then uses those two byte strings to decode the parent records. Script checks each reconstructed transaction's full SHA256d against the actual input outpoint, selects its vout and checks the exact token lock body. Both owners still authorize their own inputs, and the existing conservation circuit verifies the current receipt independently of any earlier proof.

`--transfers 4` runs a payment from separate origins and three subsequent payments that consume both outputs of the previous payment. Run both modes with the same Groth16 parameters, separate output paths and the same node policy. Add `--compressed-parents` only to the second run. The receipts count the two dedicated funding transactions per payment and check each mined outpoint. The compressed fixture bounds each parent record and reconstructed transaction to eight million bytes. Unique historical bytes still grow between transfers.

Both four-payment sequences were mined on separate Bitcoin SV 1.2.3 regtest nodes. The table includes the verifier and companion funding transaction for each payment.

| Transfer | Raw parent total | Lossless parent total | Bytes saved |
|---|---:|---:|---:|
| 1 | 937,317 | 956,279 | −18,962 |
| 2 | 1,415,972 | 977,908 | 438,064 |
| 3 | 1,894,629 | 999,537 | 895,092 |
| 4 | 2,373,286 | 1,021,168 | 1,352,118 |
| Four payments | 6,621,204 | 3,954,892 | 2,666,312 |

The fourth payment alone drops from 1,918,330 to 562,940 bytes. Lossless parent records save 40.3% over four payments and dedicated funding. Each payment still carries one independent conservation proof and requires zero parent-binding proofs. Both sequences used the same fixed regtest sponsor amounts. [Node results and byte accounting](../../fixtures/conservation-repeat-regtest-summary.json)

## Pre-confirmed verifier outpoints

The `--prefunded-verifiers` profile uses the existing raw-parent verifier and the same Groth16 parameters. It confirms the verifier UTXOs before creating the test origins. The companion authenticates the ordered prevouts against its own ForkID ALL preimage and requires the full `txid:vout` at vin0 to match one of those already funded outputs. Each holder input still requires the exact companion at vin1. The verifier at vin0 checks the actual token parents and selects both spent outputs. The proof circuit and verifier locking bytes are identical to the raw-parent baseline.

| Measured bytes | Raw funding in witness | Pre-confirmed outpoint |
|---|---:|---:|
| First payment | 482,360 | 28,156 |
| Second payment | 961,015 | 52,603 |
| First payment with dedicated funding | 937,316 | 483,108 |
| Second payment with dedicated funding | 1,415,971 | 507,555 |
| Both payments with dedicated funding | 2,353,287 | 990,663 |

Bitcoin SV Node 1.2.3 confirmed both spends. The second consumes vout0 and vout1 of the first. Neither payment contains the serialized bytes of any approved verifier funding transaction. The node rejected a fresh proof and holder signatures using the identical verifier lock at an unapproved outpoint. Its per-input check passed vin0, vin2 and vin3 and rejected vin1. The byte totals cover the valid payments and their verifier and companion funding. Setup, disposable origins and funding created for the rejection are recorded separately. [Proofs and node byte accounting](../../fixtures/conservation-prefunded-regtest-summary.json)

Creating the verifier UTXO still costs 454,182 bytes per payment. The second payment still carries the 28,156-byte first payment as authenticated parent material. The fixed list is a test policy. The recursive CCTP path still requires a bounded historical witness and renewable funding authorization.

## Reproduce

From `projects/cctp/recursion`, compile and generate an independent test setup.

```sh
GOMAXPROCS=4 go test -v ./conservation ./freeze ./freeze/cmd
go build -o /tmp/cctp-conservation-prover ./freeze/cmd
/tmp/cctp-conservation-prover -mode setup -profile conservation -dir /tmp/cctp-conservation-params
```

Use an unpeered Bitcoin SV regtest with sufficient script policy, from the repository root.

```sh
PYTHONPATH=.:projects/groth16/reference:projects/cctp/reference:projects/cctp/recursion \
  python projects/cctp/recursion/run_conservation_regtest.py \
  --node-url "$REGTEST_URL" --cookie "$REGTEST_COOKIE" \
  --prover /tmp/cctp-conservation-prover --parameters /tmp/cctp-conservation-params \
  --out /tmp/cctp-conservation-regtest
```

Use `--prefunded-verifiers` and a distinct output directory to reproduce the pre-confirmed outpoint experiment.
