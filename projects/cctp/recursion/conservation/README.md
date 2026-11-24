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
