# Transaction-bound shared verifier

The first milestone combines dynamic public inputs and one verifier execution per transfer. Keep the arithmetic profiles available for comparison until the full transaction layout and performance baseline are measured.

## Public statement

The host reference selects the actual verifier input by index and authenticates the supplied funding transaction against its outpoint. It matches the spent script against the expected verifier and takes the spent satoshi value from that output. The initial format uses ForkID ALL (0x41) without ANYONECANPAY and uses the full verifier lock as scriptCode.

Compute the double-SHA256 of the byte sequence containing the versioned domain, the 36-byte issuance outpoint and the double-SHA256 ForkID preimage. Read the resulting hash as two unsigned big-endian 128-bit scalars in byte order. Inputs, sequences, output bytes, verifier outpoint, value, version and locktime are covered. Proof bytes in scriptSig remain outside the signed preimage, so constructing the proof introduces no txid self-reference. The covenant must authenticate the preimage against actual transaction execution before the verifier uses these scalars.

The circuit must interpret the same canonical bytes. Its relation must check the exact output indices, asset amounts, owner commitments and continuations. A commitment to output bytes establishes their identity. Amount conservation and issuance provenance require explicit circuit constraints.

## One verification per transfer

Each transfer consumes its own verifier instance. Every token input must bind to the actual verifier outpoint referenced by the same transaction and to its expected verifier template. The verifier must account for every token input counted and every token output recognized by the wallet. A receiving wallet checks that the demonstrated verifier spend covers the exact output it accepts. Place the verifier instance in an independent funding output so unrelated transfers can use disjoint inputs.

## Script prototype

The statement fragment authenticates ForkID ALL with the existing fixed-r PUSHTX construction and derives both public scalars. The input guard independently authenticates the token input's preimage, checks the supplied serialized prevouts against hashPrevouts, and binds input zero to output zero of the supplied verifier funding transaction. It authenticates the funding transaction by txid and checks that its output uses the exact expected verifier script.

The first layout places the verifier at input zero and uses a funding transaction with one input, one output and a one-byte CompactSize input script length. Chain-gang validates a complete transaction with two token inputs referencing one verifier input. The test harness compares the two scalars against the host reference and rejects a substituted verifier output, changed change amount and incorrect sighash type.

The harness checks public statement derivation and script linkage. The transfer circuit, dynamic public-input multiplication, owner authorization and successor covenant must be connected before wallet acceptance tests. The initial Script fragments use the full scriptCode and no code separator.

## Dynamic Groth16 integration

The verifier derives both limbs in Script, checks the affine VK combination with a fixed-base binary MSM using complete exceptional-case handling, and feeds the checked point into the additional gamma Miller term. An infinity combination contributes the pairing identity. The legacy three profiles continue to use their fixed-statement pairing preparation.

Chain-gang accepted a single real Groth16 proof for a transaction with two guarded inputs and rejected a rebuilt witness for a changed amount with the original proof. The test circuit is an arithmetic fixture. It leaves owner authorization, token conservation, provenance and successor-state constraints to the transfer circuit and covenant.

The three-input fixture produced a 450,596-byte verifier lock and a 2,256,447-byte spending transaction. Its two guarded inputs each include the full verifier parent and a preimage containing the guard script. This measurement includes those copies and establishes where the layout spends bytes before arithmetic tuning.

## Owned and variable-width token transfers

The owned output carries the issuance outpoint, a positive 64-bit token quantity and a compressed secp256k1 owner key. Its lock authenticates the expected shared verifier, then checks the owner's ForkID ALL signature. The Groth16 verifier remains reusable with any matching two-limb circuit key.

| Token inputs → outputs | Transaction inputs including verifier | Spending bytes |
|---|---:|---:|
| 2 → 1 | 3 | 2,708,309 |
| 1 → 2 | 2 | 2,257,226 |
| 2 → 2 | 3 | 3,159,750 |
| 4 → 4 | 5 | 5,867,894 |

Chain-gang accepted all four transactions with one proof and independent owner signatures, and rejected each shape with the wrong owner or an old proof after an output change. The amounts in this table denote fixture sizes. Output scripts and input witnesses still duplicate large scripts.

The host transfer relation authenticates parent outpoints, checks canonical output templates and enforces per-issuance quantity conservation. It consumes an authenticated set of genuine token outpoints and rejects a byte-for-byte copy created under a different outpoint. The current chain test uses the arithmetic fixture. The on-chain transfer circuit still needs to check the relation and prove provenance from issuance or preceding authenticated transitions.

With chain-gang installed, run the owner and shape tests from the repository root with the test-only signing dependency used by the other reference projects.

```sh
python3 -m pip install ecdsa==0.19.1
PYTHONPATH=.:projects/groth16/reference python3 -m unittest -v test_token
```

## Hash commitment for the verifier lock

The owned token guard now authenticates the verifier funding transaction by txid and compares the SHA-256 of its exact serialized output script field against a 32-byte commitment. The committed field includes the CompactSize prefix and the complete verifier script. Each owned token lock in the fixture falls from 451,428 bytes to 856 bytes.

| Token inputs → outputs | Inline verifier guard | Hash commitment guard |
|---|---:|---:|
| 2 → 1 | 2,708,309 B | 1,356,583 B |
| 1 → 2 | 2,257,226 B | 905,502 B |
| 2 → 2 | 3,159,750 B | 1,357,451 B |
| 4 → 4 | 5,867,894 B | 2,263,293 B |

The 4 → 4 witness still includes four copies of the verifier parent, one for each independently checked token input. The verifier's own ForkID preimage also includes its full 450,596-byte scriptCode. The next experiments should measure these costs separately. A compact scriptCode using an executed code separator needs a new statement and validation of the signature check position. Reducing repeated parent bytes needs a different authenticated prevout witness or transaction layout. Each token input must still verify that its payment consumes the expected verifier.

## Off-chain proof of the transfer rules

The same two-limb verifier can check a circuit specialized for token transfers. The prover supplies the canonical preimage, serialized prevouts and outputs, required funding transactions, and authenticated prior token state as private witnesses. The circuit recomputes the public digest, ties each counted token input and output to its transaction position, and checks issuance, quantity conservation and successor templates. Wallet and covenant checks still bind each token spend to the actual verifier input. The transfer proof can also carry the previous transition's provenance recursively if the chosen circuit implements a sound recursive proof relation.

A proof that authenticates a funding transaction inside the transfer circuit can remove redundant parent bytes from the shared verifier's interface. Removing those bytes from every token input also requires a compact Script check that the same payment actually executes the expected verifier. Compare layouts on this condition before treating proof size as the spending size.


## Larger transfer layouts

Chain-gang accepted complete `16 → 32`, `32 → 32`, and `32 → 1` transfers with independent owner signatures and one dynamic Groth16 verifier input. They used the existing arithmetic test proof and occupied 7,718,289, 14,975,367 and 14,948,493 bytes respectively. The 64-input and 64-output capacity has been tested as a Circom arithmetic witness. See the [configurable MIMO fragment](toolchain.md#configurable-mimo-fragment).

## Shared guard at input one

The compact layout keeps the actual Groth16 verifier at vin[0]. The short shared guard at vin[1] authenticates the full verifier parent against the transaction's signed prevout list and checks the expected verifier script commitment. Each subsequent token input authenticates the short guard parent at vin[1] and checks its owner's signature. Honest full-node validation then enforces both links in the same transaction. The existing direct layout remains available, with its original token lock bytes.

| Token inputs → outputs | Direct guard | Shared guard |
|---|---:|---:|
| 1 → 2 | 905,502 B | 907,356 B |
| 4 → 4 | 2,263,293 B | 915,710 B |
| 16 → 32 | 7,718,289 B | 973,042 B |
| 32 → 32 | 14,975,367 B | 1,033,109 B |

The shared guard uses one extra funding input. Its measured funding transaction is 774 bytes and the full verifier funding witness appears only at vin[1]. At 32 inputs the two fixed witnesses are approximately 452 KB each and the first token witness is 3,099 bytes. Each token witness still carries the authenticated prevout list, which grows with input count. Tests rebuild the signatures after substituting either funding output and reject both changed transactions. Independent payments may use different short guard and full verifier UTXOs.

### Larger shared-guard measurements

| Token inputs → outputs | Spending bytes | Two shared input witnesses | First token input witness |
|---|---:|---:|---:|
| 32 → 32 | 1,033,105 | 904,604 | 3,099 |
| 64 → 64 | 1,236,385 | 905,758 | 4,250 |
| 256 → 256 | 4,004,346 | 912,670 | 11,163 |

These complete arithmetic-proof fixture transactions passed chain-gang. Each token output lock is 860 bytes. With N token inputs, each of the N token inputs and the shared guard input carries the same serialized prevout list, containing N+2 entries of 36 bytes. The raw repeated list bytes total `36 × (N+1) × (N+2)`, before push headers. At 256 token inputs that accounts for 2,387,016 bytes. The transactions use test proof statements and do not exercise network relay policy.

### Short verifier scriptCode

The opt-in compact profile verifies Groth16 first and executes OP_CODESEPARATOR immediately before the final current-input CHECKSIG. The resulting scriptCode is 35 bytes and the complete ForkID preimage is 192 bytes. The digest is saved on the altstack while the proof runs, and the final signature check is mandatory. The compact profile uses its own transfer digest domain. Existing full-scriptCode locks remain available.

The signed outpoint still commits to the funding transaction, including the full locking script. The shared guard authenticates that funding transaction by txid and checks a hash commitment to the complete verifier lock. An alternative lock with the same post-separator suffix can spend its own output. The test verifies that this alternate output is rejected as the verifier in the original shared-guard layout, even with fresh proof and signatures. A stale proof and its matching old compact preimage are also rejected for a modified payment.

| Token inputs → outputs | Full verifier scriptCode | Short verifier scriptCode |
|---|---:|---:|
| 4 → 4 | 915,713 B | 465,147 B |
| 32 → 32 | 1,033,105 B | 582,544 B |
| 64 → 64 | 1,236,385 B | 785,829 B |
| 256 → 256 | 4,004,346 B | 3,553,803 B |

The proof input's witness is approximately 1.27 KB in this profile. The shared guard still carries the full verifier parent once. Authentication of the short preimage completes after Groth16 execution, so a malformed spend can reach the pairing computation before failing the final signature check.
