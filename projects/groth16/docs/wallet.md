# Wallet recognition

A lock starts with a canonical push of the ASCII string `BSV/Groth16/1`, `OP_DROP`, a 32-byte descriptor ID push, and `OP_DROP`. The header consumes its own data and leaves the proof stack intact. The wallet can derive the same lock before receiving the transaction.

| Stage | Wallet check |
|---|---|
| Discover | Read the marker and descriptor ID using `candidate_id(script)`. Associate the candidate with a descriptor supplied over the payment channel or already in the wallet. |
| Recognize | Decode the descriptor and compare the entire output script with the output of `VerifierDescriptor.build_lock()`. The helper `matches_lock(script)` performs the comparison. A copied marker and ID can still label arbitrary script bytes. |
| Interpret | Bind the descriptor to the wallet's expected circuit and ordered input semantics, such as the asset ID, amount and receiver commitment. The descriptor commits to the key and statement bytes. Application semantics come from the wallet's configured circuit and payment rules. |
| Confirm | Authenticate the transaction and selected output using the txid, Merkle branch and validated header chain. If confirmation must show a proof was exercised, authenticate the actual prevout of the spending transaction and recognize its locking script. The helper `matches_prevout(transaction, input_index, parent)` checks the outpoint and full script. Output creation leaves the new proof predicate pending until the output is spent. |

A wallet can cache the SHA-256 of each rebuilt lock under its descriptor ID. After the first successful derivation, it can match the lock by hash and preserve the descriptor for display and interoperability. A wallet inspecting an unconfirmed spend may locally verify the complete input against the authenticated prevout. A direct proof test through `verify_host(key, public_inputs, proof)` verifies only the mathematical statement.

## Wallet integration

```python
from descriptor import VerifierDescriptor, candidate_id

descriptor = VerifierDescriptor.decode(encoded_descriptor)
assert descriptor.identifier() in accepted_descriptor_ids
assert candidate_id(received_lock) == descriptor.identifier()
assert descriptor.matches_lock(received_lock)
assert descriptor.matches_prevout(confirmed_spend, input_index, parent_transaction)
```

The application must validate confirmation and decide which circuit and statement it accepts. The prevout helper authenticates the supplied parent bytes against the input reference. The application can obtain the parent transaction from its transaction package or any data source.

## Canonical encoding

The descriptor ID is SHA-256 over the concatenation of the fields below. Coordinate ordering is affine $x,y$. A $G_2$ coordinate is encoded real component first, imaginary component second. All fixed-width integers use big endian.

| Field | Encoding |
|---|---|
| Domain and version | ASCII `BSV/Groth16/descriptor/v1` followed by one zero byte |
| Script profile | One byte, ordered as `0` separate, `1` fused, `2` alpha, `3` beta, `4` gamma |
| Public input count | Four bytes |
| Verification key | α in $G_1$, then (β, γ, δ) in $G_2$, each base-field coordinate 48 bytes |
| IC entries | Count plus one entries. Each starts with `00` for the identity or `01` followed by an affine $G_1$ point |
| Public inputs | Count scalar elements, 32 bytes each |

Reject unknown profiles, trailing data, bad field ranges and malformed point encodings. Script generation additionally validates the verification key's curve and subgroup membership. The descriptor profile identifies the experiment and selects its corresponding witness format.

The unlock is push-only. In stack pop order the verifier reads eight proof coordinates and twelve residue coefficients. Alpha then reads 408 affine slope coordinates, beta reads 136, and gamma takes the proof and residue alone. The host emits minimally encoded little-endian signed-magnitude ScriptNum values. The script bounds each input element to 48 bytes and normalizes it before checking its field range. Wallets should call `descriptor.build_unlock(proof)` so the witness matches the locking profile.
