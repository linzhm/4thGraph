# P2PKH-R1 — Pay to P-256 Public Key Hash

**Status**  Initial draft for review · **Category**  Bitcoin Script template · **Maintainer repository**  linzhm/bsv-script-lab  
[中文文本](./p2pkh-r1-proposal.zh-CN.md) · [Canonical template bytes](./p2pkh-r1/template.hex)

## Abstract

P2PKH-R1 defines a BSV locking script template. A payer commits an output to a recipient’s P-256 public-key hash and a set of permitted transaction signature types. To spend it, the owner reveals the public key and signs a transaction digest for the current input once. This proposal specifies output generation and recognition, the unlocking stack, and byte-level interoperability checks for wallets and SDKs.

## Motivation and scope

Conventional P2PKH lets a payer create an output knowing only the recipient’s public-key hash. BSV’s native signature check uses secp256k1. Signers such as Apple’s Secure Enclave offer NIST P-256 (secp256r1). P2PKH-R1 retains the public-key-hash payment model, verifies the P-256 signature in Script, and uses Push TX to bind the authorization to the transaction verified by the node. Any signer providing the specified P-256 interface can be used. On-chain verification requires no device identification. Address encoding, payment-request transport, hardware attestation and successor-output covenants are outside the scope of this template. [BRC-16](https://github.com/bsv-blockchain/BRCs/blob/master/scripts/0016.md) · [BRC-21](https://github.com/bsv-blockchain/BRCs/blob/master/scripts/0021.md) · [Apple signing API](https://developer.apple.com/documentation/cryptokit/secureenclave/p256/signing/privatekey)

## Specification

In this section, MUST states a byte-level interoperability requirement. SHOULD states recommended wallet behavior. Offsets are zero-based from the first byte of the raw script. Hexadecimal byte strings are shown in serialization order.

### 1. Create and recognize an output

The payment parameters are `ownerHash160` (20 bytes) and `allowedTypes` (a nonempty subset of the table below). If the recipient supplies a public key Q, the wallet MUST validate that Q is a finite P-256 curve point and compute `RIPEMD160(SHA256(Q))` over exactly the 65 bytes `04 || x_BE32 || y_BE32`. When accepting a hash directly, the payer SHOULD confirm the template name, hash and permission set through an authenticated payment request. The recommended ordinary payment policy is `{41,61}`, allowing the owner to commit to all outputs using either digest algorithm.

1. Read the [canonical template bytes](./p2pkh-r1/template.hex), remove ASCII whitespace and decode the hex. The result is the complete 59,811-byte program for vector A below.
2. Replace the 20 bytes at `[437,457)` with `ownerHash160`. For each signature type in the table, write `51` (`OP_1`) at its offset if permitted, otherwise `00` (`OP_0`). Each of the twelve offsets occupies one byte.
3. The result is the raw `scriptPubKey`. Every other byte MUST match the canonical template. To serialize a transaction output, write the amount in satoshis as an eight-byte little-endian integer, followed by the script length `fd a3 e9` and the raw program.
4. A recognizer MUST check the full length, every fixed byte, all twelve permission values and a nonempty permission set before returning the template name, owner hash and permitted types. A byte-pattern matcher can perform this check. Its input is the script field of one parsed output. The internal binding public key belongs to the fixed program. The owner supplies the payment public key at spend time.

| Type | ForkID / offset | ForkID + ANYONECANPAY / offset | OTDA / offset | OTDA + ANYONECANPAY / offset |
| --- | --- | --- | --- | --- |
| ALL | `41` / 307 | `c1` / 316 | `61` / 366 | `e1` / 376 |
| NONE | `42` / 326 | `c2` / 336 | `62` / 386 | `e2` / 396 |
| SINGLE | `43` / 346 | `c3` / 356 | `63` / 406 | `e3` / 416 |

### 2. Construct the transaction authorization

The spending wallet selects a permitted signature type for each input. All types in the table include the ForkID bit `40`. Under the Chronicle rules the additional `20` bit selects OTDA. Here, BIP143 denotes the ForkID path with that bit clear. Inputs of one transaction can select different types. The transaction’s `nVersion` is serialized separately. [Chronicle specification](https://docs.bsvblockchain.org/network-topology/nodes/sv-node/chronicle-release) · [Node digest algorithms](https://github.com/bitcoin-sv/bitcoin-sv/blob/6504a3aff65ba97c0f6c80962b033e35ecbfed4b/src/script/interpreter.cpp#L1894-L2124)

| Current input | Preimage P the wallet MUST construct | Selector |
| --- | --- | --- |
| BIP143, including unpaired SINGLE | Use ForkID serialization for the requested type with `scriptCode = 68 ac`. The preimage is 159 bytes | 0 |
| OTDA ALL, NONE or paired SINGLE | Use OTDA serialization for the requested type with `scriptCode = 68 ac` for the current input. Length varies with the transaction | 0 |
| OTDA SINGLE with input index ≥ output count | Retain the native check for the requested `63/e3`. Construct a companion BIP143 preimage for `43/c3` respectively, with `scriptCode = 63 ad 67 ab 68 ac` and 32 zero bytes for `hashOutputs`. The preimage is 163 bytes | 1 |

Each `scriptCode` above is the raw script suffix following the applicable executed `OP_CODESEPARATOR`. Encode its length as required by the selected serialization. The preimage ends with the actual preimage signature type as a four-byte little-endian integer. The wallet MUST obtain the output at the current outpoint from the actual parent and check its owner and permissions. The BIP143 path MUST use that output’s amount. The signer makes one P-256 ECDSA signature over `SHA256(SHA256(P))`. A digest-signing API takes those 32 bytes. Passing them through a message-signing API that hashes its input would change the digest. [Reference preimage construction](../../research/secure-enclave-p256/universal.py)

**Output coverage.** ALL commits to all serialized outputs in order, including their amounts and scripts. NONE permits all outputs to change. Paired SINGLE commits to the output at the current input’s index. Unpaired BIP143 SINGLE uses zero `hashOutputs` and retains an input-specific digest. For unpaired OTDA SINGLE the node returns `uint256(1)` directly. Selector 1 obtains the owner’s authorization for this input through the companion digest. Permission for the requested type is independent of permission for the companion type. Both paths require one owner signature.

**Input coverage.** BIP143 `hashPrevouts` commits to all outpoints in order. ANYONECANPAY sets it to zero. The current outpoint, amount and sequence still enter the preimage directly. Only ALL without ANYONECANPAY includes the full `hashSequence`. OTDA serializes a transformed transaction and has no separate aggregate-hash fields or previous-output amount field. To calculate fees, the wallet should obtain the actual spent outputs. For example, if input A uses NONE and relies on B’s ALL signature to select the outputs, A should check B’s outpoint and omit ANYONECANPAY. Otherwise A’s authorization permits B to be omitted. [Node serialization rules](https://github.com/bitcoin-sv/bitcoin-sv/blob/6504a3aff65ba97c0f6c80962b033e35ecbfed4b/src/script/interpreter.cpp#L1894-L2124)

### 3. Construct and verify the unlocking script

The spender MUST push six byte strings in the following order, followed by the selector opcode. The direct parent is the full transaction referenced by the current outpoint. Let n be the order of the P-256 group. [P-256 parameters](https://doi.org/10.6028/NIST.SP.800-186)

| Order, bottom to top | Encoding |
| --- | --- |
| 1 | Complete wire serialization of the direct parent transaction |
| 2 | Preimage P selected in section 2 |
| 3 | 65-byte public key Q including the `04` prefix |
| 4 | 64 bytes `r_BE32 || s_BE32`, with `1 ≤ r,s < n`. Convert a DER signature to this representation and omit any signature-type suffix |
| 5 | Four-byte little-endian unsigned integer. Use the actual input index for ordinary OTDA without ANYONECANPAY and zero otherwise |
| 6 | 32-byte little-endian unsigned integer `w = s⁻¹ mod n` |
| 7 | `OP_0` for the ordinary path or `OP_1` for the companion path |

The lock checks the owner hash, curve point and signature scalars, verifies `1 ≤ w < n` and `s·w mod n = 1`, and checks the ECDSA verification equation. It checks the parent transaction hash against the current outpoint’s txid in the preimage. Native `OP_CHECKSIG` binds the supplied material to the transaction. The ordinary OTDA path uses the input count and ordinal to locate the current input and check its script marker. No Script loop scales with the number of transaction inputs or outputs. A wallet SHOULD derive these values from transaction data and show amounts, fees and fields that the signature permits to change before obtaining consent. [Signature verification assembly](../../research/secure-enclave-p256/payment.asm) · [Transaction binding assembly](../../research/secure-enclave-p256/universal.asm)

## Interoperability vectors

These fingerprints use one SHA-256 over the raw locking script. Both scripts are 59,811 bytes. The hash excludes the amount, CompactSize length and line breaks in the hex file. The owner hashes below are byte fixtures.

| Vector | ownerHash160 (hexadecimal) | allowedTypes | Raw script SHA-256 |
| --- | --- | --- | --- |
| A | `000102030405060708090a0b0c0d0e0f10111213` | `41,61` | `6ac6c4dbbf77bb0a73cf2136338c5d81a3c2674f71929f9c2dd196064be6b952` |
| B | Byte `11` repeated 20 times | `42,e3` | `92599b5ff408dbbeb92241bc89e7ce932bdddfd318907c8099db5ba348ef8d52` |

An implementation should generate both vectors, recognize them and return the exact payment parameters. A recognizer should reject an empty permission set, a changed fixed opcode, truncation or appended bytes. Spend tests should cover both digest algorithms on the same UTXO, NONE, paired and unpaired SINGLE, an incorrect parent, and an incorrect inverse. [Recognition tests](../../research/secure-enclave-p256/test_lock_identity.py) · [Native node tests](../../research/secure-enclave-p256/test_universal.py)

## Reference implementation and verification status

The reference program is defined directly in Bitcoin Script assembly. Its assembler expands named blocks and fixed repetitions. The reference P-256 verifier uses four-bit windows. Wallets can instantiate the canonical bytes directly using section 1. Run the following commands in the repository’s `research/secure-enclave-p256` directory with Python 3.12 and `tx-engine==0.13.1`. [Generator](../../research/secure-enclave-p256/generate_lock.py) · [Window arithmetic](../../research/secure-enclave-p256/window-4.asm)

```sh
python generate_lock.py --owner-hash160 000102030405060708090a0b0c0d0e0f10111213 --allow 41,61 --format raw > scriptPubKey.bin
sha256sum scriptPubKey.bin
```

Offline testing has exercised all twelve types, mixed inputs in the same transaction and the unpaired paths. The recorded reference run passed 52 Python/chain-gang tests, eight BSV Node 1.2.3 tests and two nChain comparisons. Its output script fingerprint matches vector A. [Verification record](https://github.com/linzhm/bsv-script-lab/actions/runs/44356580922/job/134986197432) · [nChain PUSHTX reference](https://github.com/nchain-innovation/zkscript_package/blob/fc20fb743edbc5bc5aba9d16625d50d1f50a3ef4/src/zkscript/transaction_introspection/transaction_introspection.py)

## Security and deployment considerations

The output exposes the owner hash. Spending reveals the public key, signature and an inverse computable from public s. The signing private key and ECDSA nonce k must remain inside the signer. Reusing k under one key for distinct digests can disclose the private key. The reference wallet checks r and the digest for each public key before releasing the signature and blocks on conflict. Its observation covers only calls sharing an intact signing history. Trust in a particular device’s provenance is a separate wallet decision. [ECDSA specification](https://doi.org/10.6028/NIST.FIPS.186-5) · [Wallet implementation](../../research/secure-enclave-p256/checked_wallet.py)

Each output carries about 60 KB of program. A spend also carries the complete parent, which can include earlier unlocking data after successive spends. Wallets should estimate fees from the actual serialized lengths and establish the target service’s transaction acceptance limits.

## Outstanding work

| Work item | Acceptance criterion |
| --- | --- |
| Independent implementation and portable spend vectors | Publish fixed parents, spending transactions, preimages, digests, signatures and expected results. Reproduce the ordinary and companion paths in a second wallet implementation |
| Device integration | Sign a fixture digest on a physical Secure Enclave device, convert its signature to the specified 64 bytes and validate the complete spend on an offline node |
| Deployment and independent review | Record representative sizes, fees and acceptance policies. Obtain independent review of preimage binding, branch separation, curve arithmetic and wallet consent displays |

This draft follows the BRC script proposal format. A BRC number has not been assigned. [BRC proposal format](https://github.com/bsv-blockchain/BRCs/blob/master/EXAMPLE.md) · [Wei Zhang, WP1605, *PUSHTX and its Building Blocks* (original publisher URL)](https://nchain.com/wp-content/uploads/2022/03/WP1605_PUSHTX-and-its-Building-Blocks.pdf)
