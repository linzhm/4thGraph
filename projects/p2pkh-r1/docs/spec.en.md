# P2PKH-R1 payment script template

Developer request for comments · BRC number unassigned · [中文](./spec.zh-CN.md)

## Payment model

A payer can create an output using the recipient's P-256 public key hash. The holder spends it by revealing the public key and signing the current input's digest once. The outpoint selects the previous output. The node obtains its amount and locking script from its UTXO view. The wallet may use the complete funding transaction locally to verify that information. Only current authorization data enter the unlocking script.

For example, an ordinary P2PKH payment can create an R1 output for Alice. When Alice pays Bob, her device signs the input spending that output. When Bob later spends his output, his unlocking script contains his signature for the new payment. Alice's signature stays in the transaction she signed.

## Create and identify an output

1. Validate the uncompressed 65-byte X9.63 encoding `04 || X_BE32 || Y_BE32` on secp256r1. Compute HASH160 of those 65 bytes. A wallet with the recipient's 20-byte hash may use it directly.
2. Copy the canonical raw script and write the recipient hash at the zero-based half-open interval `[208, 228)`. The script is **59,582 bytes**. Only these 20 bytes vary between recipients.
3. For recognition, check the length and ten-byte prefix `760052a569766b7c8201`. Extract the candidate owner hash. Require `SHA256(raw[:208] || raw[228:])` to equal `2129d374594069d08a9b2127555f48ea21c75fb06d1ad5e77c68ad251e97f784` before returning the type and hash. Byte zero is the first opcode. The public key itself is revealed on spend. [Canonical bytes](../template/template.hex) · [Layout and three vectors](../template/layout.json) · [Byte matcher and generator](../reference/p2pkh_r1.py)

Set `R1_OWNER_HASH160` to the recipient’s 20-byte HASH160 in hex.

```sh
cd projects/p2pkh-r1/reference
python generate_lock.py --owner-hash160 "${R1_OWNER_HASH160:?Set the recipient HASH160}" --format raw > scriptPubKey.bin
```

The CLI also accepts `--public-key HEX`. Omitting `--format raw` returns the length, owner hash and script SHA-256. The canonical template embeds the owner hash of vector C’s public test key. Outputs using that key are for local tests only. Vector C has script SHA-256 `b3acd6b92a23120bd24432ada2b1cac013fe06381d7ea96ac6c5a73c493f4287`. [Generator](../reference/generate_lock.py)

## Spend one input

The wallet checks the funding txid, output index, amount, template and owner key. Build the transaction including recipient and change outputs, then serialize the signing preimage `P` for the selected input and signature type. Ask the device for one ECDSA P-256 signature of **SHA256d(P)**. Pass the 32-byte digest to a digest-signing API. For a message API that applies SHA-256 once, pass SHA256(P). Encode the result as two 32-byte big-endian scalars. Write the following items in order. [Wallet entry point](../reference/wallet.py) · [Preimage and unlocking script](../reference/signature.py)

| Order | Encoding | Meaning |
|---|---|---|
| 1 | push(P) | Signing preimage for this input and execution path |
| 2 | push(Q) | Current owner's 65-byte public key |
| 3 | push(r ∥ s) | Current input's 64-byte R1 signature |
| 4 | push(invS) | Little-endian 32-byte s⁻¹ modulo the R1 order n. The lock checks s × invS ≡ 1 modulo n |
| 5 | OP_0 or OP_1 | Ordinary path or the unpaired OTDA SINGLE companion path below |

The wallet MUST derive item 5 from the prepared transaction and the requested signature type. It MUST emit OP_1 exactly when the type is 0x63 or 0xe3 and the zero-based input index is at least the number of outputs. In every other supported case it MUST emit OP_0. The ordinary payment API fixes the type to 0x41 and exposes no selector or sighash argument. A multi-input protocol that explicitly uses another supported type derives the selector by the same rule. [Wallet implementation](../reference/wallet.py) · [Selector derivation](../reference/signature.py)

When recognizing an incoming payment, verify the complete template fingerprint and the expected recipient hash. A sender can create arbitrary output scripts. A script that forces NONE on the recipient changes fixed program bytes and fails this template check. A sender's own signature type applies to the input it signs. Each recipient chooses a signature type when later spending their output.

The lock checks HASH160(Q), verifies the R1 signature, and binds the authorization to the node's transaction context through the public PUSHTX construction and native `OP_CHECKSIG`. Neither a serialized parent nor an earlier signature occurs in the witness. For ordinary ForkID ALL, P is 159 bytes and includes serialized scriptCode `02 68 ac`. The five items occupy **326 bytes** (161 + 66 + 65 + 33 + 1). [Lock assembly](../reference/asm/lock.asm) · [Transaction binding](../reference/asm/binding.asm) · [nChain WP1605](https://nchain.com/wp-content/uploads/2022/03/WP1605_PUSHTX-and-its-Building-Blocks.pdf) · [BRC-21](https://github.com/bsv-blockchain/BRCs/blob/master/scripts/0021.md)

The wallet first constructs P from the actual spend and signature type, hashes P, and asks the owner's R1 key to sign that digest. The R1 check proves owner authorization. The separate native secp256k1 PUSHTX check uses the same digest and public construction parameters; the spender needs only the R1 private key. The node evaluates that native signature against its own transaction context, within the chosen signature coverage. [nChain PUSHTX implementation](https://github.com/nchain-innovation/zkscript_package/blob/fc20fb743edbc5bc5aba9d16625d50d1f50a3ef4/src/zkscript/transaction_introspection/transaction_introspection.py)

## Signature coverage

Each input chooses its own type. The template supports the ForkID BIP143 and Chronicle OTDA algorithms. Each accepts ALL, NONE and SINGLE, with or without ANYONECANPAY. The payment helper uses `0x41`. The `0x20` signature-type bit selects OTDA under the applicable Chronicle activation rules. [Chronicle release](https://docs.bsvblockchain.org/network-topology/nodes/sv-node/chronicle-release) · [Node serialization and digest selection](https://github.com/bitcoin-sv/bitcoin-sv/blob/6504a3aff65ba97c0f6c80962b033e35ecbfed4b/src/script/interpreter.cpp#L1894-L2124)

| Requirement | Commitment |
|---|---|
| All outputs | ALL covers the ordered output list. BIP143 hashOutputs hashes the concatenation of complete serialized outputs. OTDA ALL serializes those outputs in the transformed spending transaction |
| Selective output coverage | NONE leaves outputs free. SINGLE's output commitment selects the same-index output. To establish a particular script or amount, a verifier must account for complete output boundaries |
| Other inputs' outpoints | Without ANYONECANPAY, BIP143 hashPrevouts covers all ordered input outpoints. With it, the field is zero. OTDA selects the input set in the transformed transaction |
| Input values | BIP143 includes the current input amount. Neither algorithm directly proves another input's amount. OTDA also omits the current input amount |

With no same-index output, BIP143 SINGLE sets hashOutputs to zero and still commits to the current outpoint. Unpaired OTDA SINGLE uses the node's constant digest 1. The derived selector is OP_1. The device signs one companion BIP143 SINGLE preimage bound to the current input, preserving the ANYONECANPAY selection. The script also checks the native OTDA constant using a public construction. The companion P is 163 bytes. An ordinary OTDA preimage can grow with this transaction. For instance, OTDA ALL includes the locking script of a new R1 output. [Native behavior](https://github.com/bitcoin-sv/bitcoin-sv/blob/6504a3aff65ba97c0f6c80962b033e35ecbfed4b/src/script/interpreter.cpp#L1894-L2124) · [Path construction](../reference/signature.py)

The expanded program is 59,582 bytes. Its four-bit scalar-multiplication window occupies 57,224 bytes (96.0%). The ordinary k1 signature-construction block occupies 394 bytes, excluding the shared dispatch and native CHECKSIG instructions. These figures describe serialized code size. Node execution time is a separate measurement. [Window](../reference/asm/window.asm) · [Public k1 construction](../reference/asm/r1.asm)

## Signing message and serialization

For ordinary BIP143, concatenate the following fields in wire order. The scriptCode length is a CompactSize prefix. Transaction version, output index, sequence, locktime and hash type are little-endian 32-bit integers. Amount is an eight-byte little-endian integer in satoshis. The outpoint contains the funding txid in wire order and the output index. The final signed transaction contains the unlocking script once.

```text
version || hashPrevouts || hashSequence || outpoint || 02 68 ac ||
amount || sequence || hashOutputs || locktime || typeLE32
```

The ordinary preimage has 159 bytes. The companion replaces `02 68 ac` with `06 63 ad 67 ab 68 ac`. BIP143 hashSequence is zero for NONE, SINGLE and ANYONECANPAY. An unpaired SINGLE has no placeholder output in the transaction. For paired OTDA SINGLE, the node's signing serialization uses null outputs at earlier indices; these placeholders exist only in that serialization. Use the node rules for the active network and spend context. The built-in payment SDKs serialize version 2, final sequence and zero locktime. [Payment vector](../template/spend-all.json) · [Reference builder](../reference/signature.py)

## Security and interoperability

P-256 keys must lie on the curve, and both signature scalars must be in `[1,n)`. The hardware protects the private key and the signing nonce. Only public quantities enter the witness. The host must verify the full funding script, check recipients, change and fees before signing, and verify the returned signature before releasing a transaction. A persistent signer may additionally withhold a signature if the same key emits the same r on different digests. The Python reference includes this check. A signature in NONE mode leaves payment outputs unconstrained. Other inputs can supply additional authorizations. [Reference wallet](../reference/wallet.py)

The receiving and normal payment APIs, their trusted inputs, and conformance cases are specified in the [SDK guide](./sdk.en.md). Run the [node differential tests](../reference/test_payment.py) against the released BSV Node 1.2.3 interpreter and the [pinned chain-gang OTDA fix](https://github.com/linzhm/chain-gang/commit/8b60b71a12a69fdcb465d3e627dbf6f43d6ed081) before claiming engine interoperability. Test the two unpaired OTDA SINGLE cases as complete spends. The program uses the last *executed* code separator; dropping another one from BIP143 scriptCode changes the digest. The release gate also includes a physical hardware signing round trip, independent cryptographic review and miner policy/fee measurement. See [Chronicle rule applicability](./chronicle.md).

## Acknowledgments

We thank Wei Zhang for documenting in nChain white paper WP1605, *PUSHTX and its Building Blocks*, how a secp256k1 signature constructed from public parameters can bind a supplied signing preimage to the actual transaction through native `OP_CHECKSIG`. P2PKH-R1 uses this construction for its transaction check. [WP1605 reference](https://github.com/bsv-blockchain/BRCs/blob/master/scripts/0021.md#references) · [nChain's PUSHTX implementation](https://github.com/nchain-innovation/zkscript_package/blob/fc20fb743edbc5bc5aba9d16625d50d1f50a3ef4/src/zkscript/transaction_introspection/transaction_introspection.py)

We thank Xiaohui Liu for explaining the applications of OP_PUSH_TX in Bitcoin Script, and the BRC-21 contributors for documenting how the unlocking stack can supply the signing preimage. [Xiaohui Liu's technical talk](https://www.wearedevelopers.com/videos/146-op_push_tx-and-its-applications-in-bitcoin-smart-contracts) · [BRC-21](https://github.com/bsv-blockchain/BRCs/blob/master/scripts/0021.md)

We thank the BSV Node and chain-gang maintainers. Their interpreters let us validate the same complete input independently and compare the behavior of the Chronicle execution paths. [BSV Node](https://github.com/bitcoin-sv/bitcoin-sv) · [chain-gang](https://github.com/nchain-innovation/chain-gang)
