# P2PKH-R1 — Pay to P-256 Public Key Hash

**Status**  Initial draft for review · **Category**  Bitcoin Script template · **Maintainer repository**  linzhm/bsv-script-lab  
[中文文本](./p2pkh-r1-proposal.zh-CN.md) · [Canonical template bytes](./p2pkh-r1/template.hex)

## Abstract

P2PKH-R1 defines a BSV locking script template. A payer commits an output to a recipient’s P-256 public-key hash. To spend it, the owner reveals the public key and signs a transaction digest for the current input once. This proposal specifies output generation and recognition, the unlocking stack, and byte-level interoperability checks for wallets and SDKs.

## Motivation and scope

Conventional P2PKH lets a payer create an output knowing only the recipient’s public-key hash. BSV’s native signature check uses secp256k1. Signers such as Apple’s Secure Enclave offer NIST P-256 (secp256r1). P2PKH-R1 retains the public-key-hash payment model, verifies the P-256 signature in Script, and uses Push TX to bind the authorization to the transaction verified by the node. Any signer providing the specified P-256 interface can be used. On-chain verification requires no device identification. Address encoding, payment-request transport, hardware attestation and successor-output covenants are outside the scope of this template. [BRC-16](https://github.com/bsv-blockchain/BRCs/blob/master/scripts/0016.md) · [BRC-21](https://github.com/bsv-blockchain/BRCs/blob/master/scripts/0021.md) · [Apple signing API](https://developer.apple.com/documentation/cryptokit/secureenclave/p256/signing/privatekey)

## Quick start: spend an ordinary payment

Suppose the wallet owns output 0 of a parent transaction. It holds 100,000 satoshis under P2PKH-R1. The wallet pays 99,000 satoshis to a conventional P2PKH recipient and approves a fixture fee of 1,000 satoshis. There is no change. The payment has one input and one output.

1. Fetch the **complete parent**, prepare the recipient output and display the payment amount, change and fee. Call the entry below after approval.
2. The wallet checks the outpoint, spent amount and owner against the parent. It builds a BIP143 ALL (`0x41`) preimage and passes its 32-byte double-SHA-256 digest to the signer. One signer call returns the 64-byte big-endian `r || s`.
3. The wallet assembles all seven unlocking items, validates the child and returns the signed transaction. Call `signed.serialize()` to obtain its wire bytes. Include any change output in `outputs` before signing. The sum of outputs plus the approved fee must equal the spent amount.

```python
from checked_wallet import sign_payment
from tx_engine import TxOut

outputs = [TxOut(99_000, recipient_script)]
signed = sign_payment(parent, 0, outputs, 1_000, owner_public_key,
                      hardware_sign_digest, wallet_history_path)
```

The payment request provides `recipient_script`. The 65-byte R1 `owner_public_key` belongs to the output being spent. The wallet supplies a device digest-signing callback and a persistent signing history path. This entry covers ordinary single-input payments. Use the per-input signing interface for mixed inputs or other signature types. [Wallet implementation](../../research/secure-enclave-p256/checked_wallet.py)

**Offline replay.** The verification environment uses Python 3.12 and the pinned fork. Installation requires Git, a Rust build environment and network access. Subsequent replay is offline. From the repository root run

```sh
python -m pip install "tx-engine @ git+https://github.com/linzhm/chain-gang.git@ffa7f0cc0797d8905655ca9dd0e5270d41daee50"
python research/secure-enclave-p256/replay_payment.py
```

The program returns a recorded public signature only for the fixture digest, validates the transaction locally and compares it byte-for-byte to the published signed transaction. Expected output is `62b466ac14c69de5fb2ea8b743f4b7dfba63ac9af12588f844db2217ca03efa7  (60189 bytes)`. The previous output is synthetic. Amounts and fees are illustrative. An isolated BSV Node 1.2.3 regtest verifies input 0 against the same supplied previous output. [Complete parent](./p2pkh-r1/spend-all/parent.hex) · [Unsigned child, preimage, digest and signature](./p2pkh-r1/spend-all/vector.json) · [Signed transaction](./p2pkh-r1/spend-all/signed.hex) · [Replay program](../../research/secure-enclave-p256/replay_payment.py)

## Specification

In this section, MUST states a byte-level interoperability requirement. SHOULD states recommended wallet behavior. Offsets are zero-based from the first byte of the raw script. Hexadecimal byte strings are shown in serialization order.

### 1. Create the output from a public key

The only template parameter is `ownerHash160` (20 bytes). If given a public key Q, the wallet MUST validate that it is a finite P-256 curve point and compute `RIPEMD160(SHA256(Q))` over exactly the 65 bytes `04 || x_BE32 || y_BE32`. When accepting a hash directly, the payer SHOULD confirm the template name and hash through an authenticated payment request.

1. Read the [canonical template bytes](./p2pkh-r1/template.hex), remove ASCII whitespace and decode the hex into 59,706 bytes. The file is the complete script for vector C.
2. Replace the zero-based slice `[332,352)` with the owner hash and copy all other bytes in order. The result is the raw `scriptPubKey`. Wallets given the same public key should produce identical bytes.
3. In the transaction output, write the eight-byte little-endian amount in satoshis, the CompactSize length `fd 3a e9` and the raw program. Generation requires only public data.

The following example runs from `research/secure-enclave-p256` using Python, `cryptography` and the template file shipped with the repository. The example key is a public test point. [Wallet interface](../../research/secure-enclave-p256/p2pkh_r1.py)

```python
from hashlib import sha256
from p2pkh_r1 import locking_script_from_public_key, recognize

q = bytes.fromhex(
    "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
)
raw = locking_script_from_public_key(q)
assert recognize(raw).hex() == "4ceab2c8be16c1d4c6b4147d39aa449c2d63f184"
assert sha256(raw).hexdigest() == "bef784e131b6095c604523f9b4d2d1a5af8b9eb548353f971bece7695631f9b3"
```

### Recognize the template and extract the owner hash

Use the raw bytes of one output’s script. Decode display hex before matching. The locking script exposes the public-key HASH160. The complete R1 public key appears in item 3 of the unlocking stack. [Machine-readable layout](./p2pkh-r1/layout.json)

| Check | Rule |
| --- | --- |
| Length and prefix | Exactly **59,706 bytes**. The first ten bytes are `76 00 52 a5 69 6b 82 01 20 9d` |
| Owner field | Use the byte regex below with `re.DOTALL` and `fullmatch`. The named group captures 20 bytes at offset 332 |
| Fixed program | Compute `SHA256(raw[:332] + raw[352:])` over the **59,686** remaining bytes, in order. The expected fingerprint is `95bebb421328f7710133c35925231673e7f3f921b31203ce0f02fe1c6825e892` |

```python
rb"\x76\x00\x52\xa5\x69\x6b\x82\x01\x20\x9d.{322}(?P<owner_hash160>.{20}).{59354}"
```

Return the captured hash only after all three checks pass. To verify a payment to a particular recipient, compare the result to the expected owner hash. Pin the expected fixed-program fingerprint in the SDK. The hash can be updated with two slices to avoid allocating a concatenated buffer. The full-script fingerprints in the vectors also cover the owner hash.

### 2. Construct the transaction authorization

Ordinary P2PKH-R1 supports the twelve signature types below. The payer writes only the owner hash. The spending wallet chooses the type separately for each input. A wallet SHOULD default to ALL for an ordinary payment and explain the mutable fields when the user chooses NONE, SINGLE or ANYONECANPAY. Its signing default imposes no permanent restriction on the output. [Conventional P2PKH template](https://github.com/bsv-blockchain/BRCs/blob/master/scripts/0016.md)

| Type | BIP143 | BIP143 + ANYONECANPAY | OTDA | OTDA + ANYONECANPAY |
| --- | --- | --- | --- | --- |
| ALL | `41` | `c1` | `61` | `e1` |
| NONE | `42` | `c2` | `62` | `e2` |
| SINGLE | `43` | `c3` | `63` | `e3` |

All types in the table include the ForkID bit `40`. Under the Chronicle rules the additional `20` bit selects OTDA. Here, BIP143 denotes the ForkID path with that bit clear. Inputs of one transaction can select different types. The transaction’s `nVersion` is serialized separately. [Chronicle specification](https://docs.bsvblockchain.org/network-topology/nodes/sv-node/chronicle-release) · [Node digest algorithms](https://github.com/bitcoin-sv/bitcoin-sv/blob/6504a3aff65ba97c0f6c80962b033e35ecbfed4b/src/script/interpreter.cpp#L1894-L2124)

| Current input | Preimage P the wallet MUST construct | Selector |
| --- | --- | --- |
| BIP143, including unpaired SINGLE | Use ForkID serialization for the requested type with `scriptCode = 68 ac`. The preimage is 159 bytes | 0 |
| OTDA ALL, NONE or paired SINGLE | Use OTDA serialization for the requested type with `scriptCode = 68 ac` for the current input. Length varies with the transaction | 0 |
| OTDA SINGLE with input index ≥ output count | Retain the native check for the requested `63/e3`. Construct a companion BIP143 preimage for `43/c3` respectively, with `scriptCode = 63 ad 67 ab 68 ac` and 32 zero bytes for `hashOutputs`. The preimage is 163 bytes | 1 |

Each `scriptCode` above is the raw script suffix following the applicable executed `OP_CODESEPARATOR`. Encode its length as required by the selected serialization. The preimage ends with the actual preimage signature type as a four-byte little-endian integer. The wallet MUST obtain the output at the current outpoint from the actual parent and check its template and owner. The BIP143 path MUST use that output’s amount. The signer makes one P-256 ECDSA signature over `SHA256(SHA256(P))`. A digest-signing API takes those 32 bytes. Passing them through a message-signing API that hashes its input would change the digest. [Reference preimage construction](../../research/secure-enclave-p256/universal.py)

**Output coverage.** ALL commits to all serialized outputs in order, including their amounts and scripts. NONE permits all outputs to change. Paired SINGLE commits to the output at the current input’s index. Unpaired BIP143 SINGLE uses zero `hashOutputs` and retains an input-specific digest. For unpaired OTDA SINGLE the node returns `uint256(1)` directly. Selector 1 obtains the owner’s authorization for this input through the companion digest. Both paths require one owner signature.

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

Each vector is 59,706 bytes. Use one SHA-256 over the raw script, excluding the amount, CompactSize length and line breaks from the hex file.

| Vector | ownerHash160 | Full-script SHA-256 |
| --- | --- | --- |
| A | `000102030405060708090a0b0c0d0e0f10111213` | `4047136fffb756ffe667bd5329f3990f16acc876649d33bb96c387820717e72f` |
| B | `1111111111111111111111111111111111111111` | `9832bb1a757075188281c4f21f4666c95cb574821f1741914adcbe3f5538d951` |
| C | `4ceab2c8be16c1d4c6b4147d39aa449c2d63f184` | `bef784e131b6095c604523f9b4d2d1a5af8b9eb548353f971bece7695631f9b3` |

An implementation should reproduce all three scripts and recover the corresponding owner hashes. A changed fixed byte, truncation or appended data should fail recognition. Spend tests should cover all twelve types, mixed inputs and both unpaired SINGLE paths. [Recognition tests](../../research/secure-enclave-p256/test_generate_lock.py) · [Node tests](../../research/secure-enclave-p256/test_universal.py)

## Reference implementation and verification status

The reference program is defined directly in Bitcoin Script assembly. Its assembler expands named blocks and fixed repetitions. The reference P-256 verifier uses four-bit windows. Wallets can instantiate the canonical bytes directly using section 1. Run the following commands in the repository’s `research/secure-enclave-p256` directory using the verification environment above. [Generator](../../research/secure-enclave-p256/generate_lock.py) · [Window arithmetic](../../research/secure-enclave-p256/window-4.asm)

```sh
python generate_lock.py --owner-hash160 000102030405060708090a0b0c0d0e0f10111213 --format raw > scriptPubKey.bin
sha256sum scriptPubKey.bin
```

Offline testing has exercised all twelve types, mixed inputs in the same transaction and the unpaired paths. The assembler and the byte-oriented wallet API reproduced all three vectors. The earlier node run is linked below. The next section reports per-path results for the fork. [Verification record](https://github.com/linzhm/bsv-script-lab/actions/runs/44364686046/job/135015159182) · [nChain PUSHTX reference](https://github.com/nchain-innovation/zkscript_package/blob/fc20fb743edbc5bc5aba9d16625d50d1f50a3ef4/src/zkscript/transaction_introspection/transaction_introspection.py)

## Chronicle implications for P2PKH-R1

**Digest selection at spend time.** Both `0x41` and `0x61` commit to all outputs. Bit `0x20` in the latter selects OTDA. We signed the published one-input payment both ways using the same parent, recipient output, amounts and fee. All sizes are bytes. Both transactions passed the pinned chain-gang fork and BSV Node 1.2.3. [Release specification](https://docs.bsvblockchain.org/network-topology/nodes/sv-node/chronicle-release) · [Two-engine run](https://github.com/linzhm/bsv-script-lab/actions/runs/44369934431/job/135033638206)

| Signature type | Preimage | Unlocking script | Complete child |
| --- | ---: | ---: | ---: |
| BIP143 ALL | 159 | 60,102 | 60,189 |
| OTDA ALL | 91 | 60,034 | 60,121 |

OTDA saved **68 bytes** in this case. OTDA serialization depends on transaction shape. BIP143 ALL uses fixed-size hashes of the input and output sets. Estimate the two preimage sizes on the intended transaction. The ordinary example continues to use BIP143 ALL. Carrying the complete parent dominates its unlocking size.

**The direct parent is one raw data item.** The first unlocking item MUST be a single data push of the full serialized parent referenced by the current outpoint. Encode the push prefix for the actual byte length and preserve every input, output, script and the locktime. The outpoint’s vout identifies the spent output. This works within the applicable transaction and script size limits without searching the parent for repetition or classifying its other outputs. The canonical fixture has a 59,768-byte parent and its direct push occupies 59,771 bytes including the three-byte prefix. Spend tests cover both sides of the 65,535-byte push boundary and a parent containing two R1 outputs. [Unlock construction](../../research/secure-enclave-p256/universal.py) · [Complete spend cases](../../research/secure-enclave-p256/test_spend_example.py)

**Lock-side opportunities are smaller.** For a preimage already checked to be long enough, a 32-byte slice at offset 68 could use `OP_SUBSTR` in place of two splits and stack cleanup. The static encoding at that site would shrink from eight bytes to five. This needs the relevant UTXO-era rules and changes the template fingerprint. Numeric shifts merit timing in the four-bit window, although `OP_16 OP_DIV` and `OP_4 OP_RSHIFTNUM` each occupy two bytes. Increasing the ScriptNum ceiling offers no direct size benefit for the current P-256 arithmetic. Relaxing low-S for native signatures does not replace R1 verification or reduce the number of hardware signatures. [Node opcode implementation](https://github.com/bitcoin-sv/bitcoin-sv/blob/6504a3aff65ba97c0f6c80962b033e35ecbfed4b/src/script/interpreter.cpp#L609-L637) · [Window assembly](../../research/secure-enclave-p256/window-4.asm)

### Patched engine coverage

CI builds `linzhm/chain-gang@ffa7f0cc0797d8905655ca9dd0e5270d41daee50` from source and checks the installed revision. Both engines verified paired transactions across all twelve types at two input positions, mixed NONE/OTDA ALL, and unpaired BIP143 SINGLE. Unpaired OTDA SINGLE (`63/e3`) has two separate results.

- **Digest API.** The fork returns the native consensus sentinel, raw byte `01` followed by 31 zero bytes. The preimage API reports an error because this case has no serialized preimage. The owner makes one signature on the input-specific companion BIP143 digest. [Patch notes](https://github.com/linzhm/chain-gang/blob/ffa7f0cc0797d8905655ca9dd0e5270d41daee50/docs/otda-constant-digest.md)
- **Complete input.** The native node accepts the valid companion spend. The pinned fork’s `Tx.validate` reports a false top stack item. Its two-phase source strips separators from the remaining script code. The node retains a later unexecuted separator in the companion BIP143 script code. This source difference is consistent with the observed result. CI records the disagreement explicitly. The next engine acceptance criterion is success on the same complete `63/e3` inputs in both engines. [Initial comparison](https://github.com/linzhm/bsv-script-lab/actions/runs/44369295614/job/135031389747) · [Fork script handling](https://github.com/linzhm/chain-gang/blob/ffa7f0cc0797d8905655ca9dd0e5270d41daee50/src/script/interpreter/script_code.rs#L32-L47) · [Node script suffix selection](https://github.com/bitcoin-sv/bitcoin-sv/blob/6504a3aff65ba97c0f6c80962b033e35ecbfed4b/src/script/interpreter.cpp#L1441-L1482) · [Node BIP143 serialization](https://github.com/bitcoin-sv/bitcoin-sv/blob/6504a3aff65ba97c0f6c80962b033e35ecbfed4b/src/script/interpreter.cpp#L2065-L2084)

**Activation heights.** Node 1.2.3 and the release document specify mainnet 943,816 and testnet 1,713,168. The fork’s constants are 943,835 and 1,713,022 respectively. The comparison uses explicit Genesis/Chronicle flags on isolated regtest and the fork’s `Tx.validate`. For height-aware validation, resolve the target node’s chain parameters, UTXO era and transaction version. Signature bit `0x20` selects the digest algorithm. [Node parameters](https://github.com/bitcoin-sv/bitcoin-sv/blob/6504a3aff65ba97c0f6c80962b033e35ecbfed4b/src/chainparams.cpp#L23-L26) · [Fork parameters](https://github.com/linzhm/chain-gang/blob/ffa7f0cc0797d8905655ca9dd0e5270d41daee50/src/chronicle.rs)

## Security and deployment considerations

The output exposes the owner hash. Spending reveals the public key, signature and an inverse computable from public s. The signing private key and ECDSA nonce k must remain inside the signer. Reusing k under one key for distinct digests can disclose the private key. The reference wallet checks r and the digest for each public key before releasing the signature and blocks on conflict. Its observation covers only calls sharing an intact signing history. Trust in a particular device’s provenance is a separate wallet decision. [ECDSA specification](https://doi.org/10.6028/NIST.FIPS.186-5) · [Wallet implementation](../../research/secure-enclave-p256/checked_wallet.py)

Each output carries about 60 KB of program. A spend also carries the complete parent, which can include earlier unlocking data after successive spends. Wallets should estimate fees from the actual serialized lengths and establish the target service’s transaction acceptance limits.

## Implementation milestones and acceptance criteria

The draft supplies a public-key-to-script function, a recognizer, three output vectors, a complete ordinary BIP143 ALL spend vector and native node spend tests. The next interoperability milestone is a wallet that can complete an offline spend from the specification alone. The following deliverables remain open.

| Stage | Deliverable | Acceptance criterion |
| --- | --- | --- |
| 1. Extend the portable spend vectors | Following the published ordinary BIP143 ALL vector, provide the parent, unsigned child, input index, spent amount, requested and actual preimage types, `scriptCode`, preimage, 32-byte digest, public test signature, completed unlock and expected node result. Large transactions can be files referenced by hash. | Cover ordinary BIP143 ALL, ordinary OTDA ALL, paired SINGLE, both unpaired SINGLE paths and mixed NONE/ALL inputs. Compare serialized bytes at each stage. Record the node version and verification flags, distinguishing input script validation from transaction acceptance. |
| 2. Independent wallet | A second SDK uses the specification, canonical bytes and fixtures to recover the owner hash, construct preimages and assemble the unlocking stack. | Reproduce A/B/C and the stage 1 digests. With the supplied signatures, reproduce the unlock bytes. Validate ordinary and companion spends offline and document any ambiguity that required reading reference code. |
| 3. Physical signer | Integrate Secure Enclave public-key export, digest signing and signature conversion. Record the device, OS version and API. This can proceed alongside stage 2. | Make one signer call per ordinary or companion spend, check the returned signature and pass offline node validation. Cancellation returns no unlocking script. Check signature validity on hardware since ECDSA does not require two signatures on one digest to be byte-identical. |
| 4. Cost and availability | Measure receipt, a single spend and two successive spends. Record the sizes of the lock, parent, unlock and whole transaction. Record local validation and target service policy separately. | Estimate fees using actual sizes and documented rates. Demonstrate how a wallet retains or reacquires its full parent and reports a recoverable error when the parent is unavailable. |
| 5. Independent security review | Review owner authorization, preimage binding, the unpaired branch, P-256 arithmetic and disclosure of mutable fields before signing. | Record findings by topic, reviewed commit, remaining assumptions and retest items. Re-run byte vectors and node cases for any revised implementation. |

The payer’s interface maps a public key to a lock. An indexer maps a lock to an owner hash. At spend time the wallet derives the branch, ordinal and inverse from the transaction, chosen signature type and actual signature. The hardware signer takes one approved 32-byte digest. Keeping these responsibilities distinct lets implementers test each boundary independently.

Evaluate size changes over a complete spend. With the reference builder’s minimal data pushes, an ordinary BIP143 unlocking script occupies `bytes to push the full parent + 331`. An unpaired OTDA unlock occupies `bytes to push the full parent + 335`. The difference comes from the 159- and 163-byte preimages. Both formulas count only the unlocking script. Before moving further calculations into the witness, measure the lock, unlock and successive-spend totals for the same stage 4 fixtures. [Unlock builder](../../research/secure-enclave-p256/universal.py)

This draft follows the BRC script proposal format. A BRC number has not been assigned. [BRC proposal format](https://github.com/bsv-blockchain/BRCs/blob/master/EXAMPLE.md) · [Wei Zhang, WP1605, *PUSHTX and its Building Blocks* (original publisher URL)](https://nchain.com/wp-content/uploads/2022/03/WP1605_PUSHTX-and-its-Building-Blocks.pdf)
