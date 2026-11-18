# P2PKH-R1 v7 payment proposal

[中文版](./p2pkh-r1-proposal.zh-CN.md)

A payer needs two public parameters to create this lock, **the recipient’s P-256 public-key hash** and **the set of permitted signature types**. Instantiating the tested v7 assembly template with those parameters produces a 59,811-byte BSV output script. The recipient needs the Secure Enclave only when spending. The template version and the BSV transaction’s `nVersion` are independent. [Generator](../../research/secure-enclave-p256/generate_lock.py) · [Assembly entry point](../../research/secure-enclave-p256/universal.asm)

## 1. Agree on the payment parameters

1. The receiving wallet exports its P-256 (secp256r1) signing public key in the 65-byte X9.63 encoding `04 || x_BE32 || y_BE32`. The payment request should identify the template as `P2PKH-R1`, specify version 7 and the permitted signature types, and convey either the key or `RIPEMD160(SHA256(Q))`. This is a wallet interface proposal with no assigned BSV address prefix. A hash alone establishes neither possession of the private key nor hardware provenance. [Apple Secure Enclave signing API](https://developer.apple.com/documentation/cryptokit/secureenclave/p256/signing/privatekey)
2. The payer obtains the parameters from an authenticated payment request. For a public key, the generator validates the encoding and curve point before hashing all 65 bytes. For a supplied hash, it checks the 20-byte length. Ordinary payments default to the two ALL types, `41,61`. A payment that needs NONE, SINGLE or ANYONECANPAY must include the relevant type when creating the output.
3. After assembly, the generator reads back the template, version, owner and all permissions through the full-script matcher. The payer checks the amount and assigns the raw result to the new output’s `scriptPubKey`. The wire output is `amount_LE64 || CompactSize(59811) || scriptPubKey`. The length prefix is `fd a3 e9`. Insert the program bytes directly into the script field. An extra PUSHDATA wrapper would change the program. [Template recognition](../../research/secure-enclave-p256/lock_identity.py)

## 2. Reproduce a payment script

These commands target Linux with private repository access, Python 3.12 and an available tx-engine wheel. After dependencies are installed, generation works offline. The example hash is a byte fixture with no receiving wallet supplied.

```sh
git clone --branch research/pels-transaction-bounds https://github.com/linzhm/bsv-script-lab.git
cd bsv-script-lab
git checkout --detach f2c1503d4cb2d4843a4b13f6b8be187816376eea
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install --only-binary=tx-engine tx-engine==0.13.1
cd research/secure-enclave-p256
OWNER=000102030405060708090a0b0c0d0e0f10111213
python generate_lock.py --owner-hash160 "$OWNER" --allow 41,61
python generate_lock.py --owner-hash160 "$OWNER" --allow 41,61 --format raw > scriptPubKey.bin
sha256sum scriptPubKey.bin
```

The manifest should report `P2PKH-R1`, version `7`, permissions `["41","61"]` and `59811` bytes. The single SHA-256 fingerprint of the raw fixture is **`6ac6c4dbbf77bb0a73cf2136338c5d81a3c2674f71929f9c2dd196064be6b952`**. Spending uses a separately computed transaction signing digest. For an actual recipient public key, substitute `--public-key "$PUBLIC_KEY_HEX"` for `--owner-hash160 "$OWNER"`. Both inputs produce identical bytes when they represent the same owner and policy. Changing either parameter changes the fingerprint. [Binary fixture and JSON manifest](https://github.com/linzhm/bsv-script-lab/actions/runs/44356580922/artifacts/14454081010) · [Generation and verification log](https://github.com/linzhm/bsv-script-lab/actions/runs/44356580922/job/134986197432)

## 3. Assemble the lock

| Source | Role |
| --- | --- |
| [universal.asm](../../research/secure-enclave-p256/universal.asm) | Defines the LOCK entry, owner and twelve permission slots, ordinary and unpaired SINGLE paths, and the code separators for native verification. |
| [payment.asm](../../research/secure-enclave-p256/payment.asm) | Checks R1 curve points, the signature and public arithmetic hints. Implements the WP1605 PUSHTX building block used to bind the supplied digest to BSV’s native signature check. |
| [window-4.asm](../../research/secure-enclave-p256/window-4.asm) | Uses separate four-bit tables for the fixed base point G and the revealed public key Q. The assembler expands 64 rounds for the 256-bit scalars. |
| [handwritten.py](../../research/secure-enclave-p256/handwritten.py) | Expands named assembly blocks and fixed repetitions, encodes opcodes with nChain chain-gang’s tx-engine, and fills the 20-byte owner slot and twelve single-opcode permissions. The direct API is `locking_script(owner_hash, allowed_types, version=7).raw_serialize()`. Omitting the version selects an earlier template. |

The payer sets only those thirteen slots. At spend time, the lock hashes the supplied preimage twice with SHA-256 and verifies the owner’s R1 ECDSA signature. Native secp256k1 `OP_CHECKSIG` supplies the transaction binding using public PUSHTX parameters. The lock also ties the supplied parent transaction hash to the txid in the current outpoint. An ordinary payment allows the owner to choose new output scripts. A business requirement to continue the lock at the same output index would require a separate PELS successor rule. This assembly uses no sCrypt, JavaScript/TypeScript compiler or upstream zkscript compiler. [WP1605 source notes](./pels-transaction-bounds.md) · [nChain PUSHTX reference](https://github.com/nchain-innovation/zkscript_package/blob/fc20fb743edbc5bc5aba9d16625d50d1f50a3ef4/src/zkscript/transaction_introspection/transaction_introspection.py) · [Pinned chain-gang](https://github.com/nchain-innovation/chain-gang/tree/v0.13.1)

## 4. Choose the signature coverage

The payer fixes the allowed set at receipt. The spending wallet selects one allowed type for each input. All table entries are hexadecimal, with ANYONECANPAY variants in parentheses. Under Chronicle, these types have the ForkID bit `40` set. The additional `20` bit selects OTDA. Inputs of a single transaction can choose different types. [Chronicle specification](https://docs.bsvblockchain.org/network-topology/nodes/sv-node/chronicle-release) · [Node serialization and dispatch](https://github.com/bitcoin-sv/bitcoin-sv/blob/6504a3aff65ba97c0f6c80962b033e35ecbfed4b/src/script/interpreter.cpp#L1894-L2124)

| Authorization | BIP143-style ForkID | OTDA | Output coverage |
| --- | --- | --- | --- |
| ALL | 41 (c1) | 61 (e1) | Commits to all outputs in order, including amounts and scripts |
| NONE | 42 (c2) | 62 (e2) | Allows all outputs to change under this signature |
| SINGLE | 43 (c3) | 63 (e3) | Commits to the output at the input’s index when present. See below when absent |

For BIP143, `hashPrevouts` commits to all input outpoints in order unless ANYONECANPAY sets it to 32 zero bytes. The current outpoint, previous output amount and current sequence appear directly in the preimage. Only ALL without ANYONECANPAY commits to the complete `hashSequence`. The `hashOutputs` field commits to all serialized outputs for ALL and the paired output for paired SINGLE. NONE and unpaired SINGLE use zero. OTDA serializes a transaction transformed for the chosen signature type. It has no separate aggregate-hash fields or current previous-output amount field. Other inputs’ outpoints alone do not establish their amounts. A wallet calculating fees must obtain the actual spent outputs. A rule about variable-length outputs must authenticate their serialization and boundaries before interpreting a slice as an output. [Node source](https://github.com/bitcoin-sv/bitcoin-sv/blob/6504a3aff65ba97c0f6c80962b033e35ecbfed4b/src/script/interpreter.cpp#L1894-L2124) · [Transaction bounds study](./pels-transaction-bounds.md)

Take a transaction with inputs 0 and 1 and only output 0. Input 1 using BIP143 SINGLE has a transaction-specific digest with zero `hashOutputs`. For OTDA SINGLE the node returns `uint256(1)` before serialization. v7 retains the requested native check and has the phone sign a companion BIP143 SINGLE digest bound to the current input, using a separate `scriptCode` and preserving ANYONECANPAY. The phone makes **one** signature, covering the input-specific authorization. To delegate output choice to input B, A can use NONE after checking and committing to B’s outpoint. B can then use ALL or paired SINGLE. If A chooses ANYONECANPAY, its signature permits B’s input to be omitted. [Branch and mixed-input tests](./p2pkh-r1-universal.md)

## 5. Supply the unlocking data

The wallet obtains the direct parent transaction, unsigned child transaction, input index and requested type. It verifies the outpoint, spent output, template, permissions and owner. It should show the recipient outputs, change, fees and the fields that may change under the requested signature. Construct the applicable preimage P and invoke a hardware digest-signing API once on `SHA256(SHA256(P))`. The callback receives that 32-byte result. Passing it to a message API that hashes its input would add another hash. Return a fixed-width big-endian `r || s`. The repository entry `checked_wallet.sign_spend(tx, index, parent, requested_type, pubkey, sign_digest, history_path)` produces the unlocking script. [Checked wallet entry](../../research/secure-enclave-p256/checked_wallet.py) · [Preimage construction](../../research/secure-enclave-p256/universal.py)

| Push order, bottom to top | Value |
| --- | --- |
| 1 | Complete serialized direct parent transaction |
| 2 | Preimage P for the selected authorization path |
| 3 | Recipient’s 65-byte X9.63 public key Q |
| 4 | One 64-byte raw R1 signature with no DER wrapper or trailing signature-type byte |
| 5 | Four-byte little-endian ordinal. Use the actual input index for ordinary OTDA without ANYONECANPAY, zero otherwise |
| 6 | 32-byte little-endian `w = s⁻¹ mod n`. The lock checks range and `s·w mod n = 1` |
| 7 | `OP_0` on the ordinary path, `OP_1` on the unpaired OTDA companion path |

The ordinary OTDA path decodes the input count, checks the ordinal and verifies the current-input script marker. The shared R1 verifier has a fixed round count. No Script loop scans a variable number of transaction inputs or outputs. The wallet must retain or fetch the complete parent and budget its full size in the unlocking script. In successive spends of this template, that parent can itself contain earlier unlocking data. Use the actual parent size when estimating fees. [Universal assembly](../../research/secure-enclave-p256/universal.asm) · [Unlocking script builder](../../research/secure-enclave-p256/universal.py)

## 6. Recognize and validate the result

- **Identification.** Call `identify_locking_script(raw)` on the complete raw program of a parsed output. The zero-based v7 owner-hash range is `[437,457)`. The byte-pattern matcher captures the parameters and compares the entire fixed program. All permission opcodes must be valid, with at least one enabled. Use offsets or prefixes only to select candidates. Verify a candidate key with `matches_owner_key`. To change the payee for a new output, assemble a new instance. [Recognition](../../research/secure-enclave-p256/lock_identity.py) · [Assembly and byte patterns](../../research/secure-enclave-p256/handwritten.py)
- **Keys and nonces.** The output reveals the owner hash. Spending reveals Q. A temporary private key has no place among the template parameters. Recognition returns only the owner field and excludes the internal public binding key. Anyone can derive w from public s. The signing private key and ECDSA nonce k must remain secret. Reusing k across different digests under one key can expose the private key. The checked wallet validates the signature and records each observed r and digest before releasing the unlock. Its duplicate-r protection covers signatures that pass through this entry and share an intact history. The hardware nonce implementation remains a platform assurance question. [Wallet implementation](../../research/secure-enclave-p256/checked_wallet.py) · [RFC 6979](https://www.rfc-editor.org/rfc/rfc6979)
- **Verification evidence.** Public-key and hash inputs produce identical scripts. Invalid curve points, 32-byte scalars and unsupported permissions are rejected. Synthetic transactions cover all twelve modes, mixed inputs, both unpaired SINGLE paths and rejection of a wrong owner, parent or inverse hint. The generator revision passed 52 Python/chain-gang tests, eight isolated BSV Node 1.2.3 tests and two nChain comparisons. The native node supplies the reference result for unpaired OTDA. [CI results](https://github.com/linzhm/bsv-script-lab/actions/runs/44356580922/job/134986197432)
- **Size, performance and outstanding work.** For the earlier signature format the two-bit joint table and four-bit split tables produced 62,051 and 61,717 bytes, with million-run means of 6.7190 and 6.5925 ms respectively. v7 shares the computed digest and checks a supplied inverse, yielding 59,811 bytes. The v7 sample measured 32 local RPC calls per path at about 22 ms including RPC overhead. The next device acceptance test is to sign a fixture’s digest inside a real Secure Enclave, export the raw signature and verify the completed spend on the same offline node. Miner acceptance policy, actual fees and a deployment security review remain open. [Earlier million-run experiment](https://github.com/linzhm/bsv-script-lab/actions/runs/44342695412/job/134946778724) · [v7 measurements](https://github.com/linzhm/bsv-script-lab/actions/runs/44350574355/job/134964757191)
