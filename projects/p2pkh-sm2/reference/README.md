# P2PKH-SM2 reference

Run from this directory. Python 3.12+, OpenSSL with SM2/SM3, and `ecdsa==0.19.1` are sufficient for local tests:

```sh
python3 -m pip install ecdsa==0.19.1
python3 -m unittest -v test_sm2
python3 generate_lock.py --owner-hash160 000102030405060708090a0b0c0d0e0f10111213 --format hex
```

`sm2.py` defines curve parameters, ZA, digest verification and an **explicit-nonce test-only** signer. `sm3_script.py` unrolls SM3 into ordinary Script bytecode. `asm/` contains SM2 group verification, scalar multiplication and PUSHTX. `p2pkh_sm2.py` is the wallet API. No new consensus opcode is used.

The local evaluator is a development harness. For independent complete-input validation, use Linux x86-64 with Rust, install the pinned extension, then run the mode suite and the node comparison:

```sh
python3 -m pip install -r requirements.txt
python3 -m unittest -v test_sighash
bash verify.sh
```

This checks three consecutive transfers, mixed inputs and multiple outputs, output/input mutations, invalid keys/scalars/identities, forged signing preimages, and extra witness items in both BSV Node 1.2.3 and chain-gang. The node launcher checks the downloaded archive against the release checksum and uses a temporary regtest directory with no peers. It does not broadcast transactions.

`test_sm2.py` also checks SM3 padding boundaries and fixed-prefix midstates against the host SM3 implementation, the published SM2 vector, and a real OpenSSL-generated SM2 key/signature accepted by the generated script. All fixture private scalars and nonces are public test data.

### Chronicle conformance

The v2 zero-owner script is 199,777 bytes. Its SHA-256 is `2458fd154c157eec3ad4ddd9a2411baae23f53aef417c43e296653cf0e2b5ab9`. The [16 deterministic preimages](../template/sighash-modes.json) cover all paired modes and each unpaired SINGLE variant. The tests change other inputs, individual outputs, sequences and locktime after signing. They also validate a mixed BIP143/OTDA transaction and reproduce the v1 payment txid.

For this revision, the 112 complete-input coverage cases were run through both pinned chain-gang and the BSV Node 1.2.3 script interpreter, including six malformed preimages signed by the correct SM2 test key. The latter engine also ran 48 activation cases with explicit flags for pre-Chronicle spends, post-activation spends of older outputs, and post-activation spends of new outputs. To isolate activation from the transaction version, these 48 cases all used version 1. The Node result used a native macOS build of `VerifyScript` and `TransactionSignatureChecker` on serialized transactions and UTXO values. Use `bash verify.sh` to repeat the checks through Linux regtest RPC. The native result covers script validation only.

[BSV Node source](https://github.com/bitcoin-sv/bitcoin-sv/tree/6504a3aff65ba97c0f6c80962b033e35ecbfed4b) · [chain-gang source](https://github.com/linzhm/chain-gang/tree/5cb8c6e410dbfad1c619cec3ca54d1bcaacd4eb7) · [Chronicle release](https://docs.bsvblockchain.org/network-topology/nodes/sv-node/chronicle-release)

The [standard vector](../template/sm2-standard.json), [payment vector](../template/spend-all.json), and [layout manifest](../template/layout.json) are checked in. Raw lock bytes are generated on demand and checked against the pinned manifest hash.
