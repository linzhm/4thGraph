# Archived BN254 receipt probe

This offline experiment verifies the public upstream `TestReceiptV3_1` fixture with gnark-crypto. It reconstructs the receipt claim and the five native public inputs. Its tests exercise the exact archived proof, journal, image, key and control parameters. [Upstream fixture](https://github.com/risc0/risc0-ethereum/blob/ff30da77ba4afdd496290ebebedb205348b15d83/contracts/test/TestReceiptV3_1.sol)

Cross-curve wrapping is paused. The probe has no bridge, consensus-finality, or BSV Script integration. Source-chain deposit and release authorization follow the existing [test reserve trust model](../../../evm/README.md).

The [BSV parent checkpoint benchmark](benchmark/README.md) separately produces native RISC Zero STARK receipts and BLS12-381 Groth16 proofs for the same real BSV parent.

```sh
go test -v ./parentbinding/risczero
```
