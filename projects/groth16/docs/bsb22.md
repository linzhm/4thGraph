# Groth16 verifier and optional BSB22 adapter

The [base verifier](../reference/verifier.py) generates BLS12-381 Groth16 Script and the corresponding arithmetic witness. Use it directly with a plain Groth16 key and proof. A circuit's setup produces its own proving and verifying keys. [gnark proving schemes](https://docs.gnark.consensys.com/concepts/schemes_curves)

The [BSB22 adapter](../reference/bsb22.py) extends the same Script verifier for the supported gnark profile. It handles one BSB22 commitment with zero committed public indexes, the BLS12-381 short MiMC challenge, and two unsigned 128-bit public inputs. Pass the key and a typed `CommitmentRelation` to `verifier_lock`. Pass the same relation, signal pair, and typed `CommittedProof` to `verifier_fields`. `standalone_witness` pushes the public inputs for isolated tests. Spending covenants should derive the inputs from their authenticated transaction.

CCTP's fixture format and recursive statements are decoded in [its adapter](../../cctp/recursion/committed_verifier.py). The reusable adapter imports no CCTP rule, fixture, or transaction layout. Moving the implementation preserved the existing CCTP locks, witness fields, witness encodings, and recursive declaration bytes in a before-and-after comparison of 16 buffers.

The arithmetic fixture proves that two byte-sized factors have sum 16 and product 55. It uses a separately generated key and a single BSB22 commitment. Reproduce the fixture with the repository's pinned gnark toolchain. The generator creates fresh test-only parameters, so a regenerated proof has different bytes.

```sh
cd projects/cctp/recursion
GOPROXY=off GOSUMDB=off go run ../../groth16/examples/bsb22_arithmetic.go /tmp/bsb22-arithmetic.json
```

Replay the checked-in fixture without CCTP on the Python path, from the repository root.

```sh
PYTHONPATH=.:projects/groth16/reference python -m unittest -v test_bsb22_independent
```

The independent BSV Node 1.2.3 replay accepted and mined the valid proof and rejected a change to one public input. The fixture used a 943,511-byte lock and a 1,864-byte unlocking witness. The isolated node allowed the generated Script size. [Regtest record](../reference/testdata/bsb22-arithmetic-regtest-summary.json) · [Replay command](../examples/run_bsb22_regtest.py)

The [statement receipt verifier](../reference/statement_receipt.py) also composes the base verifier or optional BSB22 adapter with independent vin 1 transaction authentication. It reads two public limbs from a canonical 32-byte digest in the actual vout 1. An application such as CCTP checks that the receipt expresses its own exact transition and binds its token spend to the approved verifier UTXO. The same module validates arithmetic proof fixtures without importing CCTP. [Independent receipt tests](../reference/test_statement_receipt.py) · [CCTP split layout](../../cctp/recursion/freeze/README.md#separate-verifier-on-the-same-plain-parameters)
