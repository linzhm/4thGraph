# WOTS+ (SHA-256)

This experiment verifies a WOTS+ one-time signature in Bitcoin Script and binds
it to the current BSV transaction input. It uses the RFC 8391
`WOTSP-SHA2_256` hash chains, a 64-byte BSV public-key encoding and a
2,144-byte raw signature. The [specification](docs/spec.md) describes the encoding
and its relationship to XMSS.

Each key authorizes one signature for one UTXO. The reference wallet accepts an
external signing callback. A persistent signer must reserve and consume the key
before returning a signature, even if the spend is never broadcast or confirmed.
The reference `OneTimeSigner` enforces this rule within one process for testing.

Use `locking_script(key)` for transaction-bound tests. The detached verifier
from `locking_script(key, transaction=False)` accepts a caller-provided digest
and is only for testing the primitive. The payment lock supports the twelve
ForkID and Chronicle OTDA modes, with ForkID `ALL` (`0x41`) as the wallet default.

## Run the checks

Run from the repository root in a Python virtual environment.

```sh
python -m pip install -r projects/wots-plus/reference/requirements.txt
python -m unittest discover -s projects/wots-plus/reference -p test_wots.py -v
(cd projects/wots-plus/reference && python -m unittest -v test_node.ChainGangTests)
```

Use `bash projects/wots-plus/reference/verify.sh` for the isolated BSV Node
runner on Linux x86-64, or `bash projects/wots-plus/reference/verify_apple.sh`
with Apple Container. The complete-input checks use synthetic funds and compare
the BSV Node result with chain-gang.

For explicit Chronicle height and transaction-version regression, install the
[integrated chain-gang pin](../../shared/requirements-chronicle.txt) in a
separate environment and run from the repository root.

```sh
python -m pip install -r shared/requirements-chronicle.txt
python -m unittest discover -s projects/wots-plus/reference -p test_chronicle.py -v
```

See the [validation record](docs/validation.md) for completed checks, test
limits and the script-size comparison with Lamport OTS. The 16 reproducible
payment vectors are in [template/vectors.json](template/vectors.json).

### Lean conformance

Build the [bsv-script-lean evaluator](https://github.com/Calhooon/bsv-script-lean#try-it)
and run the same synthetic spend fixtures through its complete-input API.

```sh
python projects/wots-plus/reference/test_lean.py /path/to/bsv-script-lean/eval/bsvs
```

The runner checks the transaction gate and the selected input's Script verdict
for the sighash matrix and malformed witnesses. It also checks a ForkID `ALL`
spend at Genesis-era heights before Chronicle. This is a separate executable
specification check alongside BSV Node and chain-gang.
