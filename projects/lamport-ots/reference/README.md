# Reference implementation

Python 3.12+; production primitive code uses only the standard library. Script
serialization and transaction helpers are under the repository's `shared/` folder.
Independent tests use the pinned chain-gang commit and BSV Node 1.2.3.
Install tx-engine from requirements.txt so the test adapter can verify its
Git revision. Negative cases require a known script rejection or the expected
prevout error for a deliberately invalid outpoint.

- `lamport.py`: random key generation, strict digest API, process-local one-time guard.
- `script.py`: deterministic unrolled verifier and fixed-r PUSHTX binding.
- `payment.py`: prepared-input and single-input wallet APIs, external signer, fresh-change guard.
- `fixtures.py`: public deterministic secrets for tests only, adversarial case matrix.
- `engines.py`: development ECDSA callback and complete-transaction chain-gang adapter.
- `test_lamport.py`: unit, adversarial and differential tests; no node required.
- `test_node.py`: required node conformance (not silently skipped when absent).
- `measure.py`: reproducible vector and local benchmark.
- `verify_apple.sh`: Apple Container on macOS, pinned official node image, automatic cleanup.
- `verify.sh`: repository's Linux/CI node launcher; no container runtime required.

Run commands are in the [project README](../README.md). To export exact script
bytes for your **public test key**, from repository root:

```sh
.venv/bin/python - <<'PY'
import sys
from pathlib import Path
sys.path.insert(0, 'projects/lamport-ots/reference')
from fixtures import fixture
Path('/tmp/lamport-test-lock.bin').write_bytes(fixture()[2])
PY
```

The vectors use public test keys. Regenerate both with `measure.py --write-vector`.
The original ALL vector stores full public key and signature bytes. The universal
vectors record preimages and lock/unlock fingerprints for every supported mode,
including the unpaired SINGLE paths.

Use `sign_payment(funding_raw, vout, outputs, fee, public_key, signer)` for an
ordinary single-input payment. Use
`sign_spend(tx, input_index, funding_raw, public_key, signer, sighash=...)`
for a prepared transaction. Each API accepts `signer(digest32) -> signature8192`
and returns a signed transaction. The callback is invoked once after preflight.
Before calling the signer for a child payment, verify the parent has reached
the required confirmation depth and use the verified, unspent outpoint. Approve
the transaction and sighash. Keep private keys and durable one-use state in
the signer. If a version under a different txid confirms after signature
disclosure, keep the key marked consumed. Any recovery spend must use an
independent path available in the existing lock.
[Recovering a child payment](../docs/security.md#recovering-a-child-payment)

Apple Container uses host RPC port 18449 by default; set `LAMPORT_RPC_PORT` if
occupied. Its node has no peers and is removed after testing. The Linux launcher
defaults to port 18443 and accepts `REGTEST_RPC_PORT` for concurrent runs. It verifies
the release archive against a repository-pinned SHA-256 digest before extraction.
