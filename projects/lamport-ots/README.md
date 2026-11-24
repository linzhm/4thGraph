# Lamport OTS (SHA-256)

Experimental, directly unrolled 256-bit Lamport one-time signatures in BSV Script.
Includes secure random key generation, digest signing/verification, an in-memory
one-use signing guard, complete transaction construction, and independent engine tests.

**实验项目，不是已审计钱包。每组密钥只能签名一次，且只能用于一个 UTXO。**
`OneTimeSigner` only prevents reuse of the same object in one process. It does not
protect copied keys, process restarts, backups, rollback, or duplicate funding.

## Two explicitly different verifiers

- `locking_script(key, transaction=False)` checks a supplied 32-byte digest only.
  **Never fund this script**: an observer can replay the proof into another spend.
- `locking_script(key)` additionally binds the authorized digest to the current
  input using fixed-r PUSHTX. It supports ForkID BIP143 and Chronicle OTDA
  ALL, NONE and SINGLE, each with optional ANYONECANPAY. The wallet default
  is ForkID ALL (`0x41`). Production signing uses an external callback.

The hash-based signature is a post-quantum research building block. The complete
payment construction needs its own security analysis: [binding and one-time
boundaries](docs/security.md). We do not claim an audited end-to-end PQ payment
system or a standardized “256-bit quantum security” level.

## Measured bytes

| Item | Bytes |
|---|---:|
| Secret key / public key | 16,384 each |
| Signature | 8,192 |
| Digest-only locking script, including public key | 21,876 |
| Universal locking script, including public key | 22,780 |
| Non-key portion of transaction lock, including push headers | 6,396 |
| Ordinary BIP143 unlocking script | 8,357 |
| Unpaired OTDA SINGLE unlocking script | 8,361 |
| Lock + ordinary BIP143 unlock | 31,137 |

The universal BIP143 ALL path totals 30.41 KiB. The original two-push
ForkID ALL lock and vector remain available. OTDA ordinary witness size
varies with the serialized transaction. Full measurements are in
[measurement.json](template/measurement.json).

## Run

From repository root:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r projects/lamport-ots/reference/requirements.txt
python -m unittest discover -s projects/lamport-ots/reference -p test_lamport.py -v
python projects/lamport-ots/reference/measure.py --benchmark
# macOS, Apple Container (no Docker daemon):
bash projects/lamport-ots/reference/verify_apple.sh
# Linux / CI, isolated downloaded BSV Node 1.2.3:
bash projects/lamport-ots/reference/verify.sh
```

[Validation receipt](docs/validation.md) · [Protocol and layout](docs/spec.md) · [Reference usage](reference/README.md) ·
[Original ALL vector](template/vector.json) ·
[Universal sighash vectors](template/universal-vectors.json)
