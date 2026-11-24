# Compact activation experiment

This experiment measures the cost of issuing an independent Deferred output to each recipient in a batch. From the repository root, run the following command in the [reference environment](../../README.md).

```sh
python projects/p2pkh-r1-deferred/reference/experiments/compact-activation/compare.py
```

The [experimental binder](binder.asm) replaces the two digest-to-signature conversions in the current short lock. Its three public secp256k1 keys depend on the leading byte of the digest. The choice makes the ECDSA scalar fit in 32 positive low-S bytes for every digest. The lock derives the choice from the digest. This requires no nonce search, recipient setup or extra signer. Recipient R1 authorization still occurs when spending the activated output. Each activation preserves the full face value in its paired R1 output, so a positive activation fee needs another input.

| Implementation | Lock bytes | Serialized bytes per output | Bytes for 1,000 outputs |
|---|---:|---:|---:|
| Current Deferred | 1,435 | 1,446 | 1,446,000 |
| Candidate | 635 | 646 | 646,000 |

The output totals exclude the transaction's input section, output count and other common fields. The reference tests cover both activation paths, including a subsequent R1-authorized payment. The comparison also checks the binder against an independent ECDSA implementation across all 256 leading bytes. The candidate has been checked with the project's pinned chain-gang build. A BSV Node replay and independent cryptographic review remain open. Current wallets recognize the existing template and would need to add this candidate explicitly before using it.
