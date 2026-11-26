# Reference implementation

The reference assembler builds the exact [v0.2.0 short lock](../template/v0.2.0/template.hex) from [lock.asm](asm/lock.asm) and the existing R1 PUSHTX blocks. The short lock's activation preimage is built from the authenticated funding transaction and an already arranged transaction. New short locks commit to R1 v0.2.0. Recognition returns the committed R1 version for either existing v0.1.0 or v0.2.0 outputs.

From the repository root, use Python 3.12 with Git and Rust for the pinned chain-gang dependency.

```sh
python -m pip install -r projects/p2pkh-r1-deferred/reference/requirements.txt
PYTHONPATH=src:. python projects/p2pkh-r1-deferred/reference/generate_vectors.py
PYTHONPATH=src:. python -m unittest discover -s projects/p2pkh-r1-deferred/reference -p test_deferred.py -v
```

Add `--write` to `generate_vectors.py` to regenerate the template, layout and direct and universal activation vectors. All vector keys are public test keys. To generate a lock with `generate_lock.py`, set `PYTHONPATH=src:.` and supply `--owner-hash160 HEX --value SATOSHIS`. `--public-key HEX` derives the same key hash from a full public key. Use `--format raw` for the raw lock. Supply `--script-file RAW_SCRIPT --value SATOSHIS` to recognize either funding format.

Call `funding_output_from_owner_hash` or `funding_output` when creating the short output and `recognize` when accepting it. Call `activate_input(tx, index, funding_raw, sighash=0x43)` for each input of a fully built activation transaction. Select a ForkID or an available Chronicle OTDA mode per input. Keep any sponsor's signing and the recipient's later R1 signing in the applicable wallet or external signer.

Use `bash projects/p2pkh-r1-deferred/reference/verify.sh` on Linux x86-64 for the BSV Node 1.2.3 replay. The shared entry point verifies the release checksum, launches an isolated regtest node and checks inputs through `verifyscript` with explicit previous outputs. The [activation acceptance matrix](acceptance.md) records the complete finite domain and the observed results. Miner admission requires separate evidence.
