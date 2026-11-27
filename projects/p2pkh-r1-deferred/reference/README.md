# Reference implementation

Funding defaults to the fixed v0.3.0 template produced by 4thGraph's `stack` mode. The reference assembler reproduces v0.1.0 and v0.2.0. Construct the activation preimage from the authenticated funding transaction and the assembled activation transaction. Recognition returns both the short-lock version and its committed R1 version. [v0.3.0 template](../versions/v0.3.0/template.hex) · [v0.2.0 template](../versions/v0.2.0/template.hex) · [Assembly source](asm/lock.asm)

From the repository root, use Python 3.12 with Git and Rust for the pinned chain-gang dependency.

```sh
python -m pip install -r projects/p2pkh-r1-deferred/reference/requirements.txt
PYTHONPATH=src:. python projects/p2pkh-r1-deferred/reference/generate_vectors.py
PYTHONPATH=src:. python -m unittest discover -s projects/p2pkh-r1-deferred/reference -p test_deferred.py -v
```

Add `--write` to `generate_vectors.py` to regenerate the template, layout and direct and universal activation vectors. All vector keys are public test keys. To generate a lock with `generate_lock.py`, set `PYTHONPATH=src:.` and supply `--owner-hash160 HEX --value SATOSHIS`. `--public-key HEX` derives the same key hash from a full public key. Use `--format raw` for the raw lock. Supply `--script-file RAW_SCRIPT --value SATOSHIS` to recognize either funding format.

Use `--template v0.2.0` or pass `optimization=None` to the Python funding helpers to issue the assembly lock for the R1 v0.2.0 target. Add `--optimize baseline`, `--optimize safe`, or `--optimize stack` to compile the typed Forth source. The compiler adapter binds the amount and commitments and preserves both published `scriptCode` suffixes. Run `compare_forth.py --output-dir DIRECTORY` to emit the comparison locks. [Typed Forth source](../forth/deferred-activation.fth) · [Compiler adapter](forth_lock.py) · [Comparison report](../versions/v0.3.0/forth-results.json)

Call `funding_output_from_owner_hash` or `funding_output` when creating the short output and `recognize` when accepting it. Call `activate_input(tx, index, funding_raw, sighash=0x43)` for each input of a fully built activation transaction. Select a BIP143 or an available Chronicle OTDA mode per input. Keep any sponsor's signing and the recipient's later R1 signing in the applicable wallet or external signer.

Use `bash projects/p2pkh-r1-deferred/reference/verify.sh` on Linux x86-64 for the BSV Node 1.2.3 replay. The shared entry point verifies the release checksum, launches an isolated regtest node and checks inputs through `verifyscript` with explicit previous outputs. The [activation acceptance matrix](acceptance.md) records the complete finite domain and the observed results. Miner admission requires separate evidence.
