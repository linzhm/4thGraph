# Reference implementation

The wallet uses the exact script bytes in [the canonical template](../template/template.hex). The assembler rebuilds those bytes independently from the literal blocks in [lock.asm](./asm/lock.asm). Conformance compares three owner vectors, validates three consecutive ordinary payments, and exercises the twelve paired sighash modes and four unpaired SINGLE modes. Both BSV Node and chain-gang must accept each valid complete input, including the two OTDA companion cases. This is input-level regtest validation with supplied UTXOs and explicit script flags.

Use Python 3.12 on Linux x86-64 with Git and a Rust toolchain available to build the pinned Python extension. Install the dependencies from requirements.txt before running the node comparison. It pins tx-engine to [5cb8c6e410](https://github.com/linzhm/chain-gang/commit/5cb8c6e410dbfad1c619cec3ca54d1bcaacd4eb7) from the fork's `fix/otda-complete-validation` branch. CI checks the installed Git commit before executing the full-input tests. [Conformance run](https://github.com/linzhm/bsv-script-lab/actions/runs/44392715745) The ordinary TypeScript, Rust and Go SDKs are independent of this dependency.

```sh
cd projects/p2pkh-r1/reference
python -m pip install -r requirements.txt
python generate_lock.py --owner-hash160 4ceab2c8be16c1d4c6b4147d39aa449c2d63f184
bash verify.sh
```

The regtest script downloads BSV Node 1.2.3 and checks the archive against the release checksum. It runs a local node with no peers and submits only verification RPCs. The software signer in the test uses publicly known test scalars. Integrations should supply a device callback to [wallet.py](./wallet.py). The current release draft awaits physical-device verification, independent review and relay/fee measurements.
