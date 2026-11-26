# Comparison with the sCrypt Schnorr verifier

[简体中文](scrypt-comparison.zh-CN.md) · [Project README](../README.md)

The 2021 article illustrates a witness-assisted approach. Its archived contract calls `isMul` three times with off-chain point multiplication data. Each auxiliary array group declares 512 points and 510 slopes, giving 4,602 integer fields across the three groups before the other arguments. The companion article's roughly 400-byte figure describes the check for one point addition. These historical figures come from the source. [Schnorr article](https://scryptplatform.medium.com/schnorr-signatures-on-bitcoin-397ca51d8bda) · [Archived contract](https://github.com/sCrypt-Inc/boilerplate/blob/2284e11c9aa22faccd266d85a992e8a91a5b70f3/contracts/schnorr.scrypt) · [Archived arithmetic](https://github.com/sCrypt-Inc/boilerplate/blob/2284e11c9aa22faccd266d85a992e8a91a5b70f3/contracts/ec.scrypt) · [Point arithmetic article](https://scryptplatform.medium.com/efficient-elliptic-curve-point-addition-and-multiplication-in-scrypt-script-f7e143a752e2)

The article's link now points to `legacy`. At the pinned revision, the contract computes `sG = R + eP` using affine point arithmetic and modular inversions. It has separate generator and variable-base multipliers. The challenge is untagged `SHA256(r || P || m)` reduced modulo the group order, with `P` encoded as a 65-byte uncompressed SEC1 key. The witness supplies both coordinates of `R`. [Pinned contract](https://github.com/sCrypt-Inc/boilerplate/blob/7b2cd79d005b2fcdc3c992d039efd619fb47abf7/contracts/schnorr.scrypt) · [Point arithmetic](https://github.com/sCrypt-Inc/boilerplate/blob/7b2cd79d005b2fcdc3c992d039efd619fb47abf7/contracts/ec.scrypt#L80-L153)

Script Lab uses the BIP340 tagged challenge, a 32-byte x-only public key, and two y-coordinate witnesses whose curve membership and parity the script checks. It computes `sG − eP` as a two-bit joint multiplication with shared doubling steps. It uses homogeneous projective coordinates and checks the result against `R` without a field inversion. [BIP340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) · [Script generator](../reference/schnorr_script.py)

## Standalone verifier replay

Each verifier receives a signature in its own format over the 32-byte message and public-key x-coordinate from official BIP340 vector 0. All three builds use synthetic one-input spends with explicit prevouts and pass BSV Node 1.2.3 `verifyscript` under the repository's raised script limits and the pinned chain-gang evaluator. The figures count serialized script bytes, including witness push opcodes. `scryptlib` 2.1.36's local interpreter reports `SCRIPT_ERR_SCRIPT_SIZE` on the default legacy build with its default flags. [BIP340 vectors](../template/bip340-vectors.csv) · [Runner](../reference/compare_scrypt.py) · [Isolated regtest](../../../tools/verify_node.sh)

| Verifier | Lock bytes | Witness bytes | Combined script bytes | chain-gang median | BSV Node RPC median |
| --- | ---: | ---: | ---: | ---: | ---: |
| sCrypt `legacy`, default build | 2,248,962 | 231 | 2,249,193 | 195.2 ms | 731.3 ms |
| sCrypt `legacy`, `scryptc --asm -O` | 2,178,125 | 231 | 2,178,356 | 200.5 ms | 699.7 ms |
| Script Lab BIP340 | 29,415 | 197 | 29,612 | 3.1 ms | 13.2 ms |

Timings are medians from 15 replays per engine after one warmup on an Intel Xeon Platinum 8370C Linux host. They include input preparation and verification. The BSV Node measurements also include loopback RPC.

The Script Lab verifier uses 98.6% fewer combined script bytes than the optimized legacy build in this fixture. Each verifier uses its own signature format. The 30,398-byte P2PKH-Schnorr payment lock also checks ownership and binds the preimage to the current input. [Payment measurements](../README.md#measured-sizes) · [Payment specification](spec.en.md)

## Compiler optimization and byte bound

The pinned compiler's `-O` applies to its ASM output. The runner assembles that output and replays it with the original witness. It first checks that assembling the default ASM output reproduces the default hex artifact byte for byte. The optimized lock saves 70,837 bytes (3.15%).

Both sCrypt builds contain 769 nonoverlapping copies of the 2,544-byte `modInverseBranchlessP` body, starting at opcode boundaries. That accounts for **1,956,336 bytes**, or about 89.8% of the optimized lock. Any binary retaining those 769 intact copies has a lower bound of 1,956,336 bytes for its lock. This bound allows arbitrary improvements to the rest of the script. It applies only while the count and encoding of those copies are preserved. [Pinned inversion routine](https://github.com/sCrypt-Inc/boilerplate/blob/7b2cd79d005b2fcdc3c992d039efd619fb47abf7/contracts/ec.scrypt#L61-L66) · [Byte count implementation](../reference/comparison/scrypt_legacy.cjs)

Even if a rewrite uses a different inversion routine, retaining 769 disjoint inline inversions leaves an average budget of less than 39 bytes per inversion to fit in the Script Lab verifier's 29,415 bytes, before accounting for everything else. Porting joint projective multiplication to sCrypt removes that assumption, as the comparison below shows.

## BIP340 with a common witness

Both implementations use BIP340 tagged hashing, x-only key rules, and the same five witness fields. The high-level sCrypt port uses a one-bit joint loop and complete homogeneous point addition. Script Lab uses an endomorphism split and 64 two-bit windows. The runner gives both sCrypt builds the common three-byte stack-depth guard. [sCrypt source](../reference/comparison/bip340.scrypt) · [Matched runner](../reference/compare_bip340.py)

| BIP340 verifier | Lock bytes | Witness bytes | Peak stack payload | chain-gang median | BSV Node RPC median |
| --- | ---: | ---: | ---: | ---: | ---: |
| High-level sCrypt, default | 131,479 | 197 | 2,235 B | 9.0 ms | 53.0 ms |
| High-level sCrypt, `--asm -O` | 122,710 | 197 | 2,235 B | 8.7 ms | 56.2 ms |
| Script Lab | 29,415 | 197 | 3,290 B | 3.2 ms | 13.0 ms |

All three builds accept the same nine valid BIP340 vectors and reject all ten invalid vectors plus eight malformed witness cases on both engines. The local tests also regenerate the eight published signatures that include private keys. The stack figures are development evaluator peaks for the same official vector 0, counting the data payload on both stacks. Timing uses 15 replays after one warmup on the same host as the legacy comparison.

The Forth verifier uses 93,295 fewer bytes than the optimized sCrypt port in this fixture. Its point table contributes to a higher peak stack payload. For on-chain payment and two-party costs, see the measured comparison with native multisig. [MuSig2 and native CHECKMULTISIG](threshold-comparison.en.md)

## Reproduce

Run from the repository root after setting up the [project Python environment](../README.md#validate-the-baseline). The replay was tested with Node.js 22. The compiler and BSV Node binaries are for Linux x86-64. The runner checks the upstream source revision and compiler SHA-256.

```sh
scratch=$(mktemp -d)
git clone --no-checkout https://github.com/sCrypt-Inc/boilerplate.git "$scratch/boilerplate"
git -C "$scratch/boilerplate" checkout --detach 7b2cd79d005b2fcdc3c992d039efd619fb47abf7
npm --prefix "$scratch/boilerplate" ci --ignore-scripts --no-audit --no-fund
gh release download v1.19.1 --repo sCrypt-Inc/compiler_dist \
  --pattern 'scryptc-1.19.1-Linux-x86_64' --dir "$scratch"
chmod +x "$scratch/scryptc-1.19.1-Linux-x86_64"
export SCRYPTC="$scratch/scryptc-1.19.1-Linux-x86_64" GHCRTS=-N2
PYTHONPATH=src:. bash tools/verify_node.sh -- \
  projects/p2pkh-schnorr/workspace/p2pkh-schnorr/bin/python projects/p2pkh-schnorr/reference/compare_scrypt.py \
  "$scratch/boilerplate" --compiler-study --samples 15
PYTHONPATH=src:. bash tools/verify_node.sh -- \
  projects/p2pkh-schnorr/workspace/p2pkh-schnorr/bin/python projects/p2pkh-schnorr/reference/compare_bip340.py \
  --compiler "$SCRYPTC" --samples 15
```
