# P2PKH-SM2

[BSV Script Lab](../../README.md) · Second public script project / 第二个公开脚本项目

A BSV payment template for the hash of an uncompressed curveSM2 public key. The owner authorizes the current input using a standard SM2/SM3 message signature. Bitcoin Script computes ZA and SM3, verifies the SM2 equation, and binds the approved message to the actual spending transaction through PUSHTX and native `OP_CHECKSIG`.

付款人凭收款人的 SM2 公钥哈希创建输出。收款人对当前交易签名一次，脚本验证 SM2 签名、ZA 用户标识绑定和实际交易绑定。解锁数据不携带父交易或历史签名，常规 ForkID 连续转付时，每个输入的解锁脚本保持 291 字节。

| Property | v2 |
|---|---|
| Curve and signature | curveSM2 / SM2, not ECDSA |
| Message hash | SM3 with ZA |
| Owner | HASH160 of `04 || X_BE32 || Y_BE32` |
| SM2 user ID | ASCII `1234567812345678`, fixed by this template |
| Coverage | ALL, NONE, SINGLE, each with optional ANYONECANPAY, using BIP143 or Chronicle OTDA |
| Lock / ordinary unlock | 199,777 / 291 bytes (BIP143); ordinary OTDA varies with the covered transaction data |
| Witness | preimage, public key, raw `r || s` |
| Current API | Python reference; external device/message-sign callback |

`sign_payment` uses `0x41`. Use `sign_input` to select coverage per input, including a mix of both algorithms in one transaction. Provide the target network’s Chronicle activation state when signing OTDA. An unpaired OTDA SINGLE uses a 294-byte witness and binds the owner’s authorization to the current outpoint. The wallet recognizes existing v1 outputs and spends them with `0x41`.

[中文规范](docs/spec.zh-CN.md) · [English specification](docs/spec.en.md) · [Reference and tests](reference/README.md) · [Layout](template/layout.json) · [Standard vector](template/sm2-standard.json) · [Payment vector](template/spend-all.json) · [16 sighash vectors](template/sighash-modes.json)

The Python wallet can also accept [GB/T 35275-2026 SignedData](reference/README.md#signeddata-payment-interop)
from a configured signer using the direct, single-signer payment profile.

```sh
cd projects/p2pkh-sm2/reference
python3 generate_lock.py --owner-hash160 000102030405060708090a0b0c0d0e0f10111213
python3 generate_lock.py --owner-hash160 000102030405060708090a0b0c0d0e0f10111213 --format raw > scriptPubKey.bin
```

The canonical program is reproducibly generated from source; the manifest fixes its length, owner offset, base hash and fixed-byte fingerprint. Pass `--version 1` to reproduce the [original template](template/layout-v1.json).
