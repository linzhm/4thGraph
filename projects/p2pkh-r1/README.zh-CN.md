# P2PKH-R1 v0.2.0

[English](README.md) · [BSV Script Lab](../../README.zh-CN.md)

P2PKH-R1 用未压缩的 secp256r1（P-256）公钥的 HASH160 锁定 BSV 输出。付款人只需填入 20 字节收款人哈希。花费时，钱包提供公钥和当前输入的一份经校验的 64 字节 `r || s` 签名。

## 当前模板

v0.2.0 是当前开发版本。新建输出使用 [46,302 字节的固定锁](template/v0.2.0/template.hex)，[二进制布局](template/v0.2.0/layout.json)记录固定字节指纹。已有的 59,582 字节 [v0.1.0 输出](template/template.hex)仍可识别和花费。两个版本的收款人槽位都在偏移 208 至 227，也都支持 ForkID 与 Chronicle OTDA 的全部 12 种签名类型。钱包通过核对实际上一输出的固定字节识别模板。

普通付款使用 ForkID ALL（`0x41`），每个解锁为 326 字节。两进两出夹具从 v0.1.0 的 119,934 字节降到 v0.2.0 的 93,374 字节。Chronicle 激活后可以按需使用 OTDA。对版本 2 交易，参考钱包可以在 OTDA ALL 下重建可识别的输出，在配对 SINGLE 下只重建同索引输出。无配对的 SINGLE 走伴随验签。

## 钱包接入

[TypeScript、Rust 和 Go 指南](docs/sdk.zh-CN.md)介绍如何收款以及构造普通 ForkID ALL 付款。[Python 参考钱包](reference/README.md)可为每个输入选择签名类型，支持混合输入和 Chronicle OTDA。请求外部签名前，先核对入金 outpoint、金额和锁定脚本，再确认目标输出和费用。

```sh
cd projects/p2pkh-r1/reference
python -m pip install -r requirements.txt
python generate_lock.py --owner-hash160 "${R1_OWNER_HASH160:?请设置收款公钥哈希}"
bash verify.sh
```

详见[协议规范](docs/spec.zh-CN.md)、[验收矩阵](reference/acceptance.md)和[付款向量](template/v0.2.0/spend-all.json)。向量密钥是公开测试数据。独立复核和硬件设备验证仍待完成。
