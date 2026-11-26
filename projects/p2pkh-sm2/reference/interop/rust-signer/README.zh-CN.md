# GB/T 35275-2026 Rust 测试签名器

[English](README.md) · [参考实现指南](../../README.zh-CN.md)

Rust 命令行工具使用 RustCrypto 的 `sm2` 生成 SM2/SM3 签名，并用 `der` 完成 ASN.1
编码。它生成直接签名的 `SignedData` 封装，外层版本为 `1`，内层
`SignerInfo.version = 2`，SM2 用户标识固定为 `1234567812345678`。测试夹具沿用
原有的颁发者通用名称 `Independent Go Signer` 和序列号 `1`，以便和
[Python 测试签名器](../python-signer/README.zh-CN.md) 使用同一 DER 签名者标识。

## 构建并签署测试消息

在仓库根目录执行。示例使用公开的测试密钥。

```sh
signer_dir="$PWD/projects/p2pkh-sm2/reference/interop/rust-signer"
cargo build --locked --release --manifest-path "$signer_dir/Cargo.toml" --target-dir "$signer_dir/target"
"$signer_dir/target/release/sm2-signed-data-signer" \
  -message 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
  -key 0000000000000000000000000000000000000000000000000000000000000001
```

加上 `-detached` 可生成分离封装，省略其中的消息原文。标准输出为 JSON 对象，包含
`envelope_hex`、`public_key_hex`、`signer_identifier_hex` 和 `signer_version`。
命令行工具从参数读取密钥，请使用专用测试密钥。

## 验证签名器输出

安装[参考实现依赖](../../requirements.txt)，并使用支持 SM2 和 SM3 的 OpenSSL。
在仓库根目录保留上一节定义的 `signer_dir`，运行 Rust 签名器的专项测试。

```sh
SM2_SIGNED_DATA_SIGNER="$signer_dir/target/release/sm2-signed-data-signer" \
  PYTHONPATH=src:.:projects/p2pkh-sm2/reference python -m unittest -v test_signed_data.IndependentSignedDataTests
```

运行 `bash projects/p2pkh-sm2/reference/verify.sh`，可自动构建 Rust 签名器，
再用 BSV Node 1.2.3 和 chain-gang 重放两版签名器生成的交易。
