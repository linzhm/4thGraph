# GB/T 35275-2026 Python 测试签名器

[English](README.md) · [参考实现指南](../../README.zh-CN.md)

Python 命令行工具使用支持 SM2 和 SM3 的 OpenSSL 3 生成签名，再用 `asn1crypto`
编码为 DER。它生成直接签名的 `SignedData` 封装，外层版本为 `1`，内层
`SignerInfo.version = 2`，SM2 用户标识固定为 `1234567812345678`。命令行参数、
JSON 字段和 DER 签名者标识均与 [Rust 测试签名器](../rust-signer/README.zh-CN.md) 一致。

## 签署测试消息

请在本目录使用 Python 3.12 或以上版本执行。示例使用公开的测试密钥。

```sh
python3 -m pip install asn1crypto==1.5.1
python3 sm2_signed_data_signer.py \
  -message 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
  -key 0000000000000000000000000000000000000000000000000000000000000001
```

加上 `-detached` 可生成分离封装，省略其中的消息原文。标准输出为 JSON 对象，包含
`envelope_hex`、`public_key_hex`、`signer_identifier_hex` 和 `signer_version`。

请使用专用测试密钥。命令行工具从参数读取密钥，并将它写入仅当前用户可访问的临时目录，
供 OpenSSL 使用。签名结束后，Python 会删除该目录。

## 验证签名器输出

在仓库根目录安装[参考实现依赖](../../requirements.txt)，运行 Python 签名器的专项测试。

```sh
PYTHONPATH=src:.:projects/p2pkh-sm2/reference \
  python -m unittest -v test_signed_data.PythonSignedDataSignerTests
```

运行 `bash projects/p2pkh-sm2/reference/verify.sh`，可用 BSV Node 1.2.3 和
chain-gang 重放两版签名器生成的交易。
