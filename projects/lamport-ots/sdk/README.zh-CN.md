# Lamport OTS 钱包 SDK

[English](README.md) · [开发指南](../docs/developer.zh-CN.md#sdk) · [统一钱包接入](../../../shared/sdk/README.zh-CN.md)

收款时选择 `full-key`（默认）或 `committed-key`，识别时传入完整且顺序一致的公钥。SDK 也能识别旧版输出，其花费模式为 ForkID ALL。签名器接收 32 字节摘要，返回 8,192 字节签名。释放签名前持久记录密钥已使用。找零用新密钥，重试时保留已签交易。

## 接入付款

运行时使用 Python 3.12 标准库，复放额外依赖见下方。

沿用统一接入指南的 `config` 和已审批的交易数据。生成由钱包控制的收款脚本，用同一客户端准备付款。

```ts
import { WalletClient } from "./shared/sdk/typescript/index.ts";

const wallet = new WalletClient("lamport-ots", { ...config, template: "full-key" });
const receiveScript = wallet.createLock({ publicKey: receiveKeyHex });
const prevout = wallet.prevoutFromFunding(fundingTxHex, fundingVout);
const recognized = wallet.recognize({ script: prevout.script, publicKey: spendKeyHex });
if (!recognized) throw new Error("Funding output does not match the spending key");

const signedHex = wallet.signPayment({
  prevout,
  publicKey: spendKeyHex,
  outputs: approvedOutputs,
  feeSats: approvedFeeSats.toString(),
}, ({ payload }) => signer.signLamportOnce(keyId, payload));
```

已构造的交易用 `signInput`，传入交易、本次输入索引和对应的 prevout。Rust、Go、Python 的等价入口在[调用表](../../../shared/sdk/README.zh-CN.md#调用与数据)。

## 复放向量

```sh
.venv/bin/python -m pip install -r projects/lamport-ots/reference/requirements.txt
SCRIPT_LAB_SDK_PYTHON="$PWD/.venv/bin/python" \
  bash shared/verify_node.sh -- bash shared/sdk/verify_wallet.sh lamport-ots
```

## 原有源码入口

| 语言 | 源码与入口 |
|---|---|
| TypeScript | [index.ts](typescript/index.ts) · `createClient` |
| Rust | [Cargo.toml](rust/Cargo.toml) · `bsv_script_lab_lamport_sdk::client` |
| Go | [go.mod](go/go.mod) · `New` |
| Python | [客户端入口](python/__init__.py) · `create_client` |
