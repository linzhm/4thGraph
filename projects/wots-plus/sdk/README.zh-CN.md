# WOTS+ 钱包 SDK

[English](README.md) · [开发指南](../docs/developer.zh-CN.md#sdk) · [统一钱包接入](../../../shared/sdk/README.zh-CN.md)

可选 `canonical`（默认）、`cached-constants` 或 `cached-steps`。识别收款脚本时提供预期的 64 字节公钥。签名器接收 32 字节摘要，返回 2,144 字节签名。释放签名前持久记录密钥已使用，找零用新密钥，重试时保留已签交易。Chronicle 已激活时，可用 `compressOtda: true` 为符合条件的版本 2 交易选择更短的解锁编码。

## 接入付款

运行时使用 Python 3.12 标准库，复放额外依赖见下方。

沿用统一接入指南的 `config` 和已审批的交易数据。生成由钱包控制的收款脚本，用同一客户端准备付款。

```ts
import { WalletClient } from "./shared/sdk/typescript/index.ts";

const wallet = new WalletClient("wots-plus", { ...config, template: "cached-steps" });
const receiveScript = wallet.createLock({ publicKey: receiveKeyHex });
const prevout = wallet.prevoutFromFunding(fundingTxHex, fundingVout);
const recognized = wallet.recognize({ script: prevout.script, publicKey: spendKeyHex });
if (!recognized) throw new Error("Funding output does not match the spending key");

const signedHex = wallet.signPayment({
  prevout,
  publicKey: spendKeyHex,
  outputs: approvedOutputs,
  feeSats: approvedFeeSats.toString(),
}, ({ payload }) => signer.signWotsOnce(keyId, payload));
```

已构造的交易用 `signInput`，传入交易、本次输入索引和对应的 prevout。Rust、Go、Python 的等价入口在[调用表](../../../shared/sdk/README.zh-CN.md#调用与数据)。

## 复放向量

```sh
.venv/bin/python -m pip install -r projects/wots-plus/reference/requirements.txt
SCRIPT_LAB_SDK_PYTHON="$PWD/.venv/bin/python" \
  bash shared/verify_node.sh -- bash shared/sdk/verify_wallet.sh wots-plus
```

## 原有源码入口

| 语言 | 源码与入口 |
|---|---|
| TypeScript | [index.ts](typescript/index.ts) · `createClient` |
| Rust | [Cargo.toml](rust/Cargo.toml) · `bsv_script_lab_wots_sdk::client` |
| Go | [go.mod](go/go.mod) · `New` |
| Python | [客户端入口](python/__init__.py) · `create_client` |
