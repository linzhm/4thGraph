# Lamport OTS 钱包 SDK

[English](sdk.en.md) · [开发指南](developer.zh-CN.md#sdk) · [统一钱包接入](../../../sdk/README.zh-CN.md)

收款时可选择 `full-key`（默认）、`committed-key` 或两个实验模板 `committed-key-forth` 和 `committed-key-forth-compact`。识别时传入完整有序公钥。SDK 也能识别旧版输出，其花费模式为 BIP143 ALL。[模板与交易成本](../README.zh-CN.md#选择付款模板)

显式选择 `committed-key-forth-v0.2.0` 可创建 6,525 字节的候选锁。SDK 从完整有序公钥计算承诺并填入固定模板。[固定布局](../versions/v0.2.0/layout.json)

<a name="quickstart"></a>

## 接入付款

运行时使用 Python 3.12 标准库，复放额外依赖见下方。

在仓库根目录为桥接程序创建 Python 环境。

```sh
python3.12 -m venv projects/lamport-ots/workspace/venv
```

以下示例使用已核验的交易数据。将桥接配置中的 `python` 指向 `projects/lamport-ots/workspace/venv/bin/python`，`bridge` 指向当前检出的 `sdk/python/bridge.py`。[共享接入示例](../../../sdk/docs/integration.zh-CN.md#first-payment)

```ts
import { WalletClient } from "./sdk/typescript/index.ts";

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

已构造的交易用 `signInput`，传入交易、本次输入索引和对应的 prevout。Rust、Go、Python 的等价入口在[调用表](../../../sdk/docs/reference.zh-CN.md#calls-and-data)。

## 固定重量候选

通过 `WalletClient("lamport-ots", …)` 的 `template: "committed-key-forth-subset"` 选项显式启用候选模板，并提供独立生成的固定重量公钥。回调收到 `algorithm: "lamport-ots-subset"` 和 32 字节摘要，返回 4,096 字节原始签名。钱包用 11,264 字节公钥验证签名并组装 11,264 字节证明。付款请求要保存具体模板和完整有序公钥。用 `compressOtda: true` 显式开启适用的版本 2 OTDA 原文重建。[密钥和证明格式](subset.zh-CN.md)

## 重建 OTDA 签名原文

确认 Chronicle 花费环境后，在签名请求里设置 `chronicleActive: true`、`compressOtda: true` 和 `0x61` 等 OTDA sighash。Python 使用 `compress_otda=True`，Go 使用 `CompressOTDA`。v2 交易中，OTDA ALL 或有配对的 OTDA SINGLE 可重建其覆盖的紧凑 Forth、v0.2.0 和固定重量输出，含 ANYONECANPAY。一个见证可使用多种模板字典。钱包选用最短编码，传给签名器的摘要与原样编码相同。[编码及测量（英文）](optimization.md#otda-unlocking-reconstruction)

## 随付款请求保存密钥状态

记录付款请求使用的具体模板，并保留完整的有序公钥，经典 Lamport 公钥为 16,384 字节。承诺模板需要用公钥组装花费证明。钱包恢复时同时恢复公钥和密钥消耗记录。

签名器释放首次签名前，先持久记录这把密钥已消耗。签名请求超时后，密钥可能已经用过。若已签交易可恢复，使用相同字节重播。新输出使用新密钥。[统一 SDK 的一次性签名接入](../../../sdk/docs/reference.zh-CN.md#one-time-signing)

## 复放向量

```sh
projects/lamport-ots/workspace/venv/bin/python -m pip install -r projects/lamport-ots/reference/requirements.txt
SCRIPT_LAB_SDK_PYTHON="$PWD/projects/lamport-ots/workspace/venv/bin/python" \
  bash tools/verify_node.sh -- bash sdk/verify_wallet.sh lamport-ots
```
