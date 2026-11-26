# Lamport OTS 钱包 SDK

[English](sdk.en.md) · [开发指南](developer.zh-CN.md#sdk) · [统一钱包接入](../../../sdk/README.zh-CN.md)

收款时选择 `full-key`（默认）或 `committed-key`，识别时传入完整且顺序一致的公钥。SDK 也能识别旧版输出，其花费模式为 ForkID ALL。签名器接收 32 字节摘要，返回 8,192 字节签名。释放签名前持久记录密钥已使用。找零用新密钥，重试时保留已签交易。

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

## 随付款请求保存密钥状态

记录付款请求使用 `full-key` 还是 `committed-key`，并为两者保留按序排列的公钥。这 16,384 字节有固定顺序。承诺模板在组装花费证明时会用到这些字节。钱包恢复时应同时恢复公钥和密钥消耗记录。

签名器释放 8,192 字节的签名前，先持久记录这把密钥已消耗。签名请求超时后，密钥可能已经用过。若已签交易可恢复，使用相同字节重播。新输出使用新密钥。[统一 SDK 的一次性签名接入](../../../sdk/docs/reference.zh-CN.md#one-time-signing)

## 复放向量

```sh
projects/lamport-ots/workspace/venv/bin/python -m pip install -r projects/lamport-ots/reference/requirements.txt
SCRIPT_LAB_SDK_PYTHON="$PWD/projects/lamport-ots/workspace/venv/bin/python" \
  bash tools/verify_node.sh -- bash sdk/verify_wallet.sh lamport-ots
```
