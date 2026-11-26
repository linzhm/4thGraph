# P2PKH-SM2 钱包 SDK

[English](sdk.en.md) · [开发指南](developer.zh-CN.md#sdk) · [统一钱包接入](../../../sdk/README.zh-CN.md)

收款脚本可由 65 字节未压缩 SM2 公钥或 20 字节所有者哈希生成。创建新输出时，SDK 默认以 `template: "v1.0.0"` 选择锁定模板 `1`，也可用 `template: "v1.2.0"` 选用模板 `2`，或用 `template: "v1.3.0"` 选用更小的模板 `3`。识别和花费以实际的上一输出锁定脚本为准。将 32 字节交易消息和 SDK 提供的用户 ID 一起交给 SM2 签名器，返回 64 字节 `r ∥ s`。使用 GB/T 35275-2026 服务时，将 `signerIdentifier` 设为可信的 DER 颁发者与序列号十六进制，返回 SDK 请求的 DER SignedData。

使用 OTDA 时，根据实际花费环境设置 `chronicleActive`。对符合条件的版本 2 OTDA ALL 和配对 SINGLE，SDK 自动选择更短的编码，包含 ANYONECANPAY 组合。两种编码给签名器提供同样的消息和用户 ID。构建子交易时使用最终已签交易的 ID。

<a name="quickstart"></a>

## 接入付款

从仓库根目录创建 Python 3.12 虚拟环境并安装依赖。

```sh
python3.12 -m venv projects/p2pkh-sm2/workspace/venv
projects/p2pkh-sm2/workspace/venv/bin/python -m pip install -r projects/p2pkh-sm2/reference/requirements-sdk.txt
```

以下示例使用已核验的交易数据。将桥接配置中的 `python` 指向 `projects/p2pkh-sm2/workspace/venv/bin/python`，`bridge` 指向当前检出的 `sdk/python/bridge.py`。[共享接入示例](../../../sdk/docs/integration.zh-CN.md#first-payment)

```ts
import { WalletClient } from "./sdk/typescript/index.ts";

const wallet = new WalletClient("p2pkh-sm2", { ...config, template: "v1.0.0" });
const receiveScript = wallet.createLock({ publicKey: receiveKeyHex });
const prevout = wallet.prevoutFromFunding(fundingTxHex, fundingVout);
const recognized = wallet.recognize({ script: prevout.script, publicKey: spendKeyHex });
if (!recognized) throw new Error("Funding output does not match the spending key");

const signedHex = wallet.signPayment({
  prevout,
  publicKey: spendKeyHex,
  outputs: approvedOutputs,
  feeSats: approvedFeeSats.toString(),
}, ({ payload, userId }) => signer.signSm2(payload, userId!));
```

已构造的交易用 `signInput`，传入交易、本次输入索引和对应的 prevout。Rust、Go、Python 的等价入口在[调用表](../../../sdk/docs/reference.zh-CN.md#calls-and-data)。

SDK 接收 SINGLE 时要求交易具备同索引输出。Python 参考钱包也支持无配对的 OTDA 伴随编码。[参考钱包](../reference/README.zh-CN.md)

## 选择服务端的签名操作

| 服务类型 | 请求和响应 |
| --- | --- |
| 原始 SM2 | 用 SDK 给出的 SM2 用户标识签署 32 字节消息。由服务计算 SM2 的 ZA 和 SM3 输入，返回 64 字节原始签名 `r ∥ s`。 |
| GB/T 35275‑2026 SignedData | 在可信配置中绑定预期的 SM2 公钥以及 DER 颁发者与序列号，并设置 `signerIdentifier`。在 DER 封装中返回一份对请求消息的直接签名，使用 `SignedData.version = 1` 和 `SignerInfo.version = 2`。付款适配器核验后提取原始签名。 |

新服务同时提供这两种操作时，分别复放一笔原始 SM2 付款和一笔 SignedData 付款，并检查修改消息、公钥或签名者标识后会被拒绝。使用 Chronicle OTDA 时，在组装子交易前保存最终已签字节，同一签名授权的不同解锁编码会产生不同的 txid。[SignedData 接入与测试签名器](../reference/README.zh-CN.md#signeddata-付款接入)

## 复放向量

```sh
projects/p2pkh-sm2/workspace/venv/bin/python -m pip install -r projects/p2pkh-sm2/reference/requirements.txt
SCRIPT_LAB_SDK_PYTHON="$PWD/projects/p2pkh-sm2/workspace/venv/bin/python" \
  bash tools/verify_node.sh -- bash sdk/verify_wallet.sh p2pkh-sm2
```
