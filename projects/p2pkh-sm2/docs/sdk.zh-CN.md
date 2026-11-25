# P2PKH-SM2 钱包 SDK

[English](sdk.en.md) · [开发指南](developer.zh-CN.md#sdk) · [统一钱包接入](../../../shared/sdk/README.zh-CN.md)

v1.0.0 收款脚本可由 65 字节未压缩 SM2 公钥或 20 字节所有者哈希生成。将 32 字节交易消息和 SDK 提供的用户 ID 一起交给 SM2 签名器，返回 64 字节 `r ∥ s`。使用 GB/T 35275-2026 服务时，将 `signerIdentifier` 设为经信任的 DER 颁发者与序列号十六进制，返回 SDK 请求的 DER SignedData。Chronicle 已激活时，可用 `compressOtda: true` 为符合条件的版本 2 OTDA ALL 和配对 SINGLE 启用构造器，包含 ANYONECANPAY 组合。签名器契约相同。

<a name="quickstart"></a>

## 接入付款

从仓库根目录创建 Python 3.12 虚拟环境并安装依赖。

```sh
python3.12 -m venv .venv
.venv/bin/python -m pip install -r projects/p2pkh-sm2/reference/requirements-sdk.txt
```

沿用统一接入指南的 `config` 和已审批的交易数据。生成由钱包控制的收款脚本，用同一客户端准备付款。

```ts
import { WalletClient } from "./shared/sdk/typescript/index.ts";

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

已构造的交易用 `signInput`，传入交易、本次输入索引和对应的 prevout。Rust、Go、Python 的等价入口在[调用表](../../../shared/sdk/README.zh-CN.md#调用与数据)。

## 复放向量

```sh
.venv/bin/python -m pip install -r projects/p2pkh-sm2/reference/requirements.txt
SCRIPT_LAB_SDK_PYTHON="$PWD/.venv/bin/python" \
  bash shared/verify_node.sh -- bash shared/sdk/verify_wallet.sh p2pkh-sm2
```
