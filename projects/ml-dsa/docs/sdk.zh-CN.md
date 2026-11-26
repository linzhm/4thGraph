# 纯模式 ML-DSA-44 钱包 SDK

[English](sdk.en.md) · [开发指南](developer.zh-CN.md#sdk) · [统一钱包接入](../../../sdk/README.zh-CN.md)

用预期的 1,312 字节公钥创建和识别锁定脚本。将 SDK 提供的 32 字节原样作为消息交给纯模式 ML-DSA-44，使用空上下文。签名为 2,420 字节。SDK 验签后再组装解锁脚本。公开夹具生成需要 OpenSSL 3.5 或以上版本。若可执行文件不在 PATH，设置 `ML_DSA_OPENSSL`。

<a name="quickstart"></a>

## 接入付款

运行时使用 Python 3.12 标准库，复放额外依赖见下方。

沿用统一接入指南的 `config` 和已审批的交易数据。生成由钱包控制的收款脚本，用同一客户端准备付款。

```ts
import { WalletClient } from "./sdk/typescript/index.ts";

const wallet = new WalletClient("ml-dsa", { ...config, template: "pure-ml-dsa-44" });
const receiveScript = wallet.createLock({ publicKey: receiveKeyHex });
const prevout = wallet.prevoutFromFunding(fundingTxHex, fundingVout);
const recognized = wallet.recognize({ script: prevout.script, publicKey: spendKeyHex });
if (!recognized) throw new Error("Funding output does not match the spending key");

const signedHex = wallet.signPayment({
  prevout,
  publicKey: spendKeyHex,
  outputs: approvedOutputs,
  feeSats: approvedFeeSats.toString(),
}, ({ payload }) => signer.signPureMlDsa44(payload, new Uint8Array()));
```

已构造的交易用 `signInput`，传入交易、本次输入索引和对应的 prevout。Rust、Go、Python 的等价入口在[调用表](../../../sdk/README.zh-CN.md#调用与数据)。

## 入金前验证签名器

创建或识别锁时，使用签名器提供的 1,312 字节原始 ML‑DSA‑44 公钥。把 SDK 提供的 32 字节原样交给纯模式 ML‑DSA‑44 签署，使用空上下文。确认签名器返回 2,420 字节的原始签名。集成测试可修改请求消息，以验证错误签名会被拒绝。

先用离线示例核对消息处理，再在两个引擎上复放付款，并按目标节点的脚本大小及验证策略独立测试有资金的花费。锁大小随公钥夹具变化，因此要用实际收款公钥测量。[入资 regtest 指南](../../../docs/benchmark.zh-CN.md)

## 复放向量

```sh
.venv/bin/python -m pip install -r tools/requirements-chronicle.txt
SCRIPT_LAB_SDK_PYTHON="$PWD/.venv/bin/python" \
  bash tools/verify_node.sh -- bash sdk/verify_wallet.sh ml-dsa
```
