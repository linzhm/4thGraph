# WOTS+ 钱包 SDK

[English](sdk.en.md) · [开发指南](developer.zh-CN.md#sdk) · [统一钱包接入](../../../sdk/README.zh-CN.md)

可选 `canonical`（默认）、`cached-constants` 或 `cached-steps`。识别收款脚本时提供预期的 64 字节公钥。签名器接收 32 字节摘要，返回 2,144 字节签名。释放签名前持久记录密钥已使用，找零用新密钥，重试时保留已签交易。Chronicle 已激活时，可用 `compressOtda: true` 为符合条件的版本 2 交易选择更短的解锁编码。

<a name="quickstart"></a>

## 接入付款

运行时使用 Python 3.12 标准库，复放额外依赖见下方。

沿用统一接入指南的 `config` 和已审批的交易数据。生成由钱包控制的收款脚本，用同一客户端准备付款。

```ts
import { WalletClient } from "./sdk/typescript/index.ts";

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

已构造的交易用 `signInput`，传入交易、本次输入索引和对应的 prevout。Rust、Go、Python 的等价入口在[调用表](../../../sdk/README.zh-CN.md#调用与数据)。

## 选择收款模板并演练重试

先用 `canonical` 做对照，再按预期的输入输出数量比较 `cached-constants` 和 `cached-steps`。版本 2 Chronicle 交易新建符合条件的缓存步骤输出时，可设置 `compressOtda: true` 验证重建。每个输出保留其规范编码的 64 字节公钥。[模板实测](../README.zh-CN.md#完整交易与栈测量)

签名器持久记录密钥状态，每个输出使用新密钥。广播重试时重播已保存的交易字节。不同交易需要重新授权，发起请求前先核对密钥是否已经消耗。测试应覆盖签名进程重启后，同一密钥的二次请求被阻止。[持久签名器参考实现](../../../src/fourthgraph/bsv/one_time_signer.py)

## 复放向量

```sh
.venv/bin/python -m pip install -r projects/wots-plus/reference/requirements.txt
SCRIPT_LAB_SDK_PYTHON="$PWD/.venv/bin/python" \
  bash tools/verify_node.sh -- bash sdk/verify_wallet.sh wots-plus
```
