# 原生 P2PK/P2PKH 钱包 SDK

[English](sdk.en.md) · [开发指南](developer.zh-CN.md#sdk) · [统一钱包接入](../../../sdk/README.zh-CN.md)

传入 33 字节压缩 secp256k1 公钥。P2PKH 也支持用 `createLock({ ownerHash160 })` 创建输出。创建 P2PK 输出时选择 `template: "p2pk"` 并传入完整公钥。识别可匹配两种模板。签名器接收 32 字节摘要，返回 low-S DER 签名。sighash 字节由 SDK 写入。

<a name="quickstart"></a>

## 接入付款

从仓库根目录创建 Python 3.12 虚拟环境并安装依赖。

```sh
python3.12 -m venv .venv
.venv/bin/python -m pip install -r projects/p2pk-p2pkh-baseline/reference/requirements-sdk.txt
```

沿用统一接入指南的 `config` 和已审批的交易数据。生成由钱包控制的收款脚本，用同一客户端准备付款。

```ts
import { WalletClient } from "./sdk/typescript/index.ts";

const wallet = new WalletClient("p2pk-p2pkh-baseline", { ...config, template: "p2pkh" });
const receiveScript = wallet.createLock({ publicKey: receiveKeyHex });
const prevout = wallet.prevoutFromFunding(fundingTxHex, fundingVout);
const recognized = wallet.recognize({ script: prevout.script, publicKey: spendKeyHex });
if (!recognized) throw new Error("Funding output does not match the spending key");

const signedHex = wallet.signPayment({
  prevout,
  publicKey: spendKeyHex,
  outputs: approvedOutputs,
  feeSats: approvedFeeSats.toString(),
}, ({ payload }) => signer.signSecp256k1DigestDer(payload));
```

已构造的交易用 `signInput`，传入交易、本次输入索引和对应的 prevout。Rust、Go、Python 的等价入口在[调用表](../../../sdk/README.zh-CN.md#调用与数据)。

## 核对签名器和模板

- 先跑原生 P2PKH 离线示例。在钱包的复放中，先比较锁和签名请求，再比较最终的交易字节。
- 用接收预先计算摘要的 secp256k1 接口签署这 32 字节。如果设备返回定长的 `r ∥ s`，先转换为低 S 的 DER 编码，再交回 SDK。sighash 字节由客户端添加。
- 回归测试可分别覆盖按所有者哈希生成的 P2PKH 输出，以及按完整压缩公钥生成的 P2PK 输出。确认两类输出用不同的花费公钥都会识别失败。

[离线上手](../../../sdk/README.zh-CN.md#quickstart)

## 复放向量

```sh
.venv/bin/python -m pip install -r projects/p2pk-p2pkh-baseline/reference/requirements.txt ecdsa==0.19.1
SCRIPT_LAB_SDK_PYTHON="$PWD/.venv/bin/python" \
  bash tools/verify_node.sh -- bash sdk/verify_wallet.sh p2pk-p2pkh-baseline
```
