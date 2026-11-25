# 原生 P2PK/P2PKH 钱包 SDK

[English](README.md) · [开发指南](../docs/developer.zh-CN.md#sdk) · [统一钱包接入](../../../shared/sdk/README.zh-CN.md)

传入 33 字节压缩 secp256k1 公钥。P2PKH 也支持用 `createLock({ ownerHash160 })` 创建输出。创建 P2PK 输出时选择 `template: "p2pk"` 并传入完整公钥。识别可匹配两种模板。签名器接收 32 字节摘要，返回 low-S DER 签名。sighash 字节由 SDK 写入。

## 接入付款

从仓库根目录创建 Python 3.12 虚拟环境并安装依赖。

```sh
python3.12 -m venv .venv
.venv/bin/python -m pip install -r projects/p2pk-p2pkh-baseline/sdk/requirements.txt
```

沿用统一接入指南的 `config` 和已审批的交易数据。生成由钱包控制的收款脚本，用同一客户端准备付款。

```ts
import { WalletClient } from "./shared/sdk/typescript/index.ts";

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

已构造的交易用 `signInput`，传入交易、本次输入索引和对应的 prevout。Rust、Go、Python 的等价入口在[调用表](../../../shared/sdk/README.zh-CN.md#调用与数据)。

## 复放向量

```sh
.venv/bin/python -m pip install -r projects/p2pk-p2pkh-baseline/reference/requirements.txt ecdsa==0.19.1
SCRIPT_LAB_SDK_PYTHON="$PWD/.venv/bin/python" \
  bash shared/verify_node.sh -- bash shared/sdk/verify_wallet.sh p2pk-p2pkh-baseline
```

## 原有源码入口

| 语言 | 源码与入口 |
|---|---|
| TypeScript | [index.ts](typescript/index.ts) · `createClient` |
| Rust | [Cargo.toml](rust/Cargo.toml) · `bsv_script_lab_native_sdk::client` |
| Go | [go.mod](go/go.mod) · `New` |
| Python | [客户端入口](python/__init__.py) · `create_client` |
