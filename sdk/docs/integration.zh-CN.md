# 接入钱包 SDK

[English](integration.md) · [SDK 首页](../README.zh-CN.md) · [接口参考](reference.zh-CN.md)

[桥接配置](#bridge-setup) · [钱包流程](#wallet-workflow) · [外部签名器](#first-payment) · [逐输入签名](#prepared-payments)

<a name="bridge-setup"></a>

## 配置本地桥接程序

TypeScript 绑定需要 Node.js 24 或更新版本，Go 模块需要 Go 1.23 或更新版本，Rust crate 使用 2021 edition。

让应用和本地桥接进程都能读取同一份 4thGraph 源码。在应用配置中解析 `sdk/python/bridge.py` 和方案所用 Python 解释器的绝对路径。语言绑定和锁定模板应取自同一提交。

| 语言 | 加载方式 |
| --- | --- |
| TypeScript | 在 Node.js 进程中导入该检出的 `sdk/typescript/index.ts`。对接异步设备时，使用 `signPaymentAsync` 或 `signInputAsync`。本地桥接进程仍同步执行。 |
| Rust | 在钱包的源码包中执行 `cargo add --path /path/to/4thGraph/sdk/rust`。 |
| Go | 在钱包模块目录中，按需用 `go work init .` 创建工作区，再运行 `go work use /path/to/4thGraph/sdk/go`。 |
| Python | 将检出目录加入 `PYTHONPATH`，从 `sdk.python.client` 导入 `WalletClient`。桥接默认使用当前解释器。 |

原生 P2PK/P2PKH、R1、Deferred R1、Schnorr 和 SM2 的 Python 环境按项目指南安装。Lamport、WOTS+ 和 ML-DSA 付款接口使用 Python 标准库。ML-DSA 的测试签名器还需要支持纯模式 ML-DSA-44 的 OpenSSL。节点和 chain-gang 复放需要另装测试依赖。复放依赖不同 chain-gang 提交的项目时，分别建 Python 环境。[各项目接入指南](../README.zh-CN.md#scheme-integrations)

将 `python` 指向已安装项目依赖的解释器，将 `bridge` 指向检出目录里的 `sdk/python/bridge.py`。以下示例使用离线上手时创建的原生付款环境。

<a name="wallet-workflow"></a>

## 从付款请求到广播

| 步骤 | 钱包负责 | SDK 调用 |
| --- | --- | --- |
| 生成收款 | 记录项目、预期公钥或所有者哈希、收款金额。按模板要求保留完整公钥字节。 | 用 `createLock` 生成写入输出的原始脚本。 |
| 确认 UTXO | 从可信链视图核对入金 txid、输出索引、金额和可花费状态。把实际输出与付款请求核对。 | `prevoutFromFunding` 解析父交易，`recognize` 按项目和预期公钥核对实际脚本。 |
| 审批交易 | 选择输入、按序确定收款与找零输出和手续费。已组装交易的手续费需要根据全部已核验的上一输出计算。 | `signPayment` 组装单输入付款，`signInput` 填写已组装交易中的一个输入。 |
| 签名授权 | 把请求发给这把密钥对应的签名器。释放签名前核对算法、签名输入类型、签名格式和 sighash。 | 客户端准备签名数据，并核验返回的签名、组装解锁。Deferred 的已承诺输入用 `activate` 启用。 |
| 广播确认 | 保存最终交易字节和 txid，按接收策略提交并跟踪确认。父交易的 outpoint 变化时，重建依赖它的子交易。 | 客户端返回完整交易供应用广播。 |

<a name="first-payment"></a>

## 接入外部签名器

以下 TypeScript 片段接入已有钱包。`receiveKeyHex` 是付款请求上的收款公钥。`fundingTxHex`、`fundingVout` 和 `spendKeyHex` 对应钱包已经核验的上一输出。`approvedOutputs` 包含找零，`approvedFeeSats` 是这笔单输入付款的总手续费。回调连接钱包的外部签名器。

```ts
import { resolve } from "node:path";
import { WalletClient } from "./sdk/typescript/index.ts";

const config = {
  python: resolve("workspace/sdk-venv/bin/python"),
  bridge: resolve("sdk/python/bridge.py"),
};
const wallet = new WalletClient("p2pk-p2pkh-baseline", config);

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

签名器返回 low-S DER 签名。SDK 验签并添加 sighash 字节，返回序列化交易。钱包按自己的审批和广播流程提交交易。初始化时加上 `template: "p2pk"`，即可用同一套接口创建 P2PK 输出。识别按实际脚本判定，两种格式都可以识别。

## Rust、Go 和 Python 调用

Rust 和 Go 的 `config` 填入与 TypeScript 相同的 Python 解释器和 bridge 绝对路径。Rust 示例里的 `approved_outputs` 为 `Vec<Output>`，Go 为 `[]sdk.Output`，Python 为 `(聪金额, 原始锁定脚本字节)` 的序列。

```rust
use bsv_script_lab_local_sdk::{WalletClient, WalletPayment, WalletSigningOptions};

let wallet = WalletClient::new("p2pk-p2pkh-baseline", config, None);
let prevout = wallet.prevout_from_funding(&funding_hex, vout)?;
let signed_hex = wallet.sign_payment(
    WalletPayment {
        prevout,
        outputs: approved_outputs,
        fee_sats: approved_fee_sats.to_string(),
        options: WalletSigningOptions { public_key: spend_key_hex, ..Default::default() },
    },
    |request| signer.sign_secp256k1_digest_der(&request.payload),
)?;
```

```go
import sdk "github.com/linzhm/4thGraph/sdk/go"

wallet := sdk.NewWallet("p2pk-p2pkh-baseline", config, "")
prevout, err := wallet.PrevoutFromFunding(ctx, fundingHex, vout)
if err != nil {
    return err
}
signedHex, err := wallet.SignPayment(ctx, sdk.WalletPayment{
    Prevout: prevout, Outputs: approvedOutputs, FeeSats: approvedFeeSats,
    WalletSigningOptions: sdk.WalletSigningOptions{PublicKey: spendKeyHex},
}, func(request sdk.SigningRequest) ([]byte, error) {
    return signer.SignSecp256k1DigestDER(request.Payload)
})
```

```python
from pathlib import Path
from sdk.python.client import WalletClient

wallet = WalletClient("p2pk-p2pkh-baseline", python=str(Path("workspace/sdk-venv/bin/python").resolve()))
prevout = wallet.prevout_from_funding(funding_bytes, vout)
signed = wallet.sign_payment(
    prevout, approved_outputs, approved_fee_sats, spend_key,
    lambda request: signer.sign_secp256k1_digest_der(request.payload),
)
```

<a name="prepared-payments"></a>

## 签署已组装交易

多输入、混合签名方案、自定义序列号或锁定时间的交易使用 `signInput`。开始时，待签输入的解锁脚本为空。每个输入按其实际上一输出选择对应的客户端和签名器。例如，R1 UTXO 和原生 P2PKH 手续费输入使用不同的客户端和签名器。R1 请求中还须填写持久化的 `historyPath`。

```ts
import { WalletClient, type WalletInput, type WalletSigner } from "./sdk/typescript/index.ts";

type ApprovedInput = {
  wallet: WalletClient;
  request: Omit<WalletInput, "transaction">;
  signer: WalletSigner;
};

export function fillApprovedInputs(transaction: string, approvedInputs: readonly ApprovedInput[]): string {
  for (const { wallet, request, signer } of approvedInputs) {
    transaction = wallet.signInput({ ...request, transaction }, signer);
  }
  return transaction;
}
```

调用前用已核验的输入金额之和减去输出金额之和，审批整笔手续费。填写解锁时，按已审批的输入输出顺序、序列号和锁定时间执行。每次调用返回的整笔交易作为下一次的输入，广播前核对每个待签输入的解锁脚本是否齐备。Deferred 先组装同索引的承诺输出并调用 `activate`，再用赞助输入自己的客户端签名。[Deferred 接入](../../projects/p2pkh-r1-deferred/docs/sdk.zh-CN.md#quickstart)

## 接口设计参考

4thGraph 每种语言提供一个源码库，通过项目标识选择付款模板。交易和模板的职责划分参考 BSV SDK，签名回调参考 BDK 将密钥交给应用管理的工作流。TypeScript 为硬件设备提供独立的异步签名方法，调用方式参考 bitcoinjs-lib。设备等待授权期间，SDK 使用调用时已审批的交易副本。[BSV 模板接口](https://hub.bsvblockchain.org/bsv-code-academy/code-features/code-features/custom-templates) · [BDK 签名流程](https://bookofbdk.com/design/signing/) · [bitcoinjs-lib 异步签名接口](https://bitcoinjs.github.io/bitcoinjs-lib/interfaces/SignerAsync.html)
