# 钱包 SDK 接入指南

[English](README.md)

用同一套钱包接口创建和识别锁、准备签名请求，以及组装签名交易。先用原生 P2PKH 核对序列化和 secp256k1 签名，再选择其他项目验证相应的签名策略。调用通过本地 Python 3.12 桥接进程执行，使用当前检出的模板。

[离线上手](#quickstart) · [钱包流程](#wallet-workflow) · [已组装交易](#prepared-payments) · [选择签名方案](#scheme-integrations) · [排错与重试](#troubleshooting)

<a name="quickstart"></a>

## 配置原生 P2PKH

从仓库根目录运行以下命令，体验 Python 示例。

```sh
python3.12 -m venv .venv
.venv/bin/python -m pip install -r projects/p2pk-p2pkh-baseline/reference/requirements-sdk.txt ecdsa==0.19.1
.venv/bin/python -m sdk.examples.receive_and_pay
```

离线示例创建并识别原生 P2PKH 锁，再签署一笔手续费为 100 聪的模拟交易，并输出模板、字节数和交易 ID。示例使用公开测试密钥，全程离线运行。`ecdsa` 包供测试签名器使用。[示例源码](examples/receive_and_pay.py)

在命令末尾加上 `p2pkh-sm2`、`lamport-ots`、`wots-plus` 或 `ml-dsa` 可体验其他签名方案。SM2 依赖见其接入指南。此示例中的 Lamport 和 WOTS+ 只需 Python 标准库。ML-DSA-44 需要 OpenSSL 3.5 或以上版本，可通过 `ML_DSA_OPENSSL` 指定。R1 和 Deferred 的交易和启用复放见下方项目指南。

TypeScript 示例需要 Node.js 24 或以上版本，Go 示例需要 Go 1.23 或以上版本，Rust 库采用 2021 版语言规范。

源码入口为 [TypeScript 的 `WalletClient`](typescript/index.ts)、[Rust 的 `WalletClient::new`](rust/Cargo.toml)、[Go 的 `NewWallet`](go/go.mod) 和 [Python 的 `WalletClient`](python/client.py)。Python 项目可以从仓库根目录运行，或把仓库加入 `PYTHONPATH`。

以下 TypeScript 片段接入已有钱包。`receiveKeyHex` 是付款请求上的收款公钥。`fundingTxHex`、`fundingVout` 和 `spendKeyHex` 对应钱包已经核验的上一输出。`approvedOutputs` 包含找零，`approvedFeeSats` 是这笔单输入付款的总手续费。回调连接钱包的外部签名器。

```ts
import { resolve } from "node:path";
import { WalletClient } from "./sdk/typescript/index.ts";

const config = {
  python: resolve(".venv/bin/python"),
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

### 从独立钱包仓库接入

让应用和本地桥接进程都能读取同一份 Script Lab 源码。在应用配置中解析 `sdk/python/bridge.py` 和方案所用 Python 解释器的绝对路径。语言绑定和锁定模板应取自同一提交。

| 语言 | 加载方式 |
| --- | --- |
| TypeScript | 在 Node.js 进程中导入该检出的 `sdk/typescript/index.ts`。对接异步设备时，使用 `signPaymentAsync` 或 `signInputAsync`。本地桥接进程仍同步执行。 |
| Rust | 在钱包的源码包中执行 `cargo add --path /path/to/bsv-script-lab/sdk/rust`。 |
| Go | 在钱包模块目录中，按需用 `go work init .` 创建工作区，再运行 `go work use /path/to/bsv-script-lab/sdk/go`。 |
| Python | 将检出目录加入 `PYTHONPATH`，从 `sdk.python.client` 导入 `WalletClient`。桥接默认使用当前解释器。 |

原生 P2PK/P2PKH、R1、Deferred R1 和 SM2 的 Python 环境按项目指南安装。Lamport、WOTS+ 和 ML-DSA 付款接口使用 Python 标准库。ML-DSA 的测试签名器还需要支持纯模式 ML-DSA-44 的 OpenSSL。节点和 chain-gang 复放需要另装测试依赖。复放依赖不同 chain-gang 提交的项目时，分别建 Python 环境。[各项目接入指南](#scheme-integrations)

<a name="wallet-workflow"></a>

## 从付款请求到广播

| 步骤 | 钱包负责 | SDK 调用 |
| --- | --- | --- |
| 生成收款 | 记录项目、预期公钥或所有者哈希、收款金额。按模板要求保留完整公钥字节。 | 用 `createLock` 生成写入输出的原始脚本。 |
| 确认 UTXO | 从可信链视图核对入金 txid、输出索引、金额和可花费状态。把实际输出与付款请求核对。 | `prevoutFromFunding` 解析父交易，`recognize` 按项目和预期公钥核对实际脚本。 |
| 审批交易 | 选择输入、按序确定收款与找零输出和手续费。已组装交易的手续费需要根据全部已核验的上一输出计算。 | `signPayment` 组装单输入付款，`signInput` 填写已组装交易中的一个输入。 |
| 签名授权 | 把请求发给这把密钥对应的签名器。释放签名前核对算法、签名输入类型、签名格式和 sighash。 | 客户端准备签名数据，并核验返回的签名、组装解锁。Deferred 的已承诺输入用 `activate` 启用。 |
| 广播确认 | 保存最终交易字节和 txid，按接收策略提交并跟踪确认。父交易的 outpoint 变化时，重建依赖它的子交易。 | 客户端返回完整交易供应用广播。 |

## 接口设计参考

Script Lab 每种语言提供一个源码库，通过项目标识选择付款模板。交易和模板的职责划分参考 BSV SDK，签名回调参考 BDK 将密钥交给应用管理的工作流。TypeScript 为硬件设备提供独立的异步签名方法，调用方式参考 bitcoinjs-lib。设备等待授权期间，SDK 使用调用时已审批的交易副本。[BSV 模板接口](https://hub.bsvblockchain.org/bsv-code-academy/code-features/code-features/custom-templates) · [BDK 签名流程](https://bookofbdk.com/design/signing/) · [bitcoinjs-lib 异步签名接口](https://bitcoinjs.github.io/bitcoinjs-lib/interfaces/SignerAsync.html)

## 调用与数据

| TypeScript | Rust / Python | Go | 返回值 |
| --- | --- | --- | --- |
| `createLock` | `create_lock` | `CreateLock` | 根据公钥或受支持的 20 字节所有者哈希生成原始锁定脚本 |
| `recognize` | `recognize` | `Recognize` | 匹配的项目、模板，以及可提取的所有者或承诺信息 |
| `prevoutFromFunding` | `prevout_from_funding` | `PrevoutFromFunding` | 显示顺序的 `txid`、父交易输出索引 `vout`、聪金额 `valueSats` 和原始 `script` |
| `signPayment` | `sign_payment` | `SignPayment` | 使用已审批输出的版本 2 单输入交易，sequence 为最终值，locktime 为零 |
| `signInput` | `sign_input` | `SignInput` | 在指定 `inputIndex` 写入解锁脚本后的整笔交易 |
| `activate` | `activate` | `Activate` | 在指定 `inputIndex` 写入 Deferred 启用解锁脚本后的整笔交易 |

TypeScript、Rust、Go 用偶数长度、无前缀的十六进制传递交易、公钥和脚本，用规范的十进制字符串表示整聪。Python 用字节和整聪数值，txid 仍为显示顺序字符串。四种语言的签名回调都接收和返回二进制。识别未命中返回 `null`、`None` 或 `nil`。请求格式无效时返回错误。

钱包可以直接传入已核验的 prevout。`prevoutFromFunding` 解析入金交易并计算 txid，钱包仍需通过可信链视图核对输出存在、确认、金额和可花费状态。`signPayment` 检查输出金额加手续费是否等于输入金额。多输入交易由钱包核对所有上一输出和总手续费，再用 `signInput` 逐个填写尚未签名的输入。`prevout.vout` 始终对应父交易，`inputIndex` 始终对应本次花费交易。

普通付款默认使用 ForkID ALL（`0x41`）。`SINGLE` 需要同索引输出，选择 OTDA 时从可信链视图填写 `chronicleActive`。签名请求包含 `algorithm`、`payloadKind`（`digest` 或 `message`）、`signatureFormat`、`sighash`、`payload`，SM2 还提供 `userId`。各项目的签名方式和编码见下表。

省略重建选项即可使用所选方案的默认行为。SM2 在能缩短 OTDA 解锁脚本时自动重建。Go 的 `CompressOTDA` 为 `*bool`，用 `nil` 选择默认行为。Rust 的 `compress_otda` 为 `Option<bool>`，用 `None` 选择默认行为。要复现 SM2 的原样编码，Go 传入指向 `false` 的指针，Rust 传入 `Some(false)`，TypeScript 和 Python 传入 `false`。

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

调用前用已核验的输入金额之和减去输出金额之和，审批整笔手续费。填写解锁时，按已审批的输入输出顺序、序列号和锁定时间执行。每次调用返回的整笔交易作为下一次的输入，广播前核对每个待签输入的解锁脚本是否齐备。Deferred 先组装同索引的承诺输出并调用 `activate`，再用赞助输入自己的客户端签名。[Deferred 接入](../projects/p2pkh-r1-deferred/docs/sdk.zh-CN.md#quickstart)

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
import sdk "github.com/linzhm/bsv-script-lab/sdk/go"

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

wallet = WalletClient("p2pk-p2pkh-baseline", python=str(Path(".venv/bin/python").resolve()))
prevout = wallet.prevout_from_funding(funding_bytes, vout)
signed = wallet.sign_payment(
    prevout, approved_outputs, approved_fee_sats, spend_key,
    lambda request: signer.sign_secp256k1_digest_der(request.payload),
)
```

<a name="one-time-signing"></a>

Python 接入 Lamport 或 WOTS+ 时，用 `sign_once = durable_signer(database, project, spend_key, sign_digest)` 封装摘要签名器，再传入回调 `lambda request: sign_once(request.payload)`。各钱包进程和各模板格式共用同一个数据库和规范化的公钥。[一次性签名器](../src/fourthgraph/bsv/one_time_signer.py)

<a name="scheme-integrations"></a>

## 选择签名方案

| 项目 | 签名请求 | 接入指南 |
| --- | --- | --- |
| 原生 P2PK/P2PKH | secp256k1 摘要，low-S DER | [原生 SDK](../projects/p2pk-p2pkh-baseline/docs/sdk.zh-CN.md#quickstart) |
| P2PKH-R1 | P-256 摘要或交给设备散列的消息，64 字节 `r ∥ s` | [R1 SDK](../projects/p2pkh-r1/docs/sdk.zh-CN.md#quickstart) |
| P2PKH-R1-Deferred | 启用操作依据承诺的 R1 输出生成解锁脚本 | [Deferred SDK](../projects/p2pkh-r1-deferred/docs/sdk.zh-CN.md#quickstart) |
| P2PKH-SM2 | SM2 消息和用户 ID，64 字节 `r ∥ s` 或 DER SignedData | [SM2 SDK](../projects/p2pkh-sm2/docs/sdk.zh-CN.md#quickstart) |
| P2PKH-Schnorr | 32 字节 BSV 交易消息，64 字节 BIP340 签名 | [Schnorr SDK](../projects/p2pkh-schnorr/docs/sdk.zh-CN.md#quickstart) |
| Lamport OTS | 32 字节摘要，8,192 字节签名 | [Lamport SDK](../projects/lamport-ots/docs/sdk.zh-CN.md#quickstart) |
| WOTS+ | 32 字节摘要，2,144 字节签名 | [WOTS+ SDK](../projects/wots-plus/docs/sdk.zh-CN.md#quickstart) |
| 纯模式 ML-DSA-44 | 32 字节消息和空上下文，2,420 字节签名 | [ML-DSA SDK](../projects/ml-dsa/docs/sdk.zh-CN.md#quickstart) |

<a name="troubleshooting"></a>

## 排错与重试

| 现象 | 检查项 |
| --- | --- |
| 桥接进程启动失败 | 核对解释器和桥接脚本的绝对路径、检出的模板，以及依赖安装到了哪个解释器。用同一解释器运行离线示例。 |
| 识别未命中或准备签名失败 | 核对项目与实际上一输出的字节。已组装的交易应检查 `inputIndex`、`prevout.vout`、空解锁脚本和所选 sighash。使用 `signPayment` 时，核对输出金额加手续费是否等于输入金额。 |
| 签名器已返回，组装却失败 | 核对回调返回的是请求指定的原始字节或 DER，并核对签的是摘要还是消息。保留签名器状态，尤其要保留可能已释放签名的一次性密钥记录。 |
| 广播未被接收 | 核对入金输出是否仍可花费，并检查广播端返回的策略错误。可重播时用已保存的原始字节。使用一次性密钥时，构造替代交易前先核对已有签名状态。 |

## 复放基线

在 Linux 上，从仓库根目录安装原生项目固定的测试依赖并复放四种语言。固定的 chain-gang 绑定和 Rust 客户端测试需要 Rust 工具链。

```sh
.venv/bin/python -m pip install -r projects/p2pk-p2pkh-baseline/reference/requirements.txt ecdsa==0.19.1
SCRIPT_LAB_SDK_PYTHON="$PWD/.venv/bin/python" \
  bash tools/verify_node.sh -- bash sdk/verify_wallet.sh p2pk-p2pkh-baseline
```

复放比较四种语言生成的锁定脚本、签名请求和已签交易字节，再由 chain-gang 和 BSV Node 使用显式上一输出验证公开向量。实际入资的 regtest 还会测量指定策略下的内存池接收和出块。集成依赖转发或出块时，应执行这一步。[基准与入资 regtest 指南](../docs/benchmark.zh-CN.md)
