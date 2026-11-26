# 钱包 SDK 快速接入

[English](README.md)

用同一套钱包接口创建和识别锁、准备签名请求，以及组装签名交易。先用原生 P2PKH 核对序列化和 secp256k1 签名，再选择其他项目验证相应的签名策略。调用通过本地 Python 3.12 桥接进程执行，使用当前检出的模板。

应用接入所选语言的通用源码包，再用项目标识选择签名方案。项目接入指南分别说明模板、签名格式和特有流程。

<a name="quickstart"></a>

## 配置原生 P2PKH

从仓库根目录运行以下命令，体验 Python 示例。

```sh
python3.12 -m venv .venv
.venv/bin/python -m pip install -r projects/p2pk-p2pkh-baseline/reference/requirements-sdk.txt ecdsa==0.19.1
.venv/bin/python -m shared.sdk.examples.receive_and_pay
```

离线示例创建并识别原生 P2PKH 锁，再签署一笔手续费为 100 聪的模拟交易，并输出模板、字节数和交易 ID。示例使用公开测试密钥，全程离线运行。`ecdsa` 包供测试签名器使用。[示例源码](examples/receive_and_pay.py)

在命令末尾加上 `p2pkh-sm2`、`lamport-ots`、`wots-plus` 或 `ml-dsa` 可体验其他签名方案。SM2 依赖见其接入指南。此示例中的 Lamport 和 WOTS+ 只需 Python 标准库。ML-DSA-44 需要 OpenSSL 3.5 或以上版本，可通过 `ML_DSA_OPENSSL` 指定。R1 和 Deferred 的交易和启用复放见下方项目指南。

TypeScript 示例需要 Node.js 24 或以上版本，Go 示例需要 Go 1.23 或以上版本，Rust 库采用 2021 版语言规范。

源码入口为 [TypeScript 的 `WalletClient`](typescript/index.ts)、[Rust 的 `WalletClient::new`](rust/Cargo.toml)、[Go 的 `NewWallet`](go/go.mod) 和 [Python 的 `WalletClient`](python/client.py)。Python 项目可以从仓库根目录运行，或把仓库加入 `PYTHONPATH`。

以下参数由钱包提供。钱包先从可信链视图确认入金输出可花费，再审批收款输出、找零和手续费。

```ts
import { resolve } from "node:path";
import { WalletClient } from "./shared/sdk/typescript/index.ts";

const config = {
  python: resolve(".venv/bin/python"),
  bridge: resolve("shared/sdk/python/bridge.py"),
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

钱包位于独立仓库时，Rust 用 `cargo add --path /path/to/bsv-script-lab/shared/sdk/rust`，Go 用 `go work use /path/to/bsv-script-lab/shared/sdk/go`。所选签名方案的 Python 运行环境通过客户端配置指定。对接异步签名设备时，TypeScript 使用 `signPaymentAsync` 或 `signInputAsync`。

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

如果桥接进程启动失败，检查 Python 解释器路径、签名方案依赖和源码目录。手续费校验在调用签名器前完成。签名校验可能在回调返回后失败，此时保留签名器状态，并按项目指南处理重试，尤其是使用一次性密钥时。

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
import sdk "github.com/linzhm/bsv-script-lab/shared/sdk/go"

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
from shared.sdk.python.client import WalletClient

wallet = WalletClient("p2pk-p2pkh-baseline", python=str(Path(".venv/bin/python").resolve()))
prevout = wallet.prevout_from_funding(funding_bytes, vout)
signed = wallet.sign_payment(
    prevout, approved_outputs, approved_fee_sats, spend_key,
    lambda request: signer.sign_secp256k1_digest_der(request.payload),
)
```

Python 接入 Lamport 或 WOTS+ 时，用 `sign_once = durable_signer(database, project, spend_key, sign_digest)` 封装摘要签名器，再传入回调 `lambda request: sign_once(request.payload)`。各钱包进程和各模板格式共用同一个数据库和规范化的公钥。[一次性签名器](../one_time_signer.py)

## 选择签名方案

| 项目 | 签名请求 | 接入指南 |
| --- | --- | --- |
| 原生 P2PK/P2PKH | secp256k1 摘要，low-S DER | [原生 SDK](../../projects/p2pk-p2pkh-baseline/docs/sdk.zh-CN.md#quickstart) |
| P2PKH-R1 | P-256 摘要或交给设备散列的消息，64 字节 `r ∥ s` | [R1 SDK](../../projects/p2pkh-r1/docs/sdk.zh-CN.md#quickstart) |
| P2PKH-R1-Deferred | 启用操作依据承诺的 R1 输出生成解锁脚本 | [Deferred SDK](../../projects/p2pkh-r1-deferred/docs/sdk.zh-CN.md#quickstart) |
| P2PKH-SM2 | SM2 消息和用户 ID，64 字节 `r ∥ s` 或 DER SignedData | [SM2 SDK](../../projects/p2pkh-sm2/docs/sdk.zh-CN.md#quickstart) |
| P2PKH-Schnorr | 32 字节 BSV 交易消息，64 字节 BIP340 签名 | [Schnorr SDK](../../projects/p2pkh-schnorr/docs/sdk.zh-CN.md#quickstart) |
| Lamport OTS | 32 字节摘要，8,192 字节签名 | [Lamport SDK](../../projects/lamport-ots/docs/sdk.zh-CN.md#quickstart) |
| WOTS+ | 32 字节摘要，2,144 字节签名 | [WOTS+ SDK](../../projects/wots-plus/docs/sdk.zh-CN.md#quickstart) |
| 纯模式 ML-DSA-44 | 32 字节消息和空上下文，2,420 字节签名 | [ML-DSA SDK](../../projects/ml-dsa/docs/sdk.zh-CN.md#quickstart) |

## 复放基线

在 Linux 上，从仓库根目录安装原生项目固定的测试依赖并复放四种语言。固定的 chain-gang 绑定和 Rust 客户端测试需要 Rust 工具链。

```sh
.venv/bin/python -m pip install -r projects/p2pk-p2pkh-baseline/reference/requirements.txt ecdsa==0.19.1
SCRIPT_LAB_SDK_PYTHON="$PWD/.venv/bin/python" \
  bash shared/verify_node.sh -- bash shared/sdk/verify_wallet.sh p2pk-p2pkh-baseline
```

复放核对四种语言生成的锁定脚本、签名请求和已签交易字节，并用显式上一输出来验证 chain-gang 和 BSV Node 的判定。签名样本可以用来核对钱包序列化。成本对照及有资金的 regtest 测量见[统一基准](../benchmark.zh-CN.md)。
