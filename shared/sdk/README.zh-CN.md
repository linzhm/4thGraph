# 钱包 SDK 的本地调用方式

[English](README.md)

TypeScript、Rust、Go 和 Python 源码 SDK 通过短生命周期的本地 Python 进程复用各项目的参考钱包。配置 `shared/sdk/python/bridge.py` 的绝对路径和该项目的 Python 3.12 解释器，并让解释器能读取同一仓库里的模板文件。TypeScript 使用 Node.js 24 或以上版本，Go 使用 1.23 或以上版本，Rust 使用 2021 版语言规范。

## 钱包工作流

1. 用 `lock` 生成锁定脚本。原生 P2PKH 和 SM2 也可直接用 20 字节收款哈希。用 `recognize` 核对收款的原始锁定字节。哈希签名和 ML-DSA 需要提供预期公钥，由 SDK 重建脚本。
2. 审批收款、找零、手续费和签名类型。单输入付款传入原始入金交易、输出索引、有序的新输出和手续费。已准备好的交易传入原始交易和本次输入索引。钱包负责从可信链视图认证上一输出。
3. 提供调用方自己的签名回调。SDK 准备签名参数，调用签名器一次，再用同一份付款意图核验签名并写入解锁脚本。回调返回签名字节。SM2 回调还接收用户标识。本地进程接收签名和公开交易数据。
4. 核对返回的已签交易，再交给钱包自己的广播流程。

TypeScript 从项目的 `sdk/typescript/index.ts` 导入 `createClient`。Go 使用项目的 `sdk/go` 模块及 `New`，Rust 使用项目的 `sdk/rust` 库及 `client`。Python 在仓库位于 `PYTHONPATH` 时从 `shared.sdk.python.client` 导入 `Client`。

TypeScript、Rust、Go 用十六进制字符串传递原始交易和脚本，金额用十进制聪字符串。单输入 `signPayment` 的 `index` 是入金输出索引，`signSpend` 的 `index` 是已构造交易的输入索引。默认签名类型是 `0x41`。选用 OTDA 前用可信链状态明确设置 `chronicleActive`。Python 接口用字节和整数金额。各项目 SDK 说明列出本项目的模板选项及回调约定。

## 复验

在项目参考环境中安装固定的 chain-gang 依赖。原生测试夹具另外使用 `ecdsa==0.19.1`，ML-DSA 测试夹具需要 OpenSSL 3.5 或以上版本。在 Linux 的仓库根目录运行：

```sh
bash shared/verify_node.sh -- bash shared/sdk/verify.sh PROJECT
```

将 `PROJECT` 替换为项目目录名。该入口对照四种语言生成的锁定和已签交易字节，在 BSV Node 及 chain-gang 中复验签名交易，并检查模板识别及签名前校验。所有实际私钥操作由接入方负责。

## TypeScript 接入示例

示例中的交易参数来自钱包，由钱包审批。按实际接入项目替换导入路径。

```ts
import { resolve } from "node:path";
import { createClient } from "./projects/p2pkh-sm2/sdk/typescript/index.ts";

const sdk = createClient({ bridge: resolve("shared/sdk/python/bridge.py") });
const signedHex = sdk.signPayment({
  funding: authenticatedFundingHex,
  index: fundingVout,
  publicKey: publicKeyHex,
  outputs: approvedOutputs,
  feeSats: approvedFeeSats.toString(),
}, (message, userId) => walletSigner.signSm2(message, userId));
```
