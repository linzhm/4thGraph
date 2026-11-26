# P2PKH-R1 钱包 SDK

[English](./sdk.en.md) · [线格式规范](./spec.zh-CN.md)

<a name="quickstart"></a>

## 统一钱包接口

使用版本 0.2.0 创建新收款输出。统一客户端用同一套调用识别已核验的旧版输出和新版输出。公钥为 65 字节未压缩 P-256 编码，也可以用 `ownerHash160` 创建收款脚本。运行时使用项目参考环境，在仓库根目录安装以下依赖。

```sh
python3.12 -m venv projects/p2pkh-r1/workspace/venv
projects/p2pkh-r1/workspace/venv/bin/python -m pip install -r projects/p2pkh-r1/reference/requirements.txt
```

以下示例使用已核验的交易数据。将桥接配置中的 `python` 指向 `projects/p2pkh-r1/workspace/venv/bin/python`，`bridge` 指向当前检出的 `sdk/python/bridge.py`。[共享接入示例](../../../sdk/docs/integration.zh-CN.md#first-payment)

```ts
import { resolve } from "node:path";
import { WalletClient } from "./sdk/typescript/index.ts";

const wallet = new WalletClient("p2pkh-r1", { ...config, template: "v0.2.0" });
const receiveScript = wallet.createLock({ publicKey: receiveKeyHex });
const prevout = wallet.prevoutFromFunding(fundingTxHex, fundingVout);
if (!wallet.recognize({ script: prevout.script, publicKey: spendKeyHex })) {
  throw new Error("Funding output does not match the spending key");
}
const signedHex = wallet.signPayment({
  prevout,
  publicKey: spendKeyHex,
  outputs: approvedOutputs,
  feeSats: approvedFeeSats.toString(),
  historyPath: resolve(walletStateDir, "r1-signing.sqlite"),
}, ({ payload }) => signer.signP256DigestRaw(payload));
```

签名器返回 64 字节 `r ∥ s`。默认输入是 `SHA256d(P)`。如果设备内部执行一次 SHA-256，在请求中设 `signMessage: true`，回调会收到 `SHA256(P)`，其 `payloadKind` 为 `message`。各进程为同一钱包共用持久的 `historyPath`，用于记录重复的 P-256 签名 nonce。多输入付款用 `signInput`。Chronicle 激活后，符合条件的版本 2 OTDA 花费可用 `compressOtda: true`。

从仓库根目录复放四语言向量。

```sh
SCRIPT_LAB_SDK_PYTHON="$PWD/projects/p2pkh-r1/workspace/venv/bin/python" \
  bash tools/verify_node.sh -- bash sdk/verify_wallet.sh p2pkh-r1
```

## 接通签名设备

1. 先用夹具复放普通 BIP143 ALL，确认识别结果里的所有者哈希和模板，再接入实际设备。
2. 按设备的行为选接口。若设备接收预先计算的摘要，使用默认模式。若设备内部恰好执行一次 SHA-256，设 `signMessage: true`。回调返回定长的 64 字节 `r ∥ s`。设备返回 DER 时，先转换格式。
3. 将绝对路径 `historyPath` 指向各签名进程共用的持久存储，并演练重启后读回同一份历史。如果钱包因检测到签名随机数重复而阻止使用密钥，先排查签名器和受影响的密钥，再恢复付款。

[签名随机数历史与钱包行为](../reference/README.md)

## 正则与完整指纹

1. 检查原始脚本恰为 **46,302 字节**。
2. 将前 **228 字节**编码为小写 hex，用以下正则匹配整个头部。捕获组 1 解码后是候选的 20 字节收款哈希。

```regex
^760052a569766b7c8201[0-9a-f]{396}([0-9a-f]{40})$
```

3. 在原始二进制上计算 `SHA256(script[0:208] || script[228:])`，必须等于 `52a1d9eb9e236403c66e845e18cf31d9c3a5f4c2e0ed7ca0270a60ba4e867ca6`。只有这一步成功才返回捕获值。后缀即使只有一字节不同也会导致失败。对收款人做替换时，在已验证模板的副本上覆盖 `[208,228)`。[布局](../template/v0.2.0/layout.json)

## 设备签名和逐输入付款

摘要签名器接收 `SHA256d(P)`。设备内部还会执行一次 SHA-256 时，设 `signMessage: true`，传入的消息是 `SHA256(P)`。两种回调均返回 64 字节原始签名，`r` 和 `s` 各为左侧补零的 32 字节大端数。TypeScript 的 `signPaymentAsync` 和 `signInputAsync` 可对接异步设备。

混合输入或逐输入指定签名方式时使用 `signInput`。钱包在收集签名前固定交易并核对上一输出和手续费。父交易确认后如果 txid 有变化，核对实际 outpoint 并重建子交易。[R1 签名和摘要向量](../template/v0.2.0/spend-all.json) · [恢复子交易](chronicle.md#恢复子交易)

## 当前开发版本

新建输出使用 v0.2.0。Python 默认选择这一版本。已有 UTXO 按 v0.1.0 原有布局核对。统一客户端可识别两个版本，并支持普通 BIP143 ALL 付款。 [v0.1.0 布局](../template/layout.json)

Python 的 `sign_spend(..., compress_otda="paired")` 在支持 Chronicle
功能解锁的版本 2 交易中重建 OTDA ALL 输出和有配对输出的 OTDA SINGLE。
`SINGLE` 重建同索引输出，并保留预映像中此前的空输出占位。
交易版本 1、无配对 `SINGLE` 和未知输出格式走原有编码。签名器收到原预映像的
摘要，返回的签名直接写入解锁脚本。

版本 2 的 OTDA ALL 付款可以同时重建 47,510 字节和 46,302 字节两种模板的输出。
钱包比较原样预映像、只重建一种模板和重建两种模板的字节数，按已签名的次序
重建输出。两进两出各使用一种模板时，整笔交易从 195,028 降到 110,302 字节。
