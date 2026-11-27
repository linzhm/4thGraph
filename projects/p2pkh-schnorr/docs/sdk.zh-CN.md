# P2PKH-Schnorr 钱包 SDK

[English](sdk.en.md) · [项目首页](../README.zh-CN.md) · [统一钱包 SDK](../../../sdk/README.zh-CN.md)

<a name="quickstart"></a>

## 收款和花费

在统一 SDK 中选择项目 `p2pkh-schnorr`，默认使用 `v0.14.0` 模板。创建收款脚本时传入 32 字节 x-only 公钥或其 20 字节 HASH160。客户端在 Forth 编译产物中填入所有者哈希，识别时核对实际脚本的全部固定字节，也可以提供预期公钥。SDK 根据上一输出的脚本识别并花费九个版本的 UTXO。如需创建旧版输出，可将钱包的 `template` 设为相应版本。[版本目录](../versions/index.json)

签名请求的算法为 `schnorr-secp256k1`，数据类型为 `message`，签名格式为 `bip340`。把 32 字节载荷作为消息交给 BIP340 签名器，直接返回签名器给出的 64 字节。SDK 验证签名并推导见证所需的公开坐标，再调用 Forth 的 `schnorr-unlock` 生成解锁脚本。[Forth 源码](../reference/schnorr.fth)

以下示例使用已核验的交易数据。将桥接配置中的 `python` 指向 `projects/p2pkh-schnorr/workspace/p2pkh-schnorr/bin/python`，`bridge` 指向当前检出的 `sdk/python/bridge.py`。[共享接入示例](../../../sdk/docs/integration.zh-CN.md#first-payment) · [项目 Python 环境](../README.zh-CN.md#复现验收)

```ts
import { WalletClient } from "./sdk/typescript/index.ts";

const wallet = new WalletClient("p2pkh-schnorr", config);
const receiveScript = wallet.createLock({ publicKey: receiveKeyHex });
const prevout = wallet.prevoutFromFunding(fundingTxHex, fundingVout);
if (!wallet.recognize({ script: prevout.script, publicKey: spendKeyHex })) {
  throw new Error("Funding output does not match the Schnorr key");
}
const signedHex = wallet.signPayment({
  prevout,
  publicKey: spendKeyHex,
  outputs: approvedOutputs,
  feeSats: approvedFeeSats.toString(),
}, ({ payload }) => signer.signBip340(payload));
```

签署已组装的交易时，用 `signInput` 传入当前输入索引和已核验的上一输出。使用 Chronicle OTDA 时，根据实际链上下文填写 `chronicleActive`。SINGLE 需要同索引输出。Python、Rust 和 Go 也提供对应的接口。[统一调用表](../../../sdk/docs/reference.zh-CN.md#calls-and-data)

<a name="integrate-musig2"></a>

## 接入 MuSig2

钱包策略保存两把压缩参与者公钥及其约定顺序，在入金前按 BIP327 得到聚合公钥横坐标。收款、识别上一输出和花费都把聚合公钥传为 `publicKey`。签名时，外部协调器把已审批的输入及 `payload` 交给双方，交换公有 nonce 并核验两份部分签名，再通过现有回调返回最终的 64 字节 BIP340 签名。某个输入需要另开会话时，重新生成 nonce 和部分签名。参与者审批、通信和 nonce 状态由外部签名器管理。[2-of-2 验收与成本](threshold-comparison.zh-CN.md) · [BIP327](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki)

## 复放公开向量

按项目首页安装依赖，再运行离线示例。其中使用的密钥和辅助随机数均为公开测试数据。

```sh
PYTHONPATH=src:. projects/p2pkh-schnorr/workspace/p2pkh-schnorr/bin/python -m sdk.examples.receive_and_pay p2pkh-schnorr
SCRIPT_LAB_SDK_PYTHON="$PWD/projects/p2pkh-schnorr/workspace/p2pkh-schnorr/bin/python" \
  bash tools/verify_node.sh -- bash sdk/verify_wallet.sh p2pkh-schnorr
```

[环境与验收范围](../README.zh-CN.md#复现验收)
