# P2PKH-R1-Deferred SDK 接入

[English](sdk.en.md)

<a name="quickstart"></a>

## 统一钱包接口

用 `createLock` 生成指定金额的短锁。识别时同时传入原始脚本和输出金额。已经存在的短锁按原承诺的 R1 版本启用。先从仓库根目录安装参考环境。

```sh
python3.12 -m venv .venv
.venv/bin/python -m pip install -r projects/p2pkh-r1-deferred/reference/requirements.txt
```

使用[统一接入指南](../../../shared/sdk/README.zh-CN.md)里的 `config` 和已核验的交易数据。

```ts
import { WalletClient } from "./shared/sdk/typescript/index.ts";

const deferred = new WalletClient("p2pkh-r1-deferred", { ...config, template: "v0.2.0" });
const shortLock = deferred.createLock({ publicKey: receiveKeyHex, valueSats });
const prevout = deferred.prevoutFromFunding(fundingTxHex, fundingVout);
const commitment = deferred.recognize({
  script: prevout.script, valueSats: prevout.valueSats, publicKey: spendKeyHex,
});
if (!commitment) throw new Error("Unrecognized Deferred output");

const r1 = new WalletClient("p2pkh-r1", { ...config, template: commitment.targetTemplate });
const targetScript = r1.createLock({ publicKey: spendKeyHex });
// Put { script: targetScript, valueSats: prevout.valueSats } at inputIndex in the
// approved transaction's output list and include any needed fee-paying input.
const activatedHex = deferred.activate({ transaction: preparedHex, inputIndex, prevout });
```

`activate` 默认使用 ForkID SINGLE（`0x43`），只填指定输入，不调用私钥签名器。预先组装交易，将承诺的完整 R1 输出放到同索引，金额与短锁一致。若有额外的付费输入，钱包另行签署。启用后用普通 R1 SDK 花费。

从仓库根目录复放四语言向量。

```sh
SCRIPT_LAB_SDK_PYTHON="$PWD/.venv/bin/python" \
  bash shared/verify_node.sh -- bash shared/sdk/verify_wallet.sh p2pkh-r1-deferred
```

## 组装启用交易

1. 从可信链视图认证入金 UTXO，用实际金额识别短锁。核对发票公钥哈希，并使用返回的 `targetTemplate`。
2. 为同一公钥哈希生成等额的完整 R1 输出，将其放在与启用输入相同的索引。用独立的赞助输入支付手续费，并确定找零。
3. 将已准备的交易、输入索引和可信 prevout 传给 `activate`。默认使用 ForkID SINGLE（`0x43`）。其他模式同样需要同索引目标输出，参数见协议规范。赞助输入单独签署。
4. 记录启用后的 R1 outpoint，后续付款按 [R1 钱包接入](../../p2pkh-r1/docs/sdk.zh-CN.md)处理。

## 跟踪短锁和启用后的输出

把短锁 outpoint、金额、所有者和 `targetTemplate` 随付款请求保存。批量启用时，先固定每个启用输入与同索引 R1 输出的对应关系，再组装解锁。输出保留入金全额，因此费用由单独的输入承担。赞助方审批整笔交易并签署自己的输入。

确认后，用启用交易的最终 txid 和输出索引登记新的 R1 outpoint。广播延迟或链重组改变依赖的父交易时，先从链视图核对短锁和启用后的输出，再创建子交易。[R1 花费流程](../../p2pkh-r1/docs/sdk.zh-CN.md#quickstart)

[启用协议](spec.zh-CN.md) · [十二种签名类型向量](../template/v0.2.0/sighash-modes.json) · [参考交易构造](../reference/README.md)
