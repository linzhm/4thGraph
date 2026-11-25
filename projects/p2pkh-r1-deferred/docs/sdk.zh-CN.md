# P2PKH-R1-Deferred SDK 接入

[English](sdk.en.md)

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

## 原有源码 SDK

三个源码 SDK 使用同一份[短锁模板](../template/v0.2.0/template.hex)和[R1 v0.2.0 模板](../../p2pkh-r1/template/v0.2.0/template.hex)。读取 `.hex` 时先去掉空白，再解码为从第一个 opcode 开始的字节。金额为整数聪。TypeScript 使用 `bigint`，Rust 使用 `u64`，Go 使用 `int64`。

已有短锁按其原先承诺的 R1 版本识别和启用。v0.1.0 入金对应原先承诺的 v0.1.0 目标。 [v0.1.0 R1 模板](../../p2pkh-r1/template/template.hex)

| 接口 | TypeScript | Rust | Go |
|---|---|---|---|
| 从公钥哈希生成短锁 | `lockForOwner` | `lock_for_owner` | `LockForOwner` |
| 从完整公钥生成短锁 | `lockForKey` | `lock_for_key` | `LockForKey` |
| 完整识别 | `recognize` | `recognize` | `Recognize` |
| 编码启用解锁脚本 | `activationWitness` | `activation_witness`、`activation_witness_with_digest` | `ActivationWitness` |

生成接口接受两个模板、收款公钥哈希或完整公钥以及金额。两种接口均输出含 20 字节公钥哈希的短锁。识别接口接受 R1 模板、实际短锁及实际金额，返回经完整重建验证的公钥哈希、目标脚本 SHA-256 和目标输出 HASH256。旧版格式还会返回其内嵌公钥。钱包仍需按发票核对预期公钥哈希及金额。

组装启用交易时，先确定输入输出索引、手续费输入和找零。交易构造器根据实际交易和已认证的 prevout 生成 ForkID SINGLE 输出约束原像。直接使用 `0x43` 或 `0xc3` 时只传该原像。其他模式还需传 33 字节的 `typeByte || HASH256(selectedPreimage)`，并使用规范中双检查分支的 `scriptCode` 生成输出约束原像。SDK 检查原像字段及两种类型的组合，再编码解锁脚本。完整交易构造见 [Python 参考实现](../reference/README.md)。启用输出的后续付款使用[原有 R1 SDK](../../p2pkh-r1/docs/sdk.zh-CN.md)和外部签名器。

从各 SDK 目录运行 `npm test`、`cargo test` 和 `go test ./...`。三套测试使用相同的[生成和识别向量](../template/v0.2.0/layout.json)及[十二种启用模式向量](../template/v0.2.0/sighash-modes.json)。
