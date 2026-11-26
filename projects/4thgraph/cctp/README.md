# CCTP Groth16 的 VK_x 交易边界

## 按应用需求选择

CCTP 当前每笔转移的两个 128 位信号在花费时从经认证的交易承诺导出。验证密钥和信号顺序由协议固定。应用只有一个部署输出和一次结算花费时，可为每个新输出选一种满足这些条件的单输入布局。

| 目标 | 已复放的结果 |
| --- | --- |
| 最少部署加花费字节 | 现有 CCTP 窗口融合版为 401,694 B。通用 4thGraph 的 `path-bytes` 在 Genesis 下选内联仿射版，414,602 B。在 Chronicle 下选见证携带固定线表版，410,581 B |
| 最小 verifier 锁 | `lock-bytes` 选见证携带固定线表的仿射版。Genesis 锁 375,721 B，Chronicle 锁 370,562 B，证明见证均为 39,786 B |
| 最小 verifier 见证 | `witness-bytes` 选射影版，证明见证 1,092 B |

这些通用候选的数字以两份实际 CCTP 证明复放，范围为 `[0,2^128−1]`，度量对象是 verifier 和统一交易夹具。要接入 CCTP 花费，仍需让应用的绑定代码将实际交易导出的**同一对有序信号**交给 verifier，再实测完整锁和交易。[构建目标](../groth16-bls12-381/README.md#调用方选择) · [CCTP 同口径对照](../groth16-bls12-381/benchmarks/public-inputs/README.md#仿射布局复放)

### Chronicle 专用交易绑定

Chronicle 的专用操作码和 Chronicle OTDA 是两项可独立采用的部署取舍。`--script-era chronicle` 已支持第一项，用更短的 opcode 实现相同的证明谓词。当前 CCTP 参考路径用原始 ForkID ALL（`0x41`）验证原像，并从它导出公开信号。通用编译器的 `chronicle-v2` 交易目标也继续使用该原像。若实现 OTDA ALL（`0x61`）绑定，须明确激活和钱包支持范围，并保留实际 outpoint、有序输出、发行锚点及相关业务约束。原始 ForkID 原像直接包含被花费金额，OTDA 序列化需要另行取得并认证依赖的金额。

现有证明电路若承诺原始 ForkID 摘要，OTDA 路径需要从已认证的字段重建同一个承诺。新协议若直接承诺 OTDA 序列化，则使用单独的证明接口版本，并生成对应证明。完整 CCTP 的 OTDA 绑定尚未实测。[原像序列化](../../../shared/transaction.py) · [Chronicle 签名覆盖范围](../../p2pkh-r1/docs/chronicle.md)

## 交易拓扑

`vk-boundary.fth` 用同一验证密钥和动态的两个 128 位公开信号编译三种布局。构建时使用仓库当前的 4thGraph 前端，归档提供算术后端和证明夹具。融合版逐字节复现已验收的 400,348 B 锁。拆分版用相同的 MSM、曲线点、子群与配对逻辑。交易封装验证跨输入或跨交易的 `VK_x` 来源。对照统一使用附件所用的 v2 交易。

| 布局 | 部署 | 第一次花费 | 第二次花费 |
|---|---|---|---|
| `fused` | 完整验证锁 | 验证 MSM 和配对后结算 | — |
| `atomic` | MSM 与配对两个输出 | 按顺序共同消费真实的两个兄弟 outpoint | — |
| `serial` | MSM 与配对两个输出 | 消费 MSM 输出，验证 `VK_x`，创建状态输出 | 消费状态输出与原部署的配对输出 |

双输入版的两把锁验证 `hashPrevouts` 和 `hashOutputs`。两边根据同一部署 txid、公开信号、`VK_x` 和证明数据得到相同承诺，再校验结算输出序列化。串行版的首笔花费直接约束状态输出的金额和锁。末笔花费用原始阶段交易重建状态 outpoint，并检查首笔花费从原部署的 MSM 槽取得状态。状态输出本身也要求消费同一原部署的配对槽。交易绑定使用仓库的 ForkID PUSHTX 算术，后继引用在部署字节确定后实例化。

接收方以实际部署 outpoint 和已编译的输出形状识别验证任务。此实验终端输出用于 regtest 度量。串行状态绑定指定证明，有效解锁数据缺席会阻塞该任务。将其用于有业务资金的流程需要定义超时退出、退款授权及其与结算的互斥。

## 对照

一轮测量使用当前仓库的 BSV Node 1.2.3 `raised` 配置和 Chronicle-aware chain-gang。每个阶段七次交替测量。最大单笔验证耗时取各花费阶段中位数的最大值，部署交易计入总字节和最大单笔字节。两栈载荷由开发求值器采样。

| 布局 | 原始证明的部署＋花费 B | 最大单笔交易 B | 最慢花费 BSV Node ms | 最慢花费 chain-gang ms |
|---|---:|---:|---:|---:|
| 融合 | 401,695 | 400,519 | 151.19 | 42.33 |
| 同交易双输入 | 403,403 | 401,687 | 151.89 | 45.19 |
| 串行 | 406,280 | 402,420 | 135.23 | 38.76 |
| zkscript 仿射 | 443,653 | 417,021 | 197.91 | 67.78 |
| zkscript 射影 | 488,001 | 486,401 | 287.08 | 114.82 |

五种布局各运行同一密钥下的两份真实拆分证明。10 笔部署、2 笔 MSM 凭证和 10 笔结算均入块。15 个反例覆盖改动公开输入、兄弟 outpoint 跨根、错误 MSM 值、凭证跨根、错误的阶段交易字节、剪除配对输入、换用另一份有效证明，以及伪造交易原像。外部两版均拒绝了改变公开信号及替换证明点的花费。

外部基线采用上游原生验证路径，固定 128 位标量预算和 `modulo_threshold=1`。上游 BLS12-381 路径省略了 CCTP 显式执行的子群检查，因而这里比较同一密钥和证明下的性能与实际验收，验证覆盖按各自实现说明。

## 重跑

从 BSV Script Lab 根目录运行。需要 `ecdsa`、`patch` 和 `shared/requirements-chronicle.txt` 所固定的 chain-gang。附件必须是原 CCTP 基线 ZIP，准备器先校验摘要和文件清单，再应用两个已验收的优化补丁。

```sh
project=projects/4thgraph
build="$PWD/$project/build/cctp-vk-boundary"
python "$project/cctp/prepare_reference.py" /path/to/cctp-groth16-4thgraph-0.2.0-baseline.zip "$build/reference"
git clone https://github.com/nchain-innovation/zkscript_package.git "$build/zkscript"
git -C "$build/zkscript" checkout --detach fc20fb743edbc5bc5aba9d16625d50d1f50a3ef4
git clone --branch v0.1.3 https://github.com/nchain-innovation/elliptic_curves_package.git "$build/curves"
PYTHONPATH="$PWD:$build/reference/projects/groth16/reference:$build/zkscript:$build/curves" \
  bash shared/verify_node.sh --profile raised -- python "$project/cctp/replay_vk_boundary.py" \
  --archive "$build/reference" --zkscript --output "$build/comparison.json"
```

仅比较 4thGraph 布局时，调用复放脚本时省去 `--zkscript`。JSON 记录编译摘要、原料摘要、两份证明逐阶段的交易与运行开销、各引擎判定和真实区块记录。
