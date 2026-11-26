# CCTP Groth16 的 VK_x 交易边界

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
