# Groth16 v0.9.0 复放基线

[English](replay-plan.en.md) · [验证器指南](verification.zh-CN.md)

基线使用 v0.9.0 选中的高层 Forth 源码和紧凑的 `affine-inline` 布局。计划固定按调用点选 Fp2 公式、累积器先乘 Frobenius 像，以及用倍点斜率表的有符号 radix-4 MSM。计划记录这组五个受限公开输入下的准确锁、构建产物及两份见证摘要。[复放计划](../versions/v0.9.0/replay-plan.json) · [选型证据](../versions/v0.9.0/measurements.json)

| Script 时代 | 锁 | 每份见证 | 锁加见证序列化字节 |
| --- | ---: | ---: | ---: |
| Genesis | 253,510 B | 9,378 B | 262,896 B |
| Chronicle | 252,605 B | 9,378 B | 261,991 B |

序列化总长包含 CompactSize。入金报告另行记录完整部署和花费的字节数，包含交易结构和资金输入签名。

在仓库根目录使用 Python 3.11 或更新版本构建。校验直接应用记录的方案，并在写出产物前核对摘要。

```sh
PYTHONPATH=src:. python3 projects/groth16-verifier/reference/replay_plan.py
PYTHONPATH=src:. python3 projects/groth16-verifier/reference/replay_plan.py --script-era chronicle
```

入金复放沿用既有的 BSV Node 与 chain-gang 回放入口。两份有效证明都须完成花费，互换声明和 G1 点超出子群须被拒绝。复放工具再核对实际交易包含已固定的锁和见证。按项目说明安装回放依赖，并为每个命令启动独立 regtest。[依赖安装](../README.zh-CN.md#复现方法)

```sh
REGTEST_CHRONICLE_HEIGHT=1000 bash tools/verify_node.sh --profile raised -- \
  python3 projects/groth16-verifier/reference/replay_plan.py --funded

REGTEST_CHRONICLE_HEIGHT=2 bash tools/verify_node.sh --profile raised -- \
  python3 projects/groth16-verifier/reference/replay_plan.py --script-era chronicle --funded
```

产物按 Script 时代写入 `projects/groth16-verifier/workspace/build/pinned-v0.9.0/`。入金回放另写含计划摘要的 `replay.json`。
