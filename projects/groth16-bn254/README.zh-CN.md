<!-- Generated from manifest.yaml with Copier. -->

# BN254 Groth16 验证器 v0.7.0

[English](README.md) · [4thGraph](../../README.zh-CN.md) · [项目目录](../README.zh-CN.md) · [版本](versions/index.json)

## 开发入口

用带类型的 Forth 编译需要所有者签名的 BN254 Groth16 验证器。在 Chronicle regtest 上，两份固定声明的完整部署加一次花费均低于 472,000 B。

[算法与执行](#算法与执行) · [复现方法](#复现方法) · [完整交易与栈测量](#完整交易与栈测量) · [实测数据](versions/v0.7.0/measurements.json)

| 入口 | 用途 |
| --- | --- |
| `verify-bn254-proof` | 从带类型的 Forth 模块编译完整的固定声明验证器。 |

## 算法与执行

Forth 入口连接证明点校验、Jacobian G2 子群检查、Miller 循环和余数断言。编译器为五个固定公开输入预计算 MSM，并把结果并入固定配对项。更换公开声明时需要重新编译。[Forth 入口](forth/optimized-verifier.fth) · [验证指南](docs/verification.zh-CN.md)

v0.7.0 入口启用 Jacobian 操作数的最后一次使用调度、Script 栈压缩和 Fp12 结果的原位改名。后端在原栈位置跟踪新名字，改名发出零条搬运指令。两份锁均比 v0.6.0 缩小 6,384 B。[编译器优化](../../src/fourthgraph/verification/runar/forth_fp12_rename.patch)

## 复现方法

从仓库根目录运行，使用 Python 3.11 或更新版本、Go 1.26.6 和检出到 `workspace/runar` 的固定 Rúnar 版本。入金回放还需 Chronicle chain-gang 绑定与 BSV Node。

```sh
git clone https://github.com/icellan/runar.git workspace/runar
git -C workspace/runar checkout --detach dbcc4269f8e0895c4738cf86948b05b7d62a2010
python3 -m pip install ecdsa -r tools/requirements-chronicle.txt
```

```sh
bash projects/groth16-bn254/reference/build.sh workspace/runar \
  projects/groth16-bn254/forth/optimized-verifier.fth
for fixture_case in wrap other; do
  REGTEST_CHRONICLE_HEIGHT=2 bash tools/verify_node.sh --profile long-script -- \
    python3 -m fourthgraph.replay.groth16_bn254 --runar workspace/runar \
    --verifier-source projects/groth16-bn254/forth/optimized-verifier.fth \
    --fixture projects/groth16-bn254/versions/v0.1.0/fixture.json \
    --fixture-case "$fixture_case" \
    --output "projects/groth16-bn254/workspace/build/replay-v0.7.0-${fixture_case}.json" || exit $?
done
```

构建把锁定脚本和见证前缀写入项目的 `workspace/build/`。回放为每份夹具写一份 JSON 报告。

## 完整交易与栈测量

| 夹具 | 锁定脚本 | 见证前缀 | 部署交易 | 花费交易 | 合计 | 栈数据峰值 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `wrap` | 464,397 B | 6,765 B | 464,534 B | 6,934 B | **471,468 B** | 8,872 B |
| `other` | 464,395 B | 6,761 B | 464,531 B | 6,930 B | **471,461 B** | 8,870 B |

两笔有效花费均已出块，BSV Node 和 chain-gang 都拒绝了全部十个反例。见证前缀哈希与 v0.6.0 一致。[入金回放实测](versions/v0.7.0/measurements.json)

按阶段统计 v0.6.0 的锁，Miller 循环占 83.1%，G2 子群检查占 13.8%。验证指南给出降至 450,000 B 和 400,000 B 所需的节省量。[进一步优化空间](docs/verification.zh-CN.md#进一步优化空间) · [分阶段实测](versions/v0.6.0/optimization-profile.json)
