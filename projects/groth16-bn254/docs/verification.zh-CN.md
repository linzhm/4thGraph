# BN254 Groth16 验证

[English](verification.en.md) · [项目主页](../README.zh-CN.md)

## Forth 接线与算术

固定声明入口先校验所有者签名，再读取见证、校验证明点并执行子群检查、Miller 循环和余数检查。编译器把 MSM 点 \(L\) 与 \(-\gamma\) 的 Miller 因子并入 \(\alpha,-\beta\) 的固定因子，并预计算 \(-\delta\) 的配对线系数。见证提供证明点、点 \(B\) 的可变 Miller 斜率和余数。[Forth 入口](../forth/last-use-verifier.fth) · [固定声明](../forth/statement.fth)

Forth 的 Jacobian 模块写出了 Fp2 上的倍点与混合加点公式。子群模块写出 \([6u^2]B\) 的 127 轮有符号链和 Frobenius 比较。Miller 模块写出 \(6u+2\) 的 65 轮，包含切线、有符号加点、余数累乘及最终 Frobenius 线。余数模块校验配对乘积等于一。后端生成 Fp2 与 Fp12 基元，并在发码前校验两套轮次与 BN254 常数和见证布局一致。[Jacobian 公式](../forth/jacobian.fth) · [子群检查](../forth/subgroup.fth) · [Miller 循环](../forth/miller.fth) · [余数检查](../forth/residue.fth) · [后端](../../../src/fourthgraph/verification/runar/forth_groth16.go)

所有者授权对实际花费校验 BIP143 ALL 签名。回放复用 preimage 构造器底层的授权准备函数，取得签名摘要。`wrap` 的链下 preimage 为 470,942 B。签名者收到摘要，解锁脚本携带证明见证和签名，preimage 占 0 B。在 covenant 等需要 Script 自己读取交易字段的场景，可以用构造器生成显式 preimage 见证。[共用的 preimage 构造器](../../../src/fourthgraph/workflow/preimage_constructor.py)

## 构建与回放

按项目主页准备依赖，并从仓库根目录运行 v0.6.0 的构建和回放命令。构建将锁产物和仅含入栈操作的证明前缀写到项目内的 `workspace/build/`。回放覆盖两份夹具，分别用各自的固定声明编译锁并花费。历史 Forth 入口可复现对应版本的锁和见证摘要。[版本命令](../versions/v0.6.0/manifest.json) · [v0.5.0 入口](../forth/compact-stack-verifier.fth) · [v0.4.0 入口](../forth/verifier.fth) · [v0.3.0 入口](../forth/compact-verifier.fth)

夹具使用测试专用密钥和两个声明。两个有效花费均在 Chronicle regtest 出块。BSV Node 和 chain-gang 都拒绝了另一声明的有效证明、取负的证明点、曲线上但不在子群内的 G2 点、错误的 sighash 标记，以及修改输出后沿用旧签名的花费。子群检查发码还单独与 gnark 的结果对照。[测试夹具](../versions/v0.1.0/fixture.json) · [入金回放证据](../versions/v0.6.0/measurements.json) · [子群检查测试](../../../src/fourthgraph/verification/runar/compact_groth16_test.go)

## 栈调度实测

编译器把等深度的两次栈操作合并为一条成对指令。取模阈值固定为 64 B 时，`wrap` 的锁从 539,934 B 降到 505,179 B。两份夹具的锁中，`OP_2OVER` 各替换 1,291 次，`OP_2SWAP` 各替换 809 次，`OP_2ROT` 各替换 9,485 次。每次替换省 3 B。`wrap` 的见证前缀为 6,765 B，主栈与备用栈数据总峰值为 8,872 B。锁定脚本、完整解锁脚本及长度前缀共 512,024 B。[编译器规则](../../../src/fourthgraph/compiler/stack_schedule.py) · [v0.4.0 实测](../versions/v0.4.0/measurements.json)

v0.5.0 的 Forth 入口启用通用栈优化。编译器在签名前合并栈项删除，并缩短使用固定深度的复制与旋转序列。每组替换保留最终的栈内容和所需的最小输入深度。见证哈希和算术轮次与 v0.4.0 一致。[栈优化](../../../src/fourthgraph/compiler/stack_peephole.py)

| 版本 | 夹具 | 锁定脚本 | 见证前缀 | 序列化脚本路径 | 部署交易 | 花费交易 | 合计 |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| v0.5.0 | `wrap` | 492,007 B | 6,765 B | 498,852 B | 492,143 B | 6,934 B | 499,077 B |
| v0.5.0 | `other` | 492,005 B | 6,761 B | 498,847 B | 492,141 B | 6,931 B | 499,072 B |
| v0.6.0 | `wrap` | 470,781 B | 6,765 B | 477,627 B | 470,917 B | 6,935 B | **477,852 B** |
| v0.6.0 | `other` | 470,779 B | 6,761 B | 477,620 B | 470,916 B | 6,930 B | **477,846 B** |

v0.5.0 的两份锁各比 v0.4.0 减少 13,172 B。合计按部署和一次花费的完整交易序列化长度计算，regtest 测试资金交易单独计算。`wrap` 和 `other` 的主栈与备用栈数据总峰值分别为 8,872 B 和 8,870 B。[v0.5.0 实测](../versions/v0.5.0/measurements.json)

v0.6.0 后端统计 Jacobian 公式中每个 Fp2 操作数的剩余用途。最后一次使用直接消费原栈槽，借用的仿射坐标保留给后续轮次。编译器在返回值所在位置绑定坐标名。两份锁各缩小 21,226 B，见证前缀哈希、算术轮次和实测栈数据峰值与 v0.5.0 一致。[编译器优化](../../../src/fourthgraph/verification/runar/forth_liveness.go) · [v0.6.0 实测](../versions/v0.6.0/measurements.json)

## 编译方案对比

各方案在同一个 Chronicle regtest 节点上用同一把验证密钥和两份证明编译并验证，预热之后每个方案和每份证明各采五次耗时。下表是 `wrap` 的体积，报告还保存了耗时原始数据和 `other` 结果。栈峰值按主栈和备用栈数据总量计算。[完整对比](../versions/v0.3.0/plan-comparison.json)

| 编译方案 | 锁定脚本 | 见证前缀 | 序列化脚本路径 | 栈峰值 |
| --- | ---: | ---: | ---: | ---: |
| v0.2.0 | 821,788 B | 31,056 B | 852,925 B | 31,071 B |
| 固定配对预计算与仿射子群检查 | 598,775 B | 19,634 B | 618,490 B | 19,998 B |
| 固定配对预计算与投影二进制链 | 652,046 B | 6,765 B | 658,891 B | 8,863 B |
| 固定配对预计算与投影 NAF 链 | 627,022 B | 6,765 B | 633,868 B | 8,863 B |
| 投影 NAF 链与 64 B 归约阈值 | **539,934 B** | **6,765 B** | **546,780 B** | **8,872 B** |

NAF 链有 127 次倍点和 39 次加点，二进制链有 126 次倍点和 69 次加点。64 B 阈值在两份夹具均通过的方案中体积最小。BSV Node 对 128、256、512 B 阈值的有效证明检查失败，这三档被淘汰。所选方案使 `wrap` 的锁定脚本减少 34.3%，见证前缀减少 78.2%，序列化脚本路径减少 35.9%。该路径包含所有者签名与 CompactSize 前缀，签名长度可能随交易变化 1 B。

```sh
REGTEST_CHRONICLE_HEIGHT=2 bash tools/verify_node.sh --profile long-script -- \
  python3 projects/groth16-bn254/reference/compare_plans.py --runar workspace/runar \
  --output projects/groth16-bn254/workspace/build/plan-comparison.json
```

基线和选定的 64 B 方案均通过两份夹具后，命令才会写入报告。其他候选方案的脚本拒绝会写入报告，编译或 RPC 错误会中止命令。

## BN254 体积对照

| 实现和用例 | 公开输入数 | 锁定脚本 | 解锁脚本 | 序列化脚本路径 |
| --- | ---: | ---: | ---: | ---: |
| 4thGraph v0.1.0，Chronicle regtest | 5 | 1,524,095 B | 31,128 B | 1,555,231 B |
| 4thGraph v0.2.0，同夹具和脚本版本 | 5 | 821,788 B | 31,129 B | 852,925 B |
| 4thGraph v0.4.0，同夹具和脚本版本 | 5 | 505,179 B | 6,837 B | 512,024 B |
| 4thGraph v0.5.0，同夹具和脚本版本 | 5 | 492,007 B | 6,837 B | 498,852 B |
| 4thGraph v0.6.0，同夹具和脚本版本 | 5 | 470,781 B | 6,838 B | 477,627 B |
| sCrypt 因数分解教程，BSV 公共测试网 | 1 | 1,515,332 B | 264 B | 1,515,604 B |

两次历史回放使用同一验证密钥、声明和证明。v0.2.0 的锁定脚本减少 702,307 B，降幅为 46.1%。两版的见证前缀均为 31,056 B，哈希一致。解锁脚本相差 1 B 来自所有者 DER 签名的长度差异。路径包含两段脚本及各自的 CompactSize 长度。[v0.2.0 实测记录](../versions/v0.2.0/measurements.json)

sCrypt 教程使用另一把验证密钥和一个固定公开输入，解锁字节数来自教程公布的花费交易。这些数值对应其公开示例。nChain 的实测使用 BLS12-381 曲线。[sCrypt 教程](https://docs.scrypt.io/bsv-docs/tutorials/zkp/) · [BLS12-381 验证](../../groth16-bls12-381/docs/verification.zh-CN.md)
