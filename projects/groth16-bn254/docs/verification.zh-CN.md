# BN254 Groth16 验证

[English](verification.en.md) · [项目主页](../README.zh-CN.md)

## Forth 接线与算术

验证器入口组合所有者授权、部署时选定的五个公开标量和 `bn254-compact-fixed-pairing`。编译器计算 MSM 点 \(L\)，把 \(L,-\gamma\) 的 Miller 因子并入 \(\alpha,-\beta\) 的固定因子，并预计算 \(-\delta\) 的配对线系数。见证提供证明点 \(A,B,C\)、点 \(B\) 的可变 Miller 斜率和余数。验证器使用部署时选定声明对应的固定因子。[验证器入口](../forth/compact-verifier.fth) · [声明模块](../forth/statement.fth) · [BN254 词表与链接器](../../../src/fourthgraph/verification/groth16_bn254.py)

Go 适配器通过 Go overlay 加载固定 Rúnar 版本上的扩展。预计算线保留原有域元素表示和 Frobenius 修正，使链上验证和见证生成使用相同的 Miller 乘积。G2 检查先校验扭曲曲线方程，再用 Jacobian 坐标计算 \([6u^2]B=\psi(B)\)。脚本要求 \(Z\) 非零，并用交叉乘法比较仿射坐标。退化的加点或倍点会使 \(Z\) 变为零，之后一直为零，最终被拒绝。余数方程继续核验逆元和最终配对结果。[Go 适配器](../../../src/fourthgraph/verification/groth16_bn254_adapter.go) · [编译器扩展](../../../src/fourthgraph/verification/runar/compact_groth16.go)

所有者授权对实际花费校验 BIP143 ALL 签名。回放复用 preimage 构造器底层的授权准备函数，取得签名摘要。`wrap` 的链下 preimage 为 540,095 B。签名者收到摘要，解锁脚本携带证明见证和签名，preimage 占 0 B。在 covenant 等需要 Script 自己读取交易字段的场景，可以用构造器生成显式 preimage 见证。[共用的 preimage 构造器](../../../src/fourthgraph/workflow/preimage_constructor.py)

## 构建与回放

按项目主页准备依赖，并从仓库根目录运行 v0.3.0 的构建和回放命令。构建将锁产物和仅含入栈操作的证明前缀写到项目内的 `workspace/build/`。回放默认选 `wrap`。传入 `--fixture-case other` 可为另一声明编译锁并回放该证明。v0.2.0 入口可复现历史锁和见证摘要。[版本命令](../versions/v0.3.0/manifest.json) · [v0.2.0 入口](../forth/fixed-verifier.fth)

夹具使用测试专用密钥和两个声明。两个有效花费均在 Chronicle regtest 出块。BSV Node 和 chain-gang 都拒绝了另一声明的有效证明、取负的证明点、曲线上但不在子群内的 G2 点、错误的 sighash 标记，以及修改输出后沿用旧签名的花费。子群检查发码还单独与 gnark 的结果对照。[测试夹具](../versions/v0.1.0/fixture.json) · [入金回放证据](../versions/v0.3.0/measurements.json) · [子群检查测试](../../../src/fourthgraph/verification/runar/compact_groth16_test.go)

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

## BN254 体积对照

| 实现和用例 | 公开输入数 | 锁定脚本 | 解锁脚本 | 序列化脚本路径 |
| --- | ---: | ---: | ---: | ---: |
| 4thGraph v0.1.0，Chronicle regtest | 5 | 1,524,095 B | 31,128 B | 1,555,231 B |
| 4thGraph v0.2.0，同夹具和脚本版本 | 5 | 821,788 B | 31,129 B | 852,925 B |
| sCrypt 因数分解教程，BSV 公共测试网 | 1 | 1,515,332 B | 264 B | 1,515,604 B |

两次历史回放使用同一验证密钥、声明和证明。v0.2.0 的锁定脚本减少 702,307 B，降幅为 46.1%。两版的见证前缀均为 31,056 B，哈希一致。解锁脚本相差 1 B 来自所有者 DER 签名的长度差异。路径包含两段脚本及各自的 CompactSize 长度。[v0.2.0 实测记录](../versions/v0.2.0/measurements.json)

sCrypt 教程使用另一把验证密钥和一个固定公开输入，解锁字节数来自教程公布的花费交易。这些数值对应其公开示例。nChain 的实测使用 BLS12-381 曲线。[sCrypt 教程](https://docs.scrypt.io/bsv-docs/tutorials/zkp/) · [BLS12-381 验证](../../groth16-bls12-381/docs/verification.zh-CN.md)
