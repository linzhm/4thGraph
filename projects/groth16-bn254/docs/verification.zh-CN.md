# BN254 Groth16 验证

[English](verification.en.md) · [项目主页](../README.zh-CN.md)

## Forth 接线与算术

验证器入口用三个带类型的步骤构造验证锁。所有者授权用 BIP143 ALL 校验实际花费的签名。声明模块读取部署时选定的五个公开标量。最后一个词将这些值作为 `pinnedPublicInputs` 传给 Rúnar，在编译时把五次标量乘法折叠进 MSM 的初始点。生成的链上谓词逐一核验见证中的标量和 MSM 预计算点，再验证配对。[验证器入口](../forth/fixed-verifier.fth) · [声明模块](../forth/statement.fth) · [BN254 词表与链接器](../../../src/fourthgraph/verification/groth16_bn254.py)

Go 适配器调用固定版本的 Rúnar 编译器生成 BN254 群与域运算。见证生成器沿用 v0.1.0 的格式拼装证明和算术辅助数据。Rúnar 生成链上的点检查、Miller 循环和余数校验。[Go 适配器](../../../src/fourthgraph/verification/groth16_bn254_adapter.go) · [固定版本的 Rúnar 编译器](https://github.com/icellan/runar/blob/dbcc4269f8e0895c4738cf86948b05b7d62a2010/compilers/go/compiler/groth16_wa.go)

## 构建与回放

按项目主页准备依赖，并从仓库根目录运行 v0.2.0 的构建和回放命令。构建将锁产物和仅含入栈操作的证明前缀写到项目内的 `workspace/build/`。应用在前缀后追加对实际花费的所有者签名。此后端使用 Chronicle。复现基线可用 v0.1.0 的 Forth 入口。[版本命令](../versions/v0.2.0/manifest.json) · [基线入口](../verifier.fth)

夹具包含本地测试验证密钥与同一密钥下对应不同声明的两份证明。入金回放部署与独立构建相同的锁。BSV Node 和 chain-gang 都接受锁定声明的证明，并拒绝另一声明的有效证明、取负的证明点、错误的 sighash 标记，以及修改输出后沿用旧签名的花费。有效花费在 regtest 出块。[测试夹具](../versions/v0.1.0/fixture.json) · [原生验证证据](../versions/v0.2.0/measurements.json)

## BN254 体积对照

| 实现和用例 | 公开输入数 | 锁定脚本 | 解锁脚本 | 序列化脚本路径 |
| --- | ---: | ---: | ---: | ---: |
| 4thGraph v0.1.0，Chronicle regtest | 5 | 1,524,095 B | 31,128 B | 1,555,231 B |
| 4thGraph v0.2.0，同夹具和脚本版本 | 5 | 821,788 B | 31,129 B | 852,925 B |
| sCrypt 因数分解教程，BSV 公共测试网 | 1 | 1,515,332 B | 264 B | 1,515,604 B |

两次 4thGraph 回放使用同一验证密钥、声明和证明。v0.2.0 的锁定脚本减少 702,307 B，降幅为 46.1%。两版的见证前缀均为 31,056 B，哈希一致。解锁脚本相差 1 B 来自所有者 DER 签名的长度差异。路径包含两段脚本及各自的 CompactSize 长度。[实测记录](../versions/v0.2.0/measurements.json)

sCrypt 教程使用另一把验证密钥和一个固定公开输入，解锁字节数来自教程公布的花费交易。这些数值对应其公开示例。nChain 的实测使用 BLS12-381 曲线。[sCrypt 教程](https://docs.scrypt.io/bsv-docs/tutorials/zkp/) · [BLS12-381 验证](../../groth16-bls12-381/docs/verification.zh-CN.md)
