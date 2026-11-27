# BN254 Groth16 验证

[English](verification.en.md) · [项目主页](../README.zh-CN.md)

## Forth 接线与算术

[验证器入口](../verifier.fth) 用三个带类型的步骤构造验证锁。所有者授权用 BIP143 ALL 校验实际花费的签名。[声明模块](../forth/statement.fth) 读取部署时选定的五个公开标量。最后一个词把声明交给 Rúnar，并将生成的证明谓词接在授权检查之后。后端核验锁定的公开标量及其 MSM，将其绑定到配对验证。[BN254 词表与链接器](../../../src/fourthgraph/verification/groth16_bn254.py)

[Go 适配器](../../../src/fourthgraph/verification/groth16_bn254_adapter.go) 调用固定版本的 Rúnar 编译器生成 BN254 群与域运算，并用其见证生成器拼装证明和算术辅助数据。Forth 描述授权与声明流程。Rúnar 将点检查、MSM、Miller 循环和余数校验一起生成链上谓词。[固定版本的 Rúnar 编译器](https://github.com/icellan/runar/blob/dbcc4269f8e0895c4738cf86948b05b7d62a2010/compilers/go/compiler/groth16_wa.go)

## 构建与回放

按项目主页准备依赖，并从仓库根目录运行 v0.1.0 的构建和回放命令。构建将锁产物和仅含入栈操作的证明前缀写到项目内的 `workspace/build/`。应用在前缀后追加对实际花费的所有者签名。此后端使用 Chronicle。[版本命令](../versions/v0.1.0/manifest.json)

夹具包含本地测试验证密钥与同一密钥下对应不同声明的两份证明。入金回放要求夹具的所有者与 regtest 的确定性操作者密钥一致，以部署与独立构建相同的锁。回放将锁定声明的证明打包入块，并验证拒绝另一声明的有效证明、取负的证明点、错误的 sighash 标记，以及修改输出后沿用旧签名的花费。[测试夹具](../versions/v0.1.0/fixture.json) · [原生验证证据](../versions/v0.1.0/measurements.json)
