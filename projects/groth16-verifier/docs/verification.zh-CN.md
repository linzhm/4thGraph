# Groth16 验证器构建与回放

[English](verification.en.md) · [项目介绍](../README.zh-CN.md)

## Forth 调用与输入

项目通过标准库导入调用 `groth16-bls12-381-verify`。Forth 的返回类型表示证明校验成功。证明无效时 Script 终止。应用可以在验证器外组合签名授权和交易绑定。[项目源码](../verifier.fth) · [验证器接口](../../../docs/groth16-bls12-381.md)

```forth
REQUIRE stdlib/groth16-bls12-381.fth

: verify-proof ( -- groth16-verified )
    groth16-bls12-381-verify
;
```

演示使用证明计数器 v0.1.0 的公开测试验证密钥和两份证明。五个公开输入按验证密钥的槽位顺序在花费时提供，位宽依次为 32、1、32、2 和 2 位。[证明夹具](../../proof-counter/versions/v0.1.0/bls12381-counter.json) · [输入配置](../versions/v0.1.0/input-sources.json)

## 构建与回放

在仓库根目录运行项目介绍中的构建和验证命令。构建通过 BLS12-381 后端选择 `verify-proof`，以 Genesis Script 为目标，按 `path-bytes` 选择见证布局。构建保存锁定脚本清单和 `wrap` 夹具的 push-only 见证。锁定脚本清单记录导入的标准库及入口名。[构建与验证命令](../README.zh-CN.md#复现方法)

入金回放使用 BSV Node 1.2.3 和固定的 chain-gang 绑定。回放为每份证明分别部署同一把锁，两笔 v2 花费都在 Chronicle 激活前入块。每组用例中，两种引擎都拒绝互换公开声明和 G1 点不在素数阶子群内的证明。命令将结果写到 `projects/groth16-verifier/workspace/build/`。[引擎版本](../../../tools/requirements-chronicle.txt)

## 测量与证据

v0.5.0 沿用相同的公开输入配置和证明夹具，比较自动操作数调度与 v0.4.0 构建。布局目标计量锁与见证脚本的序列化字段。入金回放计量完整部署和花费，包含资金输入签名与交易结构。栈峰值由开发求值器按栈内数据的字节数测量。[v0.5.0 操作数实测](../versions/v0.5.0/measurements.json) · [v0.4.0 字节包实测](../versions/v0.4.0/measurements.json) · [版本索引](../versions/index.json)

复现 Chronicle 回放时，设置 `REGTEST_CHRONICLE_HEIGHT=2`，传入 `--script-era chronicle` 并使用单独的输出文件。在任一 Script 时代指定回放布局时，将 `--objective path-bytes` 改为 `--witness-layout affine-witness` 或 `--witness-layout projective`。
