# 交易工作流示例

[English](README.md) · [项目目录](../README.zh-CN.md)

**[编译一个词](#compile-a-word)** · [构建交易计划](../../docs/toolchain.md#交易与验证) · [Gforth 前端](gforth/README.md)

[并行分支](example.fth)、[带前置条件的分支](gated.fth)、[分叉与汇合](fork-join-graph.fth)和[串行状态](serial-graph.fth)展示了不同的交易依赖。[标准库示例](library-composition.fth)展示如何导入公共词。

<a name="compile-a-word"></a>

## 编译一个词

使用 Python 3.11 或更新版本，从仓库根目录运行。

```sh
PYTHONPATH=src:. python3 -m fourthgraph.workflow.protocol projects/workflow-examples/example.fth --entry inc
```

JSON 输出包含 `inc` 对应的 Script。用同一份源码比较完整交易计划时，从复放报告获取测试角色的公钥和任务 ID。[构建与复放教程](../../docs/toolchain.md#复放与编译)
