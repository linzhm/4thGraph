<!-- Generated from manifest.yaml with Copier. -->

# 交易工作流示例 v0.1.0

[English](README.md) · [4thGraph](../../README.zh-CN.md) · [项目目录](../README.zh-CN.md) · [版本](versions/index.json)

## 开发入口

将 Forth 示例编译成 Bitcoin Script，再复放具有不同依赖关系的交易计划。

[算法与执行](#算法与执行) · [复现方法](#复现方法)

| 入口 | 用途 |
| --- | --- |
| `4thgraph --entry inc` | 编译递增词，在构建报告中返回 Script。 |

## 算法与执行

**[编译一个词](#compile-a-word)** · [构建交易计划](../../docs/toolchain.md#交易与验证) · [Gforth 前端](gforth/README.md)

[并行分支](example.fth)、[带前置条件的分支](gated.fth)、[分叉与汇合](fork-join-graph.fth)和[串行状态](serial-graph.fth)展示了不同的交易依赖。[标准库示例](library-composition.fth)展示如何导入公共词。

[PELS 结算示例](pels-settle.fth)约定一个输入和两个有序输出。用 [Agent 调优循环](../../docs/README.zh-CN.md#agent-tuning-loop)比较构建候选并验证结果。

## 复现方法

使用 Python 3.11 或更新版本及工作流测试依赖，从仓库根目录运行版本命令。[Gforth 测试环境](gforth/README.md)

```sh
python -m pip install ecdsa -r tools/requirements-chronicle.txt
```

```sh
PYTHONPATH=src:. python -m fourthgraph.workflow.protocol projects/workflow-examples/example.fth --entry inc
PYTHONPATH=src:. python -m unittest discover -s tests -p test_workflow_forth.py
```

<a name="compile-a-word"></a>

### 编译一个词

使用 Python 3.11 或更新版本，从仓库根目录运行。

JSON 输出包含 `inc` 对应的 Script。用同一份源码比较完整交易计划时，从复放报告获取测试角色的公钥和任务 ID。[构建与复放教程](../../docs/toolchain.md#复放与编译)
