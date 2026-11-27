# 4thGraph Forth 基线 · Forth baseline

4thGraph SDL 以 Forth 2012 的词和栈语义为基础，描述 BSV 锁定脚本、验证关系和多笔交易的依赖。工具链检查栈效果与数值范围，并按所选目标生成 Script、交易计划或电路。

基线由以下三份文档系列组成。复跑时记录仓库提交、编译器版本和 `4thgraph --capabilities`，用实际版本定位支持范围。

Record the repository revision, compiler version, and `4thgraph --capabilities` with each build. The following pages define the source-level baseline.

| 基线文档 · Baseline | 内容 · Scope |
| --- | --- |
| [语言规范 · Semantics](specification.md) | 类型、栈效果、数值和失败语义、宿主与 Script 的边界。 Types, stack effects, numeric and failure semantics, and the host/Script boundary. |
| [中文语法](syntax.md) · [English syntax](syntax.en.md) | 词法、词定义、导入和交易声明。 Tokens, definitions, imports, and transaction declarations. |
| [标准库](stdlib.zh-CN.md) · [Standard library](stdlib.md) | 公共模块、栈签名和使用前提。 Public modules, stack signatures, and preconditions. |

源码候选和编译器变换在编译期比较，并以同一业务约束和验收夹具核对。组装器使用所选构建产物。[中文架构](../architecture.zh-CN.md) · [编译与复放](../toolchain.md)

Compare source variants and compiler transformations at compile time under the same business contract and acceptance fixtures. The assembler consumes the selected build. [Architecture](../architecture.md) · [Workflow examples](../../projects/workflow-examples/README.md)
