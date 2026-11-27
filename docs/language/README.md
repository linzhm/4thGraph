# 4thGraph SDL

4thGraph SDL 以 Forth 2012 的词和栈语义为基础，描述 BSV 锁定脚本、验证关系和多笔交易的依赖。工具链检查栈效果与数值范围，并按所选目标生成 Script、交易计划或电路。

| 文档 | 内容 |
| --- | --- |
| [语言规范](specification.md) | Forth 语义、类型、栈效果、宿主词、BSV 扩展及编译目标 |
| [中文语法](syntax.md) · [English syntax](syntax.en.md) | 词定义、`REQUIRE`、公开入口、范围、验证关系和交易声明 |
| [标准库手册](stdlib.zh-CN.md) | 模块、公开词的栈签名、构建产物及验证路径 |
| [编译与复放](../toolchain.md) | 优化、构建报告、交易计划及复放 |
| [Gforth 工作流](../../projects/workflow-examples/gforth/README.md) | 使用 Forth 定义词创建阶段、解析资源和生成 Script |

从 [PELS Counter](../../projects/pels-counter/README.md) 开始编译一个状态转换，再用[工作流项目](../../projects/workflow-examples/README.md)查看交易拓扑与调度。
