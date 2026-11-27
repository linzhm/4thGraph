# 递归溯源：逻辑 CPN 草稿

此[模型](recursive-lineage-model.json)描述一次发行和可重复的转移。`state`
表示由延续 UTXO 承诺的状态，`proof` 表示需要时再次提供的链下证明产物。
CPN token 是建模概念，不代表 Bitcoin Script 栈或证明结果会跨交易保留。
发行及转移证据、基例、状态承诺、上一证明的验证、实际交易绑定都只是**要求**，
并非已经编译或验证的实现。

预期的递归关系需要在基例中验证指定发行；每一步验证上一份证明，将它的公开
状态和起源绑定到被消费状态，执行应用的状态转移，并将后继状态和不变的起源
绑定到新的证明。链上锁还须将声明绑定到实际消费的 outpoint 和有序输出。本
草稿未确定证明体系、验证密钥、编码、交易布局或隐私构造；实现这些内容后才
能声称具备相应性质。`require-zk` 是隐私要求，本身不提供隐私保证。Script
断言可以与零知识证明配合；暴露私有赋值的直接 Script 无法满足该要求。

逻辑数量分析器可以检查结构上的循环，不能证明循环安全或可执行。目前的线性
CPN 降级不支持这个分支、循环模型或递归证据，必须拒绝编译。
运行以下命令可以检查声明的状态、约束、证据、递归端口和基例引用；
这不验证递归关系、交易或链上状态。

```bash
4thgraph cpn inspect-evidence projects/workflow-examples/recursive-lineage-model.json
```

[English](recursive-lineage-model.md)
