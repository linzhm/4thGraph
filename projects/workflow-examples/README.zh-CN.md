<!-- Generated from manifest.yaml with Copier. -->

# CPN 工作流示例 v0.1.0

[English](README.md) · [4thGraph](../../README.zh-CN.md) · [项目目录](../README.zh-CN.md) · [版本](versions/index.json)

## 开发入口

将 Forth 工作流编译成 BSV 交易计划，对照生成的 CPN、候选代价和入金复放。

[算法与执行](#算法与执行) · [复现方法](#复现方法)

| 入口 | 用途 |
| --- | --- |
| `4thgraph --cpn` | 用 Mermaid 绘制选定的交易图。用 --cpn-plan 导出其规范编码。 |
| `4thgraph --search --explain` | 比较受支持的交易边界，并解释所选布局。 |

## 算法与执行

[CPN 架构](../../docs/architecture.zh-CN.md#cpn-规划与验证) · [SPV Token 编译设计](../../docs/design/README.zh-CN.md#spv-token-cpn)

[带前置条件的工作流](gated.fth)先验证前置条件，再处理两条分支并汇合结果。编译器可以融合整条流程、将前置条件与拆分合并，或独立提交前置条件。同一份源码用于候选搜索和入金复放。

[并行分支](example.fth)、[分叉与汇合](fork-join-graph.fth)和[串行状态](serial-graph.fth)展示其他依赖形状。[标准库示例](library-composition.fth)导入公共 Forth 词。[Gforth 前端](gforth/README.md)从 Forth 定义构建交易计划。

## 复现方法

从仓库根目录运行，使用 Python 3.11 或更新版本及 jq。入金复放需要安装工作流和 regtest 依赖。 [Regtest 环境](../../docs/toolchain.md#复放与编译)

```sh
python -m pip install ecdsa -r tools/requirements-chronicle.txt
```

```sh
PYTHONPATH=src:. python -m fourthgraph.workflow.protocol projects/workflow-examples/example.fth --entry inc
PYTHONPATH=src:. python -m unittest discover -s tests -p test_workflow_forth.py
```

<a name="compile-and-replay-a-cpn"></a>

### 编译与复放 CPN

运行带前置条件的夹具以验证结算和复核路径。用复放记录中的测试公钥和任务 ID 重建同一计划，生成候选报告、Mermaid 图和规范 JSON。

```bash
export PYTHONPATH=src:.
out=projects/workflow-examples/workspace/build
mkdir -p "$out"

bash tools/verify_node.sh --profile default -- \
  python -m fourthgraph.replay.workflow --search --topology gated-parallel \
  --target both --optimize stack --samples 1 --output "$out/cpn-replay.json"

jq -e '.fixture_public_keys' "$out/cpn-replay.json" > "$out/cpn-keys.json"
task=$(jq -er .task_id "$out/cpn-replay.json")
cpn=(python -m fourthgraph.workflow.protocol projects/workflow-examples/gated.fth
     --keys "$out/cpn-keys.json" --task-id "$task" --target both --optimize stack --search)

"${cpn[@]}" --explain > "$out/cpn-build.json"
"${cpn[@]}" --cpn > "$out/cpn.mmd"
"${cpn[@]}" --cpn-plan > "$out/cpn-plan.json"
python -m fourthgraph.reporting "$out/cpn-replay.json" --output-dir "$out/cpn-decision"
```

用 `cpn-build.json` 的 `plan_sha256` 标识选中计划。决策报告对照各候选的估算和实测字节、验证与确认结果。

<a name="compile-a-word"></a>

### 编译一个词

上方的版本命令也能编译独立的 `inc` 词并运行工作流测试。
