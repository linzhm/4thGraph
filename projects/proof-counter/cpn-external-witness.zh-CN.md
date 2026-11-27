# 带外部见证的 CPN

[English](cpn-external-witness.md) ·
[公开输入模型](cpn-external-witness.json) ·
[私有输入模型](cpn-external-witness-private.json) ·
[Forth 定义](cpn-external-words.fth)

示例有两条迁移：`advance` 将公开的 `u32` 状态加一；`decide` 消费这个状态
和外部提供的 `delta` 并选择路径。Forth 先检查 `1 <= delta < 5`，再以 `u32`
回绕加法相加，最后调用已有的 `decide`。初始状态为 19、delta 为 1 时，
决策看到的是 21。`decide` 的第一个输入是状态，第二个是见证；Forth 栈的
输入顺序也一样。候选方案可以在一笔交易内部传递中间值，也可以用输出交接到
下一笔交易。

`delta-input` 是**链下输入**，不是比特币 UTXO，也不是跨交易持久保留的
Script 栈值。初始 CPN 标记表示输入可用，不表示存在已注资输出。公开模型
采用 `require-proof` 并明确允许披露完整赋值，因此可以选择透明 R1CS；R1CS
会公开赋值，**不是零知识**。当前实现不支持直接 Script 接收见证操作数，
即使策略允许直接验证，该候选也会以 `unsupported_witness_layout` 排除。

在仓库根目录安装项目依赖后运行：

```sh
mkdir -p workspace
cpn_example_dir=$(mktemp -d workspace/cpn-external.XXXXXX)
cp projects/proof-counter/{cpn-external-witness.json,cpn-external-words.fth,counter.fth} "$cpn_example_dir/"
export PYTHONPATH="src:.:${PYTHONPATH:-}"
python -m fourthgraph.workflow.protocol cpn test-keys > "$cpn_example_dir/keys.json"
python -m fourthgraph.workflow.protocol cpn tune-model "$cpn_example_dir/cpn-external-witness.json" \
  --source "$cpn_example_dir/cpn-external-words.fth" --output "$cpn_example_dir/workflow.fth" \
  --keys "$cpn_example_dir/keys.json" --current 19 --optimizations stack > "$cpn_example_dir/report.json"
python -m fourthgraph.workflow.protocol cpn verify-model "$cpn_example_dir/cpn-external-witness.json" \
  --source "$cpn_example_dir/cpn-external-words.fth" --workflow "$cpn_example_dir/workflow.fth" \
  --report "$cpn_example_dir/report.json" > "$cpn_example_dir/provenance.json"
printf '结果目录：%s\n' "$cpn_example_dir"
```

`test-keys` 产生确定性的**测试专用**密钥。可在 `report.json` 查看选中方案、
其他候选和排除原因。`verify-model` 检查模型、生成的 Forth、导入文件和报告
是否一致；它**不**重新搜索候选、执行交易、验证证明或检查链上状态。探索
本身没有提供见证值，也不会执行迁移。

要使用 `delta=1` 执行公开候选，请先按 [CPN 参考](../../skills/4thgraph/references/cpn.zh-CN.md)
安装 regtest 依赖和固定版本的 chain-gang，然后运行：

```sh
REGTEST_MIN_MINING_FEE=0.00000001 bash tools/verify_node.sh --profile long-script -- \
  python -m fourthgraph.workflow.protocol cpn replay "$cpn_example_dir/workflow.fth" \
  --report "$cpn_example_dir/report.json" --candidate 'fused/r1cs~stack' \
  --witness delta=1 --output "$cpn_example_dir/replay.json"
python -m fourthgraph.workflow.protocol cpn verify "$cpn_example_dir/replay.json" \
  --report "$cpn_example_dir/report.json" --candidate 'fused/r1cs~stack' > "$cpn_example_dir/verified.json"
```

此回放使用公开的测试密钥和本地 regtest。`verify` 检查保存的回执并用
chain-gang 重执行其中的交易输入；Node 结果是回放时记录的观察，不是当前链状态查询。

私有模型将见证可见性改为 `private` 并要求 ZK。可使用私有 JSON 和新的输出
路径检查：

```sh
cp projects/proof-counter/cpn-external-witness-private.json "$cpn_example_dir/"
if python -m fourthgraph.workflow.protocol cpn tune-model "$cpn_example_dir/cpn-external-witness-private.json" \
  --source "$cpn_example_dir/cpn-external-words.fth" --output "$cpn_example_dir/private-workflow.fth" \
  --keys "$cpn_example_dir/keys.json" --current 19 --optimizations stack > "$cpn_example_dir/private-report.json"; then
  printf '已选出候选。\n'
else
  printf '没有可选候选，请检查 private-report.json 和诊断。\n'
fi
python -m fourthgraph.workflow.protocol cpn verify-model "$cpn_example_dir/cpn-external-witness-private.json" \
  --source "$cpn_example_dir/cpn-external-words.fth" --workflow "$cpn_example_dir/private-workflow.fth" \
  --report "$cpn_example_dir/private-report.json" > "$cpn_example_dir/private-provenance.json"
```

没有匹配的证明参数时，私有示例会报告无可选候选：Script 和透明 R1CS 不能
满足私有策略，Groth16 则需要通过 `--backend-catalog` 提供匹配电路的参数。
必须具备合适的 ZK 后端、参数和实际证明，才能声称完成了私有验证。配置和
回放方法参见 [CPN 参考](../../skills/4thgraph/references/cpn.zh-CN.md)。
