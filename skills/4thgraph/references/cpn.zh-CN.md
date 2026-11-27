# 构建、调优和验证分阶段 CPN

[English](cpn.md) · [4thGraph skill](../SKILL.md) · [工作流设计](../../../docs/design/README.zh-CN.md)

比较候选时保持 Forth 关系、公开状态、私有操作数、签名角色和交易需求一致。要求阶段在同一笔交易完成时使用 `atomic:`，要求能够单独提交时使用 `independent-submit:`。只有允许公开整个赋值时，才为 R1CS 阶段写 `assignment-disclosure: STAGE allow ;`。`require-zk` 和私有见证都会排除直接 Script 与透明 R1CS。

## 使用交互工作台

装好下文的 regtest 依赖与 Node.js 后，从仓库根目录运行 `bash tools/cpn_demo.sh`，打开 `workspace/cpn-demo/index.html`。这条命令用同一份 Forth 编译、入金并验证三条路径，生成可单独离线打开的 HTML。源码、后端目录、原始报告和复放回执留在同一目录。

先看逻辑图。Place 描述接口上的状态，Transition 声明消费的输入和生产的输出。点选迁移可查看类型化计算、Forth 词和验证策略。外部信息可包含见证操作数、角色签名和证明包。交易图将这些接口映射到部署或花费中的有序 `vin`、`vout`。

选择 `path/handoff~stack` 追踪两笔交易之间的 `next: u32`。在逻辑图点选 `next`，可查看它由后继 UTXO 承载。在交易图点选对应的状态输出，可看到金额、解出的状态、工作流根、产出槽位和消费输入。实际 outpoint 来自复放回执。融合布局可以在当前输入栈中交接同一个值。零金额公开回执是携带序列化数据的不可花费输出。

对现有构建运行 `4thgraph cpn workbench REPORT --receipt RECEIPT --output index.html`。重复传入 `--receipt` 可关联多个实测候选。传入 `--source SOURCE` 可显示经摘要核对的 Forth 定义。从详情下载固定计划、规划报告和已有回执。接收方可用固定版本的 chain-gang 执行 `4thgraph cpn verify receipt.json --report report.json` 离线复核。需要重建时，再一同保留 Forth 源码、目录与设置文件。

## 从干净检出开始跑纯 Script

在仓库根目录运行，使用 Python 3.11 或更新版本的虚拟环境。第一条命令安装生成测试公钥、入金复放和离线复验所需的依赖。使用由同一份检出构建的 CLI。 [安装 CLI](../../../docs/install.zh-CN.md)

```sh
python -m pip install ecdsa -r tools/requirements-chronicle.txt
OUT="$PWD/workspace/cpn-dev"
SOURCE=projects/proof-counter/workflow.fth
mkdir -p "$OUT"
4thgraph --version
4thgraph cpn test-keys > "$OUT/keys.json"
4thgraph cpn tune "$SOURCE" --keys "$OUT/keys.json" --current 19 --target both > "$OUT/tune.json"
4thgraph cpn plan "$SOURCE" --select-candidate "$OUT/tune.json" 'fused/script~stack' --cpn-plan > "$OUT/plan.json"
REGTEST_MIN_MINING_FEE=0.00000001 bash tools/verify_node.sh --profile long-script -- \
  4thgraph cpn replay "$SOURCE" --report "$OUT/tune.json" --candidate 'fused/script~stack' --output "$OUT/replay.json"
4thgraph cpn verify "$OUT/replay.json" --report "$OUT/tune.json" --candidate 'fused/script~stack' > "$OUT/verified.json"
```

只使用一个编译优化级别时用 `plan`。`tune` 默认比较 `baseline`、`safe` 和 `stack`，候选 ID 带 `~PROFILE` 后缀。用 `--optimizations` 限定优化级别，用 `--objective`、`--max-tx-bytes`、`--max-lock-bytes` 或 `--max-constraints` 调整搜索。查看 `schedule_explanation.ranked_candidates`、`rank_order` 与每项的成本、后端和淘汰原因。没有合格候选时，命令退出并输出诊断和 JSON 报告。保留源码及导入、原始报告、所选 ID 和规范计划。

`replay` 在本地隔离 regtest 上用固定测试密钥运行。读取回执中的真实交易字节、合计栈载荷、准备时间和引擎耗时。`verify` 核对构建和计划摘要，用回执里的父交易和区块高度重新运行 chain-gang，并复查重排输出反例。节点入池和入块结果来自原始复放记录。如需重新观察节点行为，再运行一次入金复放。需要完整 STARK 嵌套验证或链上递归溯源的路径会保留声明并报告为不可部署。

## 组合 R1CS 与 Groth16

用 Node.js 和 npm 为 `decide` 阶段生成**仅供测试**的 BLS12-381 参数，再提供后端目录。第一阶段公开 R1CS 赋值，第二阶段用 Groth16 证明。两个输入都约束同一个中间值和有序输出。

```sh
MIX="$OUT/mixed"
mkdir -p "$MIX/setup"
cp projects/proof-counter/counter.fth "$MIX/counter.fth"
cp "$SOURCE" "$MIX/workflow.fth"
printf '\nassignment-disclosure: advance allow ;\n' >> "$MIX/workflow.fth"
4thgraph-circuit "$MIX/workflow.fth" --stage decide --output "$MIX/setup/decide.circom"
(
  set -e
  cd "$MIX/setup"
  snarkjs() { npx --yes --package=snarkjs@0.7.5 snarkjs "$@"; }
  npx --yes --package=circom2@0.2.22 circom2 decide.circom --r1cs --O1 --prime bls12381
  snarkjs powersoftau new bls12381 9 start.ptau
  snarkjs powersoftau contribute start.ptau contributed.ptau --name="regtest" -e="4thGraph local regtest fixture"
  snarkjs powersoftau prepare phase2 contributed.ptau phase2.ptau
  snarkjs groth16 setup decide.r1cs phase2.ptau start.zkey
  snarkjs zkey contribute start.zkey decide.zkey --name="regtest" -e="4thGraph local regtest stage fixture"
)
cat > "$MIX/catalog.json" <<'JSON'
{
  "groth16-bls12-381": {"decide": {"zkey": "setup/decide.zkey", "ptau": "setup/phase2.ptau"}},
  "workflow_paths": {
    "settlement": {"layout": "atomic", "stages": {
      "advance": {"role": "计算下一状态", "backend": "r1cs"},
      "decide": {"role": "选择结算结果", "backend": "groth16-bls12-381"}
    }}
  }
}
JSON
4thgraph cpn tune "$MIX/workflow.fth" --keys "$OUT/keys.json" --current 19 --target both \
  --backend-catalog "$MIX/catalog.json" > "$MIX/tune.json"
REGTEST_MIN_MINING_FEE=0.00000001 bash tools/verify_node.sh --profile long-script -- \
  4thgraph cpn replay "$MIX/workflow.fth" --report "$MIX/tune.json" --candidate 'path/settlement~stack' \
  --backend-catalog "$MIX/catalog.json" --output "$MIX/replay.json"
4thgraph cpn verify "$MIX/replay.json" --report "$MIX/tune.json" --candidate 'path/settlement~stack' > "$MIX/verified.json"
```

保留原构建使用的 `.zkey`、`.ptau` 和目录文件。更换设置会改变部署锁。使用私有末段示例时，为其 `decide` 电路单独生成设置，只在测试复放时传 `--witness delta=1`。比较相关边界状态，记录实际验证过的源码、输出和引擎。 [私有见证示例](../../../projects/proof-counter/workflow-private.fth) · [交易绑定和测试用例](../../../docs/design/README.zh-CN.md#首版接入和验证)
