# 构建、调优和验证分阶段 CPN

[English](cpn.md) · [4thGraph skill](../SKILL.md) · [工作流设计](../../../docs/design/README.zh-CN.md)

比较候选时保持 Forth 关系、公开状态、私有操作数、签名角色和交易需求一致。要求阶段在同一笔交易完成时使用 `atomic:`，要求能够单独提交时使用 `independent-submit:`。只有允许公开整个赋值时，才为 R1CS 阶段写 `assignment-disclosure: STAGE allow ;`。`require-zk` 和私有见证都会排除直接 Script 与透明 R1CS。

## 使用交互工作台

新建逻辑模型时运行 `4thgraph cpn design --output workspace/cpn-draft.html`，打开生成的离线编辑器。添加 Place 和 Transition、连接类型化端口，并将模型导出为 JSON。节点元数据可记录 Forth 代码、断言、见证、授权、证明方式和状态载体。

[递归溯源模型](../../../projects/workflow-examples/recursive-lineage-model.zh-CN.md)展示发行、延续 UTXO 和链下证明产物。运行 `4thgraph cpn inspect-evidence projects/workflow-examples/recursive-lineage-model.json` 可汇总声明，并检查递归端口和基例引用。这只是结构检查，不会编译或验证递归、交易、隐私或链上状态。

运行 `4thgraph cpn check-model projects/workflow-examples/token-model.json` 可以检查双输入、双输出的 Token 数量循环，也可传入编辑器导出的模型。有界分析枚举标记中的 Token 数量，报告访问到的状态、迁移、死锁和触及的边界。分析结果是过近似，不求值 Token 内容、Forth、守卫、授权、时序、交易有效性或元数据。Token 模型用于描述设计要求。

当前支持的线性子集可用 `4thgraph cpn lower-model MODEL --source WORDS.fth --output WORKFLOW.fth` 生成分阶段工作流，输出文件须与 Forth 源码位于同一目录。声明一个初始 Token、每个 Place 容量为 1、公开 `u32` 状态以 `route` 结尾、每个迁移一个输入和输出及一个授权角色。无法降级的图或要求会被拒绝。对生成的工作流运行 `4thgraph cpn plan` 或 `tune`，并与导入的 Forth 文件和报告一起保存。

可以用 `4thgraph cpn tune-model MODEL --source WORDS.fth --output WORKFLOW.fth --keys KEYS.json --current 19 > report.json` 一步完成降级和探索。它接受 `cpn tune` 的搜索预算和后端目录，不会覆盖已有工作流；生成的 Forth 注释包含原始模型的 SHA-256，并受到编译器源码摘要保护。请保存模型、生成的工作流、导入和报告；重新运行降级可核对它们的关系。没有合格候选时仍会输出淘汰报告，并以非零状态退出。

运行 `4thgraph cpn verify-model MODEL --source WORDS.fth --workflow WORKFLOW.fth --report report.json`，可重新降级模型，逐字节比较包含模型摘要的工作流，并核对报告的源码和导入摘要；对已选择的构建，还会检查内部计划和构建摘要。它不会重新探索候选、验证证明、执行交易或检查链状态；复验回执应使用 `cpn verify`。

末段迁移可增加第二个 `u32` 输入，来自初始可用、容量为 1 的 Place，其元数据须显式声明 `"carrier": "external-witness"` 和 `"visibility": "public"` 或 `"private"`。第一个输入是状态，第二个是外部见证。见证由链下提供，并非已认证的 UTXO。当前只支持一个此类见证，且不能同时声明见证元数据；私有见证需要兼容的零知识后端，直接 Script 和透明赋值不符合要求。参见[公开和私有外部见证示例](../../../projects/proof-counter/cpn-external-witness.zh-CN.md)。

迁移可声明 `"atomic_with": ["other-transition"]`，要求两阶段在同一笔交易执行；也可声明 `"independent_submit": true`，要求该阶段能够独立提交。降级器将要求转换为工作流声明，规划器淘汰不符合要求的布局。要求冲突时可能没有合格候选。这些声明适用于当前支持的线性子集，并不代表已支持任意 CPN 拓扑的编译。

可以在独立目录中运行[线性模型](../../../projects/proof-counter/cpn-linear.json)和 [Forth 导入](../../../projects/proof-counter/cpn-words.fth)：

```sh
mkdir -p workspace/cpn-linear
cp projects/proof-counter/{cpn-linear.json,cpn-words.fth,counter.fth} workspace/cpn-linear/
4thgraph cpn lower-model workspace/cpn-linear/cpn-linear.json --source workspace/cpn-linear/cpn-words.fth \
  --output workspace/cpn-linear/workflow.fth
4thgraph cpn test-keys > workspace/cpn-linear/keys.json
4thgraph cpn plan workspace/cpn-linear/workflow.fth --keys workspace/cpn-linear/keys.json \
  --current 19 --target both > workspace/cpn-linear/report.json
```

末段迁移的 `metadata.witnesses` 可声明 `name`、`type: "u32"` 及 `visibility: "public"` 或 `"private"`。例如 `"witnesses": [{"name":"delta","type":"u32","visibility":"private"}]` 搭配 `"evidence": [{"policy":"require-zk"}]` 会生成对应的 Forth 声明。计算词按顺序接收状态和声明的见证。匹配电路的设置通过后端目录提供。允许公开赋值时，可在兼容的策略中设置 `"assignment_disclosure":"allow"`。规划器仍会逐项检查候选。

迁移也可声明一条结构化范围约束，例如 `{"kind":"range","operand":"delta","range":"private-delta"}`。Forth 源码须声明对应的 `u32` 范围，该操作数须位于入口栈顶，计算词须以匹配的 `check-range` 开始。编译器核对所选 Script 和适用电路包含该检查。其他约束需要各自的降级实现。

已有 CCTP 归档提供了另一组历史输入。在包含提交 `11c919a` 的检出中运行下列命令，再把生成的模型导入编辑器。检查器核对序列化交易标识、槽位、Token 模板、所记录数量，以及每个 outpoint 在所选归档交易中是否只消费一次。同一交易的不同输出槽位是不同的 outpoint；检查无法发现所选子图之外的花费。逻辑模型的初始标记描述归档子图的边界。Script 执行、发行授权、区块包含和当前 UTXO 状态需要各自的证据。

```sh
mkdir -p workspace/cpn-dev
git show 11c919a:projects/spv-token/fixtures/covenant-backtrace-2x2-regtest.json.xz > workspace/cpn-dev/cctp.json.xz
4thgraph cpn inspect-cctp workspace/cpn-dev/cctp.json.xz --logical > workspace/cpn-dev/cctp-model.json
4thgraph cpn check-model workspace/cpn-dev/cctp-model.json > workspace/cpn-dev/cctp-analysis.json
4thgraph cpn inspect-cctp workspace/cpn-dev/cctp.json.xz --flow-report > workspace/cpn-dev/cctp-flow.json
4thgraph cpn design --model workspace/cpn-dev/cctp-model.json --output workspace/cpn-dev/cctp.html
```

固定归档的 2→2 测试适配器 `construct_fixture_spend` 接收该归档、匹配的逻辑模型、两个新输出和外部签名回调，使用归档里的验证器资金、有序 Token 前序和父交易开封证明来构造交易及 CPN 端口。该夹具固定归档摘要，前序 outpoint 改变时不能复用证明。返回值描述待提交的交易。设置 `CCTP_ARCHIVE=workspace/cpn-dev/cctp.json.xz`，运行 `bash tools/verify_node.sh --profile long-script -- python -m unittest tests.test_cctp_transfer_fixture`，可用归档父交易作为上下文，在 BSV Node 的 `verifyscript` 和 chain-gang 上验证公开测试夹具。

运行 `4thgraph cpn fixture-declaration workspace/cpn-dev/cctp.json.xz > workspace/cpn-dev/transfer.json` 可以得到显式 CPN，包含三个固定输入 Place、一个 Transition 和两个符号输出 Place。Python 入口 `construct_declared_fixture_spend` 在调用外部签名器前检查声明的端口、授权、证据和约束，返回待提交交易并将输出 Place 映射到结果 outpoint。调用方可在保留固定要求的同时重命名逻辑节点。

下面的命令使用公开测试密钥生成夹具和可离线打开的只读图。`verify-fixture` 将 CPN 声明（包括有序父 outpoint、授权和证据标签）与代码中固定的归档声明摘要比较；核对实际证明和公开输入字节的摘要，以及交易和 Place 的实际数据，并使用固定版本的 chain-gang 根据提供的父交易重新检查花费。发行点和验证密钥标签来自固定归档，不能独立证明发行授权或区块包含。包里的 Node 结果是未经认证的历史记录。这些检查不证明当前 UTXO 状态、入池或确认。将快照复制为草稿会移除其验证关联。

```sh
bash tools/verify_node.sh --profile long-script -- python -m fourthgraph.replay.cctp_fixture \
  workspace/cpn-dev/cctp.json.xz --output workspace/cpn-dev/fixture.json
4thgraph cpn verify-fixture workspace/cpn-dev/fixture.json > workspace/cpn-dev/fixture-check.json
4thgraph cpn fixture-workbench workspace/cpn-dev/fixture.json --output workspace/cpn-dev/fixture.html
```

装好下文的 regtest 依赖与 Node.js 后，从仓库根目录运行 `bash tools/cpn_demo.sh`，打开 `workspace/cpn-demo/index.html`。这条命令用同一份 Forth 编译、入金并验证三条路径，生成可单独离线打开的 HTML。源码、后端目录、原始报告和复放回执留在同一目录。

先看逻辑图。Place 描述接口上的状态，Transition 声明消费的输入和生产的输出。点选迁移可查看类型化计算、Forth 词和验证策略。外部信息可包含见证操作数、角色签名和证明包。交易图将这些接口映射到部署或花费中的有序 `vin`、`vout`。

选择 `path/handoff~stack` 追踪两笔交易之间的 `next: u32`。在逻辑图点选 `next`，可查看它由后继 UTXO 承载。在交易图点选对应的状态输出，可看到金额、解出的状态、工作流根、产出槽位和消费输入。实际 outpoint 来自复放回执。融合布局可以在当前输入栈中交接同一个值。零金额公开回执是携带序列化数据的不可花费输出。

对现有构建运行 `4thgraph cpn workbench REPORT --receipt RECEIPT --output index.html`。重复传入 `--receipt` 可关联多个实测候选。传入 `--source SOURCE` 可显示经摘要核对的 Forth 定义。从详情下载固定计划、规划报告和已有回执。接收方可用固定版本的 chain-gang 执行 `4thgraph cpn verify receipt.json --report report.json` 离线复核。需要重建时，再一同保留 Forth 源码、目录与设置文件。

在交易视图中使用已记录复放控件，可逐步查看部署和每次花费。图上会标出当前 Transition 以及消费、产生的 Place；面板展示回执中的 txid、区块高度、交易字节和有序 outpoint。这里展示的是已保存的观察结果，当前链状态需要重新查询节点。

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
