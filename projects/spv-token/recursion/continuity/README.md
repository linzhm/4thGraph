# CCTP 自验证连续性电路

同一 BLS12-381 Groth16 电路验证零至两份前序证明。真实前序使用同一份见证验证密钥。电路重算该密钥的 `keycommit` 摘要，并把摘要纳入当前公开语句。验证密钥在电路之外由 setup 生成，电路中没有写入其常量。BSV 锁采用同一 setup 的真实验证密钥，并固定对应的 `continuity_key_digest`。

公开输入是以下双 SHA-256 摘要顺序拆成的两个大端 uint128。

```text
SHA256d("BSV/CCTP/continuity/v1\0" || asset[32] || selfKeyDigest[32] ||
        transactionContext[32] || count[u8] || priorDigest0[32] || priorDigest1[32])
```

`count` 为 0、1 或 2，前序依次占用前 `count` 个槽，未用摘要必须为零。电路用同一个固定的小型 BSB22 padding 密钥和证明校验每个未用槽，选择器决定是否改用真实前序。两个前序摘要可以相等，BSV 的实际 outpoint 检查负责判断是否引用重复消费。电路验证了密钥归属与前序证明，BSV 负责认证真实交易、资产及父摘要，并在 `count=0` 分支执行合法铸造关系。单独的零前序证明不提供铸造授权。测试 setup 不能用于托管资产。

本版本编译到 8,062,485 条 R1CS 约束，含一个无公开索引的 BSB22 承诺。设置 `CCTP_CONTINUITY_SOLVER_TEST=1` 运行完整约束分派检查。它用两套独立的小型 BSB22 密钥给同一个摘要出证，使电路接受零、一、两个前序的有效形状，并拒绝摘要相同但来自另一密钥的证明。该检查使用求解器的测试挑战，独立于本电路完整 setup 和真实递归出证。

原生测试用同一把密钥验证了两份零前序证明、引用这两份证明的双前序证明，以及引用该递归证明的单前序证明。测试 setup 用时 18 分 7.6 秒，证明密钥约 2.5 GiB，四次出证各用 38.7 至 42.6 秒。两代递归证明均通过 Python 摘要重建、Script 和 chain-gang 验证。此组使用合成交易上下文。证明材料、四个负例和参数指纹见 [测试记录](testdata/native-demo-summary.json)。

Bitcoin SV Node 1.2.3 在独立验证器消费中接受第二代递归证明并于 regtest 高度 103 入块。节点在同一验证器 UTXO 上拒绝改写的知识证明。该次入块验证证明字节和 BSB22 Script，实代币的铸造、槽位和后继由下文的独立联测覆盖。

在 `projects/spv-token/recursion` 运行 Go 命令。`probe` 用嵌入的小型 BSB22 样例验证零前序 R1CS 形状。`demo` 生成一套独立参数和连续证明。`setup` 只生成参数，`prove` 复用已有参数并从前序证明 JSON 提取实际公开摘要。

```sh
go test ./continuity
go run ./continuity -mode probe
go run ./continuity -mode demo -dir /tmp/cctp-continuity-demo
go run ./continuity -mode prove -dir /tmp/cctp-continuity-demo \
  -asset ASSET_HEX32 -context CONTEXT_HEX32 -out /tmp/child.json \
  /tmp/cctp-continuity-demo/recursive-two.json
```

`key.json` 含验证密钥、承诺参数和 `continuity_key_digest`。证明文件加上各公开输入和扩展承诺字段，可用现有 Python `committed_verifier.load_artifact` 解析。`continuity` 元数据记录标准摘要材料。验证以公开输入和 BSV 提供的认证交易材料为准。保留本地 `proving.key`、`verifying.key` 和 `circuit.txt` 可以重新出证；程序拒绝加载不同约束指纹的缓存。

连续生成多笔交易时可运行 `go run ./continuity -mode session -dir /tmp/cctp-continuity-demo`。同一进程只加载一次参数。标准输出先返回包含 `ready` 和 `continuity_key_digest` 的 JSON 行，随后每个请求返回一行 JSON。诊断信息写入标准错误。以下是一条请求示例。

```json
{"id":"merge","asset":"ASSET_HEX32","context":"CONTEXT_HEX32","prior":["/tmp/left.json","/tmp/right.json"],"out":"/tmp/merged.json"}
```

成功回复包含 `ok:true`、`out` 和 `digest`，失败回复包含 `ok:false` 和 `error`。如有 `id` 则原样返回。输入关闭时会话退出。

从仓库根目录可对独立 BSV regtest 执行认证铸造和 MIMO。运行程序使用两笔隔离测试入金签发，依次入块首笔铸造、前序绑定铸造、2→2 转账和后续 1→2 转账。每步记录原始交易、证明、公开输入和区块。节点须启用 txindex 和 Chronicle，使用足够的实验脚本、栈及交易大小限额，并提供回环 RPC 地址及 cookie。

```sh
go -C projects/spv-token/recursion build -o /tmp/cctp-continuity ./continuity
PYTHONPATH=.:projects/spv-token:projects/groth16/reference:projects/spv-token/reference:projects/spv-token/recursion \
  ../cctp-test-tools/venv/bin/python projects/spv-token/recursion/run_continuity_regtest.py \
  --node-url "$REGTEST_URL" --cookie "$REGTEST_COOKIE" \
  --prover /tmp/cctp-continuity --setup-dir /tmp/cctp-continuity-demo \
  --out /tmp/cctp-continuity-regtest
```

[实际交易节点记录](../../fixtures/v3-continuity-regtest-summary.json) 覆盖高度 211–214 的两笔认证铸造、2→2 和后继 1→2。最后一笔交易为 15,081,190 字节，最大输入脚本为 14,106,366 字节。归档包含真实交易及全量证明，入金采用隔离测试签发。该配置测试了认证铸造和转账，带认证回执的冻结与解冻另有本地 Script 验证。

追加 `--mint-state-version 2` 可用累计净铸造量状态重跑。同一连续性密钥在独立 BSV Node 1.2.3 的高度 224–227 确认了两笔认证铸造及后继的 2→2、1→2。第二笔铸造消费第一笔的状态，累计净铸造量从 1,024 增至 1,408。两笔转账分别为 12,162,612 和 15,082,186 字节。这组基线仍携带完整父交易，转账形状也不同，固定形状的历史增量由新版联合证明单独验收。 [计数状态节点记录](../../fixtures/v3-counted-continuity-regtest-summary.json)

## 在电路内认证父布局和重建摘要

从 `projects/spv-token/recursion` 运行：

```sh
CCTP_CONTINUITY_SOLVER_TEST=1 go test -count=1 \
  -run 'Test(ChronicleParentStatementUsesTheSelectedLayout|ReconstructedParentsFeedTheRecursiveVerifier)$' -v ./continuity
```

单槽测试用 266 字节铸造形状和 295 字节转账形状，与 Python 原有 OTDA 和回执编码得到的摘要逐字节核对。覆盖实际 verifier outpoint、错 vout、替换摘要、回执前缀、非零填充和错误签名类型的序列。先选择预像及回执，再共用一次预像哈希和一次声明哈希，单槽测试由 912,161 条降到 583,954 条约束。双槽测试将重建的摘要接到现有同密钥递归验签。两份前序测试证明由同一个小型 BSB22 电路原生证明，替换成相同密钥下另一笔的证明失败。该组合求解有 9,301,078 条约束。测试使用合成交易和前序关系，完整铸造、守恒规则、对当前交易的链上绑定及连续入块由新版验收覆盖。

四输出测试使用 77 字节新版回执，复用按实际 `txid:vout` 打开父输出的逻辑。对每个实际代币输入重建并验证前序摘要，核对全部四个后继的同一资产、策略、Token 数量及 satoshi。固定专用电路的 1→4 和 4→4 分别为 5,790,214 和 17,092,424 条约束。测试使用真实的同密钥前序测试证明，并对改量后重算公开输入的交易求解。 [字节模型和适用范围](../../docs/recursive-provenance.md#四输出的转账形状)

```sh
CCTP_CONTINUITY_SOLVER_TEST=1 go test -count=1 \
  -run '^TestWireTransfersBindBalanceAndProofForOneOrFourParents$' -v ./continuity
CCTP_CONTINUITY_SLOT_TEST=1 go test -count=1 \
  -run '^Test(PredecessorProofSlots|ContinuityV1ConstraintFingerprint)$' -v ./continuity
```

## 本地双链闭环

安装 Foundry 并把 `forge`、`cast`、`anvil` 放入 `PATH`。下列程序启动隔离 Anvil 测试储备，连接已有的独立 BSV regtest，使用同一份连续性参数为十笔状态及代币交易出证。签发恢复、源链确认及余额对账使用持久 BridgeService。

```sh
PYTHONPATH=.:projects/spv-token:projects/groth16/reference:projects/spv-token/reference:projects/spv-token/recursion \
  ../cctp-test-tools/venv/bin/python projects/spv-token/recursion/run_certified_lifecycle.py \
  --node-url "$REGTEST_URL" --cookie "$REGTEST_COOKIE" \
  --prover /tmp/cctp-continuity --setup-dir /tmp/cctp-continuity-demo \
  --out /tmp/cctp-certified-cross-chain
```

[验收摘要](../../fixtures/v3-certified-cross-chain-regtest-summary.json) 记录冻结及解冻、部分和全额销毁、暂停后恢复铸造、两笔释放及钱包验收。[压缩归档](../../fixtures/v3-certified-cross-chain-regtest.json.xz) 保存原始 BSV 交易、证明和四份最终确认的 Anvil 回执。此实测采用实验节点策略及测试参数，后续容量和公开网络验收应分别记录其节点政策。

在专用 regtest 上追加 `--reorg-probe`，可在最后一次释放后临时撤销对应 BSV 销毁块。程序用账本副本核对持久挂起及签发拦截，再恢复原 BSV 链头。
