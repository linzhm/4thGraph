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

在 `projects/cctp/recursion` 运行 Go 命令。`probe` 用嵌入的小型 BSB22 样例验证零前序 R1CS 形状。`demo` 生成一套独立参数和连续证明。`setup` 只生成参数，`prove` 复用已有参数并从前序证明 JSON 提取实际公开摘要。

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
go -C projects/cctp/recursion build -o /tmp/cctp-continuity ./continuity
PYTHONPATH=.:projects/groth16/reference:projects/cctp/reference:projects/cctp/recursion \
  ../cctp-test-tools/venv/bin/python projects/cctp/recursion/run_continuity_regtest.py \
  --node-url "$REGTEST_URL" --cookie "$REGTEST_COOKIE" \
  --prover /tmp/cctp-continuity --setup-dir /tmp/cctp-continuity-demo \
  --out /tmp/cctp-continuity-regtest
```
