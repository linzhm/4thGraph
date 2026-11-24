# 两次异父收款与再支付

## 验收结果

使用全新的隔离 BSV Node 1.2.3 regtest 检验 v3 候选。这个试验分别评估[资金恒等、真伪溯源、可扩容](bsv-usdc-bridge-spec.md#三项协议判据)。两笔普通支付都由本次付款人从其普通 BSV 余额创建共享验证器资金 UTXO，无发行方票据。接收方在普通支付开始前，从自己的测试部署固定资产标识与验证器锁摘要 `SHA256(CompactSize(script长度) || script)`。

| 项目 | Alice 付给 Bob | Bob 付给 Carol |
|---|---:|---:|
| 两个实际输入的代币数量 | 300 + 200 | 275 + 150 |
| 收款及找零 | Bob 275，Alice 225 | Carol 350，Bob 75 |
| 付款确认高度 | 112 | 114 |
| 付款字节 | 12,343,030 | 25,625,698 |
| 含本次验证器资金的字节 | 13,326,214 | 26,608,881 |
| 链上递归 Groth16 证明字段，含编码 | 1,862 B | 1,862 B |
| 每笔见证中两份直接代币父原文的负载 | 7,409,732 B | 20,692,331 B |
| 热服务对本笔生成并核验原生证明 | 49.2 秒 | 48.9 秒 |

**资金恒等。** 三次测试铸造共 650 个六位精度最小单位。付款后可核对 Alice 找零 225、Bob 找零 75、Carol 收款 350，总额仍为 650。两笔确认交易各支付 47,975,000 satoshi 的隔离测试矿工费；验证器资金另行计入开销。费用受夹具拨款和找零布局影响。源链存款使用测试签发，此组没有独立的储备到账或赎回交易。[交易、区块与数量](../fixtures/v3-secure-receipt-regtest-summary.json)

**真伪溯源。** 两个代币 vin 均指向不同父交易。Bob 只消费 Alice 付款的 `vout 0` 和自己第三次铸造所得代币。发行进程完成铸造即退出，付款进程加载两种权限公钥和付款钱包签名器。Alice 和 Bob 从节点读取真实父交易及其已消费的验证器资金，恢复前序 Groth16 证明坐标、承诺知识证明，并从实际交易重建公开声明。原生 prover 用固定验证密钥验前序后再出证。两次出证共用一个已加载公开参数的测试服务；不需要它保存上一位付款人的证明文件。节点拒绝收款人变更后重新签名但沿用旧证明的交易。[前序证明恢复](../recursion/continuity_chain_proof.py) · [两阶段付款驱动](../recursion/run_secure_receipt_regtest.py)

收款钱包认证指定 vout、已执行的验证器、区块包含和两个确认，核对订单公钥、数量、冻结位，并在同一节点链视图查询含 mempool 的未花费状态。Carol 验收 350。错金额、把 Bob 的找零交给 Carol、把回执当作代币，以及将 Bob 已消费的 275 再计为当前可用，均被拒绝。Bob 当时确曾收到这枚币的历史凭据仍然有效。按订单幂等入账还需持久化收款账本。[严格钱包检查](../reference/certified_wallet_provenance.py)

另一台隔离 BSV Node 从创世块接收相同原始区块，使用[收款人预配置](../fixtures/v3-secure-receipt-recipient-policy.json)独立重放。高度 113 时，Bob 的付款进入该节点 mempool，原 275 仍在链上 UTXO 集，严格钱包已停止把它计作可用。高度 114 时 Carol 的 350 有一个确认，尚未达到试验的两个确认门槛；高度 115 时收款通过。仅在重放节点撤销高度 114 的块，钱包随即拒收；重新采用原链后，恢复出完全相同的收据。这是受控撤块实验。[独立节点回放](../fixtures/v3-secure-receipt-replay-regtest-summary.json)

**可扩容。** 第二笔全包增加 13,282,667 字节，其中直接父原文的负载差为 13,282,599 字节。直接父原文内又包含更早交易；嵌套字节只计一次。Bob 已有的 150 也出自一笔更大的铸造交易。因此，这个差值说明当前布局依赖历史，不能解释为每一代的固定增量。该候选没有达到零历史增长目标。[逐字段核算](../fixtures/v3-secure-receipt-audit.json)

## 复现条件

使用本仓库的 Python 环境及 chain-gang、启用 txindex 并放宽容量策略的独立 regtest，以及同一版本的 `continuity` 原生 prover 和测试参数。两阶段以独立进程执行。运行前按自己的部署取得资产和批准锁的摘要，普通付款参数分别使用 `--expected-asset` 和 `--expected-verifier-hash`。每个新发行锚的实际值会不同。

```sh
export PYTHONPATH=.:projects/groth16/reference:projects/cctp/reference:projects/cctp/recursion
driver=projects/cctp/recursion/run_secure_receipt_regtest.py
python "$driver" --phase mint --node-url "$REGTEST_URL" --cookie "$REGTEST_COOKIE" \
  --prover "$CCTP_PROVER" --setup-dir "$CCTP_PARAMS" --out "$CCTP_RUN"
python "$driver" --phase payments --node-url "$REGTEST_URL" --cookie "$REGTEST_COOKIE" \
  --prover "$CCTP_PROVER" --setup-dir "$CCTP_PARAMS" --out "$CCTP_RUN" \
  --expected-asset "$CCTP_ASSET" --expected-verifier-hash "$CCTP_VERIFIER_HASH"
```

原始链上交易、区块信息、五份原生证明及验证密钥另有[压缩归档](../fixtures/v3-secure-receipt-regtest.json.xz)。本次协议验证密钥标识为 `677731270de75ec11f65c92f2ac8b0c428df79e28a532a035b8402166eb04a9b`。R1CS 指纹为 `70a485af0ccc64cffb4275515fabc57d9344b5104960a7ae22e2819cbd681704`，原始 VK 的 SHA-256 为 `2820918c22c2fe11750547dfce9b6bdfed66c51b0e6e7a01903650c6c27615bf`。本地 PK 为 2,712,016,823 字节，其 SHA-256 为 `d3f3aed0255ec2c34dfd8f2605fb710cea1bbd11e8718f8b07a2ac066ff30b71`。本次使用单机测试 setup，未提供生产参数仪式、独立的协议安全审计、公开转发策略或公网费用证据。

离线核算可执行 `python projects/cctp/recursion/archive_secure_receipt.py replay --archive projects/cctp/fixtures/v3-secure-receipt-regtest.json.xz --audit /tmp/secure-receipt-audit.json`，再与仓内核算文件逐字节比较。使用[链状态重放驱动](../recursion/run_secure_receipt_replay.py)时指定包含源区块的原节点、一个全新的隔离 regtest 节点、运行摘要、验证密钥和收款人预配置。源节点只提供区块和交易原文，mempool、撤块和恢复均在新节点执行。

## 父交易的输出边界对齐

两阶段的运行命令均加上 `--align-output-count`。发行锚交易追加带有 `BSV/CCTP/regtest/aligned-payments/v1` 标记的零值输出，使这套配置具有独立的发行 outpoint 和资产标识。收款方在高度 215 固定实际批准的验证器锁摘要。铸造建立该策略，普通付款由共享验证器输入消费零填充。两笔付款继续携带完整父原文，节点和收款钱包沿原来的 B2G 路径校验所花的真实代币。[收款方预配置](../fixtures/v3-aligned-payment-recipient-policy.json) · [父交易绑定关系](parent-binding.md#前缀状态与实现顺序)

| 入块实测 | Alice 付给 Bob | Bob 付给 Carol |
|---|---:|---:|
| 确认高度 | 223 | 225 |
| 付款字节 | 12,343,308 | 25,626,252 |
| 含本次验证器资金的字节 | 13,326,512 | 26,609,456 |
| 零填充 push，含编码 | 38 B | 15 B |
| 第一个输出计数字节的偏移 | 12,338,432 | 25,621,376 |
| 从该偏移到交易结尾 | 4,876 B | 4,876 B |
| 后缀、中间态和已处理长度的合计 | 4,916 B | 4,916 B |
| 链上递归证明字段，含编码 | 1,862 B | 1,861 B |

每笔均用 `0x41`。Bob 花费 Alice 已确认付款的 `vout 0` 和独立铸造的 `vout 1`。节点拒绝了 256 字节零填充，也拒绝了变更收款人、重新取得持有人签名却沿用原证明的交易。第二台节点从创世块重放，Carol 在高度 226 达到两个确认后验收 350 个最小单位，撤销付款块后收据失效，重新采用后得到相同收据。两笔全包仍相差 13,282,944 字节。这部分历史增长需要在后继验证器中用独立认证的父证据替换原文。[第二台节点重放](../fixtures/v3-aligned-payment-replay.json)

离线核算从[新节点的原始交易与区块归档](../fixtures/v3-aligned-payment-regtest.json.xz)重建交易标识、区块包含、所花的两个代币 outpoint、最短填充、SHA-256 中间态和完整输出后缀。分别使用原付款核算命令的 `replay` 和新增的 `aligned-checkpoints` 模式，后者的输出可与[两笔付款的检查点](../fixtures/v3-aligned-payment-checkpoints.json)逐字节比较。
