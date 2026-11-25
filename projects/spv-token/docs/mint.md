# BSV 铸造状态和源链入金认证

R02、R03 与 R06 的铸造一侧。

发行者先创建 BSV 发行锚点 UTXO。资产描述符固定该 outpoint。铸造状态创世交易在输入 0 消费该锚点，并在输出 0 建立空事件树。验证该资产的铸造来源时，从锚点追踪状态链，或验证能证明同一关系的递归证明。复制状态锁无法复制真实的锚点来源。

每次铸造在输入 0 消费前序状态，并在输入 1 使用独立资金支付交易费和代币的 satoshi 载体。固定输出如下。

| vout | 内容 |
|---|---|
| 0 | 用同一个状态锁延续已消费事件的承诺。covenant 保留状态的 satoshi 金额。 |
| 1 | 由资产策略生成的代币输出。最小单位为入金总额减手续费，持有人取自已认证事件。 |
| 2 | 零 satoshi 的 `OP_FALSE OP_RETURN` 记录。 |
| 3（可选） | 资金输入的标准 P2PKH 找零。 |

状态 Script 从实际输入的 ForkID ALL preimage 认证输入编排和全部输出。它用压缩 secp256k1 铸造钥匙检查同一笔交易签名。签名服务通过源链适配器读取达到最终性的 canonical receipt，只对字段完全匹配的入金签名。私钥由外部签名器保管。当前测试储备合约手续费为零。

## 铸造如何进入连续性证明

首次消费创世铸造状态时，Script 核对该状态所消费的发行锚以及空事件树。只有这个基例的连续性回执可以没有前序。如果铸造前有暂停或恢复，首笔实际铸造也继承上一状态的连续性摘要。后续铸造继续消费实际的铸造状态，在验证授权和事件树更新后继承前一状态证明。源链最终性仍由现有受信 RPC 和授权签发路径核验。 [铸造的两种连续性分支](../recursion/continuity_verifier.py#L146)

铸造后第一次转账逐槽认证实际铸造 `txid:vout`、对应的代币输出及铸造的有效连续性声明。新版将父绑定、前序验证与本笔守恒放进同一份递归证明。定稿父原文作为链下见证，电路依据实际动作提取验证器、回执和获授权的 Token 输出。首轮从同一发行锚连续认证铸造两个输出，用这两个输出做第一笔 2→2，再花费该转账的两个输出做第二笔 2→2。对照每个输入的见证与整笔字节，并拒绝错锚、重放事件、换父 vout 与复制铸造回执。 [递归来源设计](recursive-provenance.md)

新版铸造状态的累计净铸造量从零开始。每次有效入金铸造由 Script 核对新值等于旧值加实际净铸造量。暂停、恢复及获准的版本迁移继承该字段。 [新版状态与验收](recursive-provenance.md#从-genesis-延续的铸造状态)

`MintPolicy(state_version=2)` 用 `BSV/CCTP/mint-state/v2` 标记开启计数。完整状态锁在尾部保留固定的 16 字节小端累计值。Script 从实际前序状态取得原值，按本笔净铸造量累加，并拒绝 uint128 溢出。旧版锁及见证字节仍由回归向量核对。新版同一测试策略的锁增加固定 47 字节。两笔不同手续费的铸造分别净增 1,017 和 383，节点确认累计从 0 到 1,017 再到 1,400。暂停和恢复都保留 1,017。两笔铸造各为 93,866 字节。节点拒绝正确签发者重签的错误累计量、重签入金重放和暂停中的铸造。 [独立节点记录](../fixtures/v2-counted-mint-regtest-summary.json)

固定 70 字节测试 DER 后，同一锚的三笔原生 v2 铸造分三块连续确认，每笔均为 93,865 字节。状态输入见证均为 50,686 字节，稀疏路径均为 8,192 字节，累计量依次为 1,017、1,400、1,654。现有 v3 认证铸造的前两笔在 verifier vin 仍推入完整父状态交易，第二笔另外推入前序验证器资金原文。新版联合证明的零历史增长需按 [递归验收](recursive-provenance.md#首轮验收) 独立验证。 [三笔同宽铸造记录](../fixtures/v2-counted-mint-fixed-width-regtest-summary.json) · [v3 节点基线](../fixtures/v3-counted-continuity-regtest-summary.json)

供递归小样使用的有界原生铸造固定三个完整测试事件 ID。状态转移表预计算这些事件集合的原稀疏树根，签发摘要、串行状态、累计净量和代币输出继续由原生铸造锁检查。它使用独立状态标识，状态输入的路径推入为空。三笔原生铸造各为 8,068 字节，节点拒绝正确重签的入金重放及未登记事件。此夹具的签发数据与事件清单均限于隔离测试。 [有界铸造节点记录](../fixtures/v2-bounded-native-mint-regtest-summary.json)

## 入金记录

`OP_FALSE OP_RETURN` 后是独立 push 的 `BSV/CCTP/deposit/v1\0` 域及 185 字节记录。所有整数使用小端。EVM 地址和交易哈希按 JSON-RPC 十六进制字节顺序。

| 字节数 | 字段 |
|---:|---|
| 8 + 4 | EVM chain ID、桥储备域 |
| 20 + 32 + 4 | 储备合约、交易哈希、该交易回执内日志的序号 |
| 32 + 4 + 32 | 源资产（ERC-20 地址左补零）、BSV 网络、桥代币资产 ID |
| 8 + 8 + 33 | 入金总额、手续费、压缩 secp256k1 持有人公钥 |

事件 ID 是 `HASH256("BSV/CCTP/deposit-id/v1\0" || 记录前 68 字节)`。记录中的日志序号按回执自身顺序计数，与区块范围的 RPC `logIndex` 不同。同源位置的重签、金额改写或换收款人都保留同一事件 ID。

事件树采用 256 层稀疏 Merkle 树。叶和分支分别对域及内容做双 SHA-256。事件 ID 以小端解释，路径从最低位开始。Script 用同一路径从空叶和已消费叶分别计算前根和后根。这阻止同一事件在后续状态再次铸造，即使签发人重新签名。不同存款同时消费同一个状态输出时，由 BSV 共识决定哪一笔生效，其余可在新状态重建。服务重启时可根据已确认的连续状态交易重建事件索引。恢复函数要求调用方先独立认证这些交易的共识和确认状态。

配置独立暂停钥匙的状态支持链上暂停和恢复。控制交易消费同一个状态输出，翻转暂停位并保留事件根，只生成后继状态和可选找零。暂停期间，状态 Script 拒绝铸造签名。暂停与铸造争用同一个状态输出。角色轮换、解除授权及已跨链执行后的深重组处置仍属于后续运营要求。

## 验证记录

- Apple Container 的 BSV Node 1.2.3 确认了 1,024 和 384 两笔独立铸造，以及中间的暂停和恢复。节点拒绝同状态竞争、重签后的同一事件与暂停期间铸造。chain-gang 和宿主检查另覆盖错误钥匙、资产、域、收款人、数量、输出位置和状态变更。见 [铸造 regtest 记录](../fixtures/mint-regtest-summary.json)。
- 本地 Anvil 储备合约收到 1,024 单位 ERC-20 测试资产。真实入金回执达到最终性前签名器调用为零。达到最终性后使用同一回执签发，独立 BSV Node 将 vout 1 含 1,024 单位的对应资产铸造交易写入区块。见 [本地双链入金记录](../fixtures/mint-reserve-integration-summary.json)。
- 双链入金测试使用本地 Mock USDC、公开测试钥匙和代币锁的验证器身份夹具。公开 Base Sepolia、后续真实证明花费及赎回由各自验收覆盖。

可在仓库根目录运行。设置 `CCTP_MINT_REGTEST_COOKIE` 和 `CCTP_MINT_REGTEST_URL` 指向启用 Chronicle 和 txindex 的回环 BSV Node。双链测试还需要 Foundry 的 `forge`、`cast` 和 `anvil`。

```sh
PYTHONPATH=.:projects/spv-token:projects/groth16/reference:projects/spv-token/reference \
  ../cctp-test-tools/venv/bin/python -m unittest -v \
  test_mint test_mint_reserve_integration evm.test_reserve_anvil
```

可用 `CCTP_MINT_REPORT` 与 `CCTP_RESERVE_MINT_REPORT` 输出本次区块引用及拒绝结果。Cookie 仅读取自节点文件。

单独复跑三笔同宽铸造时，运行 `test_mint.MintTests.test_independent_node_counted_mints_keep_the_same_shape`，并用 `CCTP_MINT_REPORT` 记录每笔交易和各字段字节数。

有界夹具使用 `test_bounded_mint.BoundedMintTests.test_three_mints_on_independent_node`。用 `CCTP_BOUNDED_MINT_URL` 和 `CCTP_BOUNDED_MINT_COOKIE` 指向隔离节点，用 `CCTP_BOUNDED_MINT_REPORT` 写入新的报告路径。
