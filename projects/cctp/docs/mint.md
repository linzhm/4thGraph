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
PYTHONPATH=.:projects/groth16/reference:projects/cctp/reference \
  ../cctp-test-tools/venv/bin/python -m unittest -v \
  test_mint test_mint_reserve_integration projects.cctp.evm.test_reserve_anvil
```

可用 `CCTP_MINT_REPORT` 与 `CCTP_RESERVE_MINT_REPORT` 输出本次区块引用及拒绝结果。Cookie 仅读取自节点文件。
