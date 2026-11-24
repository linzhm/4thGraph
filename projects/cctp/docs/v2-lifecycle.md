# v2 代币交易路径

2026-11-24。测试资产使用已锚定的铸造状态 UTXO、专用冻结角色和固定的验证器锁集合。铸造锁创建 v2 代币时固定整个策略。普通支出要求持有人签名，并核对输入零消费的验证器锁属于该集合。转账和销毁的验证器从真实交易序列化材料提取并比较各代币的锁策略。

共享验证器认证输入零的 ForkID ALL preimage，从中核对全量 prevouts 和 outputs。它用每个代币 vin 的真实 txid 和 vout 核对父交易并定位父输出，检查锁、资产和状态，再用实际数量生成证明槽位。Groth16 电路验证绑定实际交易的流量守恒。初版按交易形状编译和分派，最多两个代币输入、两个代币后继输出，父交易最多四个输入和四个输出。

冻结及解冻使每个代币输入在同位置 vout 生成唯一后继，承诺整个交易的发行方签名控制操作。脚本用当前输入的 ForkID SINGLE preimage 核对后继，保留资产、数量、持有人、策略及 carrier satoshi，切换冻结位。冻结期间普通支出和销毁都被该输入锁禁止。

销毁验证器根据绑定实际 outputs 的证明验证找零及销毁总量。最后一个输出为零 satoshi 的不可花费凭据，固定资产、储备域、20 字节收款人、uint64 销毁量和费用。向储备侧提交时还需该凭据的真实 txid、vout、确认区块和来源证据。

## 独立节点结果

[BSV Node 1.2.3 regtest 摘要](../fixtures/v2-lifecycle-regtest-summary.json) 记录实际区块和交易。主线为锚定铸造 1,024 → 640/384 拆分 → 冻结和解冻 640 → 独立父交易 2→2 → 合并 → 销毁 640 并找零 384。另铸造及全额销毁 128。节点拒绝替换父原文及保留旧证明和签名的赎回收款人改动。该轮 BSV 测试使用测试入金签发。独立的 [Anvil 入金到 BSV 铸造联测](../fixtures/mint-reserve-integration-summary.json) 实际核对了 EVM 收据和最终性。

直接携带父交易原文使交易随代际变大。使用默认 500,000 字节单脚本转发策略时，首次多父测试收到 `Script is too big`。上述验收节点使用 `-maxscriptsizepolicy=10000000`。已入块 2→2 约 1.49 MB，合并约 3.91 MB，部分销毁约 4.37 MB。容量结果依赖节点策略，64→64 和 256→256 的完整证明尚待实测。

实链接受证明脚本和实际交易关系能够执行。独立父证明的电路内递归和公开测试网部署仍待验收。测试证明使用公开 setup，测试记录不得用于资产安全或主网运行。

运行同一场景时设 `REGTEST_COOKIE` 和回环 `REGTEST_URL`，可用 `CCTP_MIMO_REPORT` 导出 JSON。环境要求 Circom、Node.js、锁定的 chain-gang 及配置 `-txindex` 的独立 Chronicle regtest。

```sh
PYTHONPATH=.:projects/groth16/reference:projects/cctp/reference \
  ../cctp-test-tools/venv/bin/python -m unittest -v test_mimo_verifier test_operational_token
```

也可以让共享脚本启动和清理独立 Apple Container 节点。使用本地 Foundry 工具并安装 EVM Python 依赖后，设 `CCTP_EVM_LIFECYCLE=1` 接入本地 Anvil 测试储备。设 `CCTP_MIMO_REPORT` 导出该次结果。

```sh
PATH="$PWD/../cctp-test-tools/venv/bin:$PATH" \
PYTHONPATH=.:projects/groth16/reference:projects/cctp/reference \
BSV_REGTEST_TXINDEX=1 BSV_REGTEST_MAX_SCRIPT_BYTES=10000000 \
BSV_REGTEST_STD_MILLISECONDS=10000 BSV_REGTEST_NONSTD_MILLISECONDS=20000 \
BSV_REGTEST_ASYNC_MILLISECONDS=30000 \
bash shared/verify_node_apple.sh cctp-v2 19445 test_mimo_verifier
```


## 本地两链闭环

[Anvil 与 BSV regtest 联测结果](../fixtures/v2-cross-chain-regtest-summary.json) 记录两边的区块与交易。Anvil 的测试 USDC 入金 1,024 达到最终性后触发 BSV 铸造，走完拆分、冻结、解冻、不同父交易合成、合并及部分销毁。Anvil 实际释放 640。另一路测试入金 128，并全额销毁及释放，覆盖无代币找零的交易。两笔已结清释放的状态均可重读恢复。最终净储备、实际储备和已确认 BSV 流通各 384 个最小单位，待铸造及待释放为零。

钱包从真实区块头和 Merkle 路径验收 384 找零，独立查询其未花费，并查询同一条路线的早期输出为已花费。赎回证明签发前，宿主用 ConfirmedLineage 从经独立 BSV Node 验证的确认历史追到真实发行锚。此观察路径仍需替换为满足规格的电路内递归，对于公开测试网也要重新配置最终性、测试资产及发布策略。

SQLite 桥账本可记录经认证的链上事件和签名前授权摘要，提供去重、补扫恢复、对照实际余额和异常挂起。其恢复及对账测试独立运行。后续服务联测还应实际注入深重组，验证账本挂起阻止签发并驱动链上暂停。
