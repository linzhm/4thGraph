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


## 竞态与恢复补充

[冻结竞态记录](../fixtures/freeze-race-regtest-summary.json) 使用两笔独立锚定铸造输出。对每笔输出，先用节点和 chain-gang 分别验证签名齐全的冻结、支付两个候选，再交换提交顺序。先提交者入块，另一笔因同一 outpoint 的 mempool 竞争被拒。错误冻结授权，以及正确持有人签名和真实 Groth16 证明的冻结后支付，均被脚本拒绝。

签发服务先持久记录准确摘要，再调用外部签名器。原参数重试可复用缓存签名。独立 BSV 节点与 Anvil 实测了 finalized 入金、确认门槛、重启后同一铸造交易复用，以及撤销 BSV 铸造块触发的持久挂起。同一状态输出的两笔不同入金不会同时出签，第二笔在第一笔确认后用后继构造。

[持久化双链联测](../fixtures/v2-durable-cross-chain-regtest-summary.json) 还实测在首次铸造、首次释放签名中断后重开账本，恢复准确授权。两次释放均从已提交推进到最终结清。最终实际储备、账面储备与已认证 BSV 流通均为 384，待铸造、待释放及挂起均为零。长运行观察进程及公开网络的重组恢复仍待验收。

[公开测试网准备与核验工具](../evm/public-testnet.md) 生成可审阅的 Base Sepolia 测试储备部署数据，离线核验外部签名，读取最终确认的部署、入金与结清。还需完成真正的递归来源闭环，并配置获授权的测试签名器、测试资产和能验证及转发最终交易的 BSV 节点。

## 双父递归交易复现

[递归工程](../recursion/README.md)包括可复用的 v2 外层测试参数。先用 `prepare_v2.py` 生成与 v2 叶子电路相同的 1→2 证明种子，再按该文档编译 Go 程序、生成参数缓存及验证密钥。缓存和证明密钥放在独立的私有临时目录。供子交易使用的验证密钥必须与叶子代币锁白名单中的递归锁完全一致。

```sh
export PYTHONPATH=.:projects/groth16/reference:projects/cctp/reference:projects/cctp/recursion
../cctp-test-tools/venv/bin/python projects/cctp/recursion/run_recursive_mimo.py \
  --node-url "$REGTEST_URL" --cookie "$REGTEST_COOKIE" \
  --vk /tmp/cctp-v2-portable-vk.json --prover /tmp/cctp-recursion-portable \
  --setup-dir /tmp/cctp-v2-portable-setup --out /tmp/cctp-actual-recursive-spend
```

该场景从实际发行锚铸造两次 1,024 单位，用两笔独立的 1→2 交易分别产生父证明。子交易从实际花费的两个 vout 取得 640 和 324，输出 700 和 264。Script 按各父交易原文及其验证器实际 funding output 重建父证明语句。子交易的 SIGHASH_ALL、实际数量守恒及两份父语句顺序一起绑定到外层证明。

`keycommit/` 单独测试了下一阶段所需的动态验证密钥认证。它按顺序承诺 gnark 实际使用的配对目标、IC 坐标、Gamma/Delta 负点与 BSB22 承诺密钥，并禁止未绑定的预计算配对线。测试用绑定的动态密钥验证真实 BSB22 证明，并拒绝换公开输入或替换密钥坐标。多层通用电路仍须把该密钥承诺和实际授权铸造锚点接入同一个受资产认可的交易语句。


独立 BSV Node 1.2.3 已在高度 1123 接受这笔实际 2→2 递归交易。验证器在两份前序证明上执行递归验证，Script 从真实父交易和实际子交易重建全部公开承诺。交换父验证器材料、以及重新签署 701/263 但沿用 700/264 的证明均在有效子交易提交前被节点以脚本错误拒绝。交易为 3,970,297 字节，隔离节点的单脚本上限为 10,000,000 字节。外层电路有 4,404,943 条约束，对应的本次出证耗时约 25 秒，读取 1.6 GB 缓存参数用时约 5 分 35 秒。

[节点结果](../fixtures/v2-recursive-mimo-regtest-summary.json) 和 [原始证据](../fixtures/v2-recursive-mimo-regtest.json.gz) 保存了交易、父交易、证明及电路输入。重建归档后，chain-gang 再次验证了子交易的全部输入。运行器支持在已记录父交易、尚未提交子交易时用 `--resume` 恢复，并重新核对父交易及验证器 funding 是否仍在采用链。当前证明只支持两笔独立的 1→2 叶子，尚未递归覆盖其真实铸造来源或接受任意层递归父证明。
