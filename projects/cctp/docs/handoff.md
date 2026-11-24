# CCTP / BSV 储备桥开发交接

2026-11-24 · 交给下一条 Codex 会话

请在 `/Users/linzheming/Codex/BSV-Script-Lab/cctp-worktree` 的 `cctp/bsv-bridge` 分支继续推进到验收。这个目录是独立 Git 检出。先检查 `git status --short --branch` 和最近提交，再读 [开发计划](development-plan.md)、[规格](bsv-usdc-bridge-spec.md)、[能力清单](bsv-usdc-token-checklist.md) 及 [转账承诺](transfer-commitment.md)。保留用户已有改动。遵守仓库 AGENTS.md，在工作目录内开发，使用 Apple Container 或获准的独立 BSV 环境验证节点，避免引入 Docker。优先实现可复用的协议关系和验证构件，随后才优化交易体积。发布和远端推送另行安排。

## 已交付

- `19c7aaa` 拆出 CCTP 子项目。 `e4aa552` 提交分阶段开发及验收计划。
- `943a5f3` 定义版本化资产和交易承诺、槽位及公开输入编码，加入参数化 Circom 电路。对 1,024 → 640 + 384 生成真实 Groth16 测试证明。
- `2089703` 加入共享验证器输入的 Script 绑定。脚本从紧凑 ForkID ALL preimage、固定的资产与验证密钥身份以及槽位编码推导证明公开输入。使用本地解释器和真实 secp256k1 签名检查。改变输出后，原见证无法通过 CHECKSIG，针对变化交易重建见证仍无法复用原证明。
- 当前测试证明覆盖 preimage、公开输入、声明槽位及金额关系。代币输入的真实身份、父输出内容、前序证明和实际后继锁仍需由完整关系强制执行。测试专用证明参数只用于验收。

## 恢复检查

```sh
PYTHONPATH=.:projects/groth16/reference ../cctp-test-tools/venv/bin/python -m unittest discover -s projects/cctp/reference -v
PYTHONPATH=.:projects/groth16/reference ../cctp-test-tools/venv/bin/python -m unittest -v shared.test_layout test_transfer_digest test_public_inputs test_recursive_transfer
```

已从工作目录内的 chain-gang 仓库提取 `shared/requirements-chronicle.txt` 锁定的提交 `74676b9c002c452e7f21a9ed9265f4972bef03f6`，在兄弟目录 `../cctp-test-tools/` 建立源码目录和 venv，并安装 `tx_engine`。CCTP 四项检查及仓库与 Groth16 十项相关回归全部通过，其中 1→2 联测已用 chain-gang 验证完整参考交易。默认 Python 缺少该模块。若需重建测试环境，用 venv 的 pip 安装 `../cctp-test-tools/chain-gang`。Apple Container 控制命令此前在会话沙箱中返回 Operation not permitted。chain-gang 交易验证与独立 BSV Node 入块分别记账。

## 接续顺序及验收

1. 先完成实际交易关系。用输入 0 验证器的认证 preimage 约束真实序列化 prevouts 和 outputs。验证每个槽位映射到实际位置及父 outpoint，认证父交易原文和被消费的输出。给出规范代币锁身份和数量的统一提取规则，检查后继锁并拒绝遗漏或伪造的槽位。先完成实测 1→2，再覆盖不同父交易的 MIMO 路径。当前 Script 绑定的证明是这一阶段的组件。
2. 建立合法铸造基例。实现测试储备入金认证、事件标识、收款人和资产绑定。验证串行铸造状态 UTXO 一次性消费事件，覆盖重签、并发、服务恢复及多笔不同入金。同步评估两个独立父证明的电路内递归方案。宿主验证回调可作对照，端到端验收要求实际递归与交易绑定。
3. 实现冻结、解冻、销毁、源链一次性释放与对账恢复。保留钱包的指定 vout 验收、区块包含和已知花费状态三个判定。先用独立 BSV regtest 和测试储备，再接跨链测试网。CCTP 用于受支持网络间的原生 USDC 调拨。Circle 域注册、合作接口和生产运营要求对应规格的 X01–X04。
4. 以入金铸造 1,024、拆分 640/384、冻结与解冻、合并、销毁并释放 640 为主线。最终 BSV 流通与源链净储备各 384，待铸造及待释放为零。保留重放、错误收款人、假证明、冻结竞争和重组恢复负例，记录拒绝层。最后用完整证明测 64→64 和 256→256，再决定见证及验证器优化。

## 2026-11-24 后续检查点：实际 1→2

新增 [实际交易关系](actual-transaction-relation.md)：规范锁、完整父交易和槽位扫描的宿主参考，以及真正约束父交易哈希、输入位置、父数量、实际后继锁的有界 Circom 电路。真实 Groth16 证明、持有人签名、chain-gang 完整输入检查和 Apple Container 的 BSV Node 1.2.3 入块均通过。原始材料保存在 `../fixtures/actual-split-regtest.json.gz`，摘要见对应 JSON。原承诺向量未修改。

**这不是完整桥验收。** 当前电路父交易只支持一输入空 scriptSig、一代币输出的形状；父来源为合成起点，无合法铸造及电路内递归。宿主支持独立父交易 MIMO 不等于电路支持 MIMO。现有固定验证器 guard 无法直接跨不同电路密钥衔接拆分和合并，需要统一电路或资产策略认证的分派，不能移除 guard 规避。冻结标记暂时 fail closed，无解冻分支。

用户说明尚无源链基础设施，并提出考虑 Base。[Base Sepolia 候选](base-sepolia-plan.md) 已记录官方支持核验和职责边界，未部署合约、创建钱包或执行公开链交易。接续应先解决统一验证器与合法铸造/递归来源，再推进冻结、销毁、Base 储备及公开测试网闭环。

## 同日续接：v2 铸造到销毁

- [铸造](mint.md) 使用真实发行锚、串行状态和 256 位稀疏事件集合。独立节点通过连续铸造、暂停、恢复、并发冲突和重签重放负例。Anvil 的实际 finalized 入金也已驱动独立 BSV 铸造。
- [v2 路径](v2-lifecycle.md) 使用资产批准的固定验证器集合，支持实测 1→2、独立父交易 2→2、2→1、冻结、解冻和全额／部分销毁。初版见证包含实际父原文。独立节点需显式提高单脚本策略上限，生产容量尚未知。
- [EVM 储备和出入金适配器](../evm/README.md) 支持入金最终性、一次性释放及恢复。钱包的指定 vout、交易包含和已知花费查询已具备独立接口。非简洁的已确认历史核验与电路内递归证明有不同的证据范围。
- [双父递归实验](../recursion/README.md) 已在 gnark 生成并验证双父外层证明，独立 BSV 通过 BSB22 小型证明和负例。完整实际递归交易和任意层来源闭环仍待验证。优先完成该闭环，再实施 64→64 和 256→256 容量实验。
- 已实查 Base Sepolia 的公开 RPC 及 Circle 测试 USDC。尚无公开测试网的部署和闭环记录。R15 管理后台在最终集成时接线和部署，当前不改变域名配置。

- [本地实链联测摘要](../fixtures/v2-cross-chain-regtest-summary.json) 记录 Anvil 入金、独立 BSV 铸造至销毁、Anvil 一次性释放、重读恢复及钱包验收。最终实际及账面储备与 BSV 流通各 384。赎回签发采用已确认交易历史的宿主来源核验。已加入持久化对账组件，需接入长运行服务并实测深重组后的暂停处理。
- 当前 USDC 约定为固定六位小数，协议以 uint64 最小单位计量。1,024 最小单位的例子为 0.001024 USDC。管理后台最终接入时在输入边界遵守同一严格解析。
