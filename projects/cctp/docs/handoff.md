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
