# 双槽生命周期验收

本试验以新发行锚、固定四输入四输出和同一个 Groth16 验证密钥覆盖铸造、转账、冻结、解冻及销毁。储备协议沿用现有 EVM 合约、规范区块与最终入金核验、外部签名及持久释放日志。证明参数和签名器均用于测试。

## 2026-11-25 独立双链验收

独立 BSV Node 1.2.3 在高度 108–142 确认九笔动作。隔离 Anvil 的三个实际最终入金分别驱动铸造 300、200 和 150。发行状态 nonce 为 1、2、3，累计数量为 300、500、650。两名普通付款人分别使用自己的签名完成异父 `2→2`。Bob 独立验收 275 后，使用实际收款 `vout 0` 和另一个真实铸造父向 Carol 付款 350。Carol 的币被冻结并解冻，随后实际部分销毁 300、全额销毁剩余的 125，两笔均从储备合约收到准确的款项。停 BSV 节点后，九笔的接收或回执均通过原始区块头和实际直接父包含证据回放。 [实测记录](../fixtures/route-d-a-lifecycle-regtest/summary.json) · [BSV 与 EVM 证据](../fixtures/route-d-a-lifecycle-regtest/packets.json.xz)

| 联测计量 | 结果 |
| --- | ---: |
| BSV 定稿结算，每笔 | 212,506 B |
| 铸造，每笔含伴随、验证器及普通费用资金 | 673,706 B |
| 转账、冻结、解冻、销毁，每笔含伴随及验证器资金 | 673,539 B |
| 九笔总链上字节，含共享钱包出资 1,239 B | 6,063,591 B |
| 同形状历史增长 | **0 B** |
| CPU 热出证，每笔 | 22.31–24.87 秒 |
| 最终储备 / BSV 未花费流通 | **225 / 225** |
| 待铸造 / 待释放 / 冻结余额 | 0 / 0 / 0 |

一份 1,078 B 的 Groth16 见证用于每笔支付。电路共有 13,787,986 条约束。测试参数生成并写盘用时 12 分 41.66 秒，原生会话峰值内存约 25.96 GB。结算锁定脚本 1,745 B，解锁脚本 210,535 B，其余 226 B。验证器锁 460,050 B。按固定物理宽度归一化签名和持币输入。 [参数及指纹](../fixtures/route-d-a-lifecycle-regtest/parameters.json) · [原生计时](../fixtures/route-d-a-lifecycle-regtest/native-timings.log)

节点拒绝额外复制代币输出、错误管理钥及更换销毁收款人。电路拒绝旧储备 nonce、把发行状态 vout 当作代币、冻结币普通花费和冻结币销毁。钱包拒绝把冻结输出记为可用，铸造服务拒绝再次接纳同一已确认入金。两次实际 EVM 释放 calldata 重新调用均返回 `AlreadySettled`，释放授权也能从持久日志恢复。 [各层负例及释放证据](../fixtures/route-d-a-lifecycle-regtest/summary.json)

## 动作如何绑定实际交易

- `vin 0` 花费一笔开放创建的伴随资金。该锁认证实际 `vin 1` 所花资金的 outpoint 和获准的完整验证器锁。
- `vin 1` 在节点认证的有序 prevouts 中提取实际 `vin 2,3`。共享证明验证各自的真实父 txid、规范输出位置和所选状态。普通费用币另有固定 P2PK 父形状，只有真实普通费用输出可当作零代币槽。
- `vout 0,1` 是两个类型明确的后继槽。可用币、冻结币和发行状态引用同一伴随策略，空槽是等宽的零 satoshi 不可花费输出。`vout 2` 是规范销毁回执或空回执，`vout 3` 记录已认证入金事件 ID 或零值。脚本重建全部四个实际输出，与认证原像的整笔输出哈希核对。
- 共享证明约束两个角色公钥。Script 在本笔真实验证器输入执行两次原生验签。普通转账和销毁用实际代币持有人，冻结和解冻用预先配置的管理者，铸造用入金授权者。权限依赖同笔实际输入和输出承诺。

| 动作 | 状态及授权 |
| --- | --- |
| 铸造 | 首笔消费实际发行锚，后续消费同一链上发行状态。预留另一个槽给经过认证的普通费用币。发行状态累计数量和储备 nonce 更新，合法入金的净额及收款公钥进入唯一新代币输出。 |
| 转账 | 两个被消费的实际代币必须可用。每个真实持有人授权，输入总量与完整后继数量守恒。 |
| 冻结与解冻 | 管理者为本笔交易签名。由明确槽位配对，选中状态仅变更冻结标记，未选槽保持原状态，所有被消费代币均保留原持有人和数量。 |
| 销毁 | 持有人授权。被消费的代币须可用。销毁数量与全部代币找零相加等于实际输入数量，固定 `vout 2` 承诺资产、目的域、收款人、数量及费用。空找零槽不可花费。 |
| 储备释放 | 在确认策略满足后读取实际销毁 `txid:vout`、区块和回执，重放 BSV 支付和全部真实直接输入。现有持久授权和 EVM 储备合约各自按销毁标识去重。 |

发行顺序采用配置储备合约已有的 `depositNonce`。授权服务读最终确认的实际日志，校验 nonce、资产、净额、公钥、发行状态和实际待签交易，再保留该入金的签名意图。电路将发行状态限制为每次严格加 1。这一布局要求按 nonce 顺序处理入金，后续入金会等待前面的入金处理完毕。源链规范性和最终性仍由已配置的 RPC 与铸造授权者认证。 [铸造授权](../recursion/prepared_lifecycle_mint.py) · [储备及日志](../evm/README.md)

## 历史长度与钱包

继续复用固定重建程序和真实 SHA-256 填充。Script 从规范父前缀重建中间态及已处理长度。电路从该位置认证固定 10,074 B 后缀和实际父输出，并校验父 `vin 0` 真实消费同一策略的伴随资金。父的完整原文及祖先原文停在链下。每个直接父披露保持固定宽度，证明、授权、持有与发行见证各有固定的字节槽。审核者可从同一策略的区块头和直接父包含凭据独立执行 Script，当前未花费性依钱包的节点观测处理。 [结算与钱包接口](../recursion/prepared_lifecycle.py)

## 公开测试网接入

独立本地双链通过后，调用 Base Sepolia 官方公网 RPC 查验链 ID 84532，并在最终块 63,427,799 的规范哈希处核对 Circle 测试 USDC 字节码和六位精度。BSV 公共浏览器返回高度 1,771,403，Chronicle 激活块与预设检查点一致。当前环境未配置授权的 BSV Testnet RPC、已资助的 Base 及 BSV 签名账户或公开储备部署。公开广播还需确认实际验证器锁 460,050 B 和结算 212,506 B 对应的转发和入块策略。此轮完成读预检，公开部署、入金、销毁释放及钱包闭环仍待实测。 [预检记录](../fixtures/route-d-a-lifecycle-regtest/public-preflight.json) · [公开测试网入口](../evm/public-testnet.md) · [Base RPC](https://docs.base.org/get-started/connect-to-base) · [Circle 测试 USDC](https://developers.circle.com/stablecoins/usdc-contract-addresses)

## Python 与标准 snarkjs 参数

待验收的生命周期入口从标准 `.zkey` 读取验证密钥，从版本化交易声明生成标准 `.wtns`，再调用通用 Python prover。新的全路径验收会由 chain-gang 检查完整输入，再由独立 BSV Node 确认。新测试发行锚及验证器资金使用新验证密钥。

从仓库根目录运行。令 `CCTP_ASSIGNMENTS` 指向已生成的生命周期赋值规则文件，`CCTP_ZKEY` 指向同一份标准 `.r1cs` 经第二阶段设置得到的 BLS12-381 `.zkey`，`CCTP_NTT_SHADER` 指向校验过指纹的 WGSL 文件。Python 环境包含 chain-gang、`wgpu` 及 `py-arkworks-bls12381`，本地储备使用 Foundry。独立 BSV Node 1.2.3 regtest 从高度 2 激活 Chronicle。

```sh
export PYTHONPATH=.:projects/spv-token:projects/groth16/reference:projects/spv-token/reference:projects/spv-token/recursion
cctp_run=$(mktemp -d)
python3 projects/spv-token/recursion/run_prepared_lifecycle_regtest.py \
  --layout prefix \
  --assignments "$CCTP_ASSIGNMENTS" --zkey "$CCTP_ZKEY" --ntt-shader "$CCTP_NTT_SHADER" \
  --out "$cctp_run/receipts" --node-url "$REGTEST_URL" --cookie "$REGTEST_COOKIE"
python3 projects/spv-token/recursion/run_prepared_lifecycle_regtest.py --out "$cctp_run/receipts" --replay
```

完整生命周期的 `.r1cs` 包含 13,787,986 条约束，需 `2^24` 档 BLS12-381 第一阶段参数。标准 witness 生成已用归档的实际交易校验九个动作。新 `.zkey`、新 BSV 验证器以及完整生命周期重新入块仍待同一套参数完成。 [Python 出证与验收进度](python-proving.md)
