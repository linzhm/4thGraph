# 固定 Groth16 转账评估基线

`parent-provenance-2x2` 使用普通 BLS12-381 Groth16，按实际 `txid:vout` 认证两个异父代币输入和发行来源。Script 绑定本笔验证器及实际交易，检查持有人签名、整笔守恒和两个规范后继。Alice 支付 275 单位给 Bob，Bob 从独立收款包验真后将该输出与自己已持有的 150 单位合并，签发另一笔异父 `2→2`，Carol 独立验收 350。在独立节点高度 110、111 入块。普通支付期间无需发行方签名。

| 实测项 | Alice → Bob | Bob → Carol |
| --- | ---: | ---: |
| 付款序列化 | 4,075 B | 4,075 B |
| 输出锁 / 输入解锁 / 其余字段 | 1,538 / 2,376 / 161 B | 1,538 / 2,376 / 161 B |
| Groth16 证明及 Script 推入 | 1,078 B | 1,078 B |
| 热出证 | 14.82 s | 19.43 s |
| 完整直接父交易进入本笔见证 | 0 B | 0 B |

预确认的同一笔资金交易提供两个验证器输出，共 904,965 B。两笔付款加这笔资金为 **913,115 B**，发行初始化另计 3,132 B。两笔付款的历史增量为 **0 B**。当前基线固定这两个验证器 outpoint，付款人开放续补留待联合版本验收。电路有 4,845,242 条约束，测试验证密钥指纹为 `e0eaa50d2aaa24c8012c091bac26693c525cb1f900ab870177d90debbf118e9d`。离线回放核对指定收款、两笔实际证明见证、Bob 花费的 outpoint、两笔父交易各异及原始字节成本。 [节点报告](../fixtures/fixed-funding-spv-regtest-summary.json) · [固定发行根与验证器](../fixtures/covenant-provenance-2x2-recipient-policy.json) · [收款包](../fixtures/fixed-funding-spv-regtest.json.xz)

## 离线复现

在仓库根目录使用固定版 chain-gang 的 Python 环境。回放使用 固定测试锚与验证密钥指纹。两个付款、直接父、区块头和 Merkle 路径都来自包内。

```sh
export PYTHONPATH=.:projects/spv-token:projects/groth16/reference:projects/spv-token/reference:projects/spv-token/recursion
f=projects/spv-token/fixtures
python3 projects/spv-token/recursion/run_fixed_funding_spv_regtest.py \
  --replay "$f/fixed-funding-spv-regtest.json.xz" \
  --summary "$f/fixed-funding-spv-regtest-summary.json" \
  --recipient-policy "$f/covenant-provenance-2x2-recipient-policy.json" \
  --proofs "$f/covenant-provenance-alice-proof.json" "$f/fixed-funding-spv-bob-proof.json"
```
