# 实际交易关系：首个有界电路

2026-11-24。此页记录开发证据，不表示 R04/R13 完成。

`reference/transaction_relation.py` 定义规范代币锁和宿主参考关系。每个实际输入必须提供规范父交易原文，以 txid 和 vout 选中父输出；扫描全部输入和输出后与声明槽位逐项匹配。资产、数量、持有人、冻结位及完整 covenant 都参与模板匹配。satoshi 与代币数量分别计量。冻结输出暂时 fail closed，尚无解冻分支，不能用于完整生命周期。

`reference/split_relation_circuit.py` 生成首个固定形状电路，复用 TransferCommitment。它直接约束：

- 输入零 preimage 的 hashPrevouts 和 hashOutputs 对应完整实际序列化材料；preimage 当前 outpoint 对应输入零。
- 输入一的 txid 等于父交易原文的双 SHA-256，vout 必须为零。
- 父交易格式为一输入（空 scriptSig）、一代币输出；版本、计数、CompactSize 和锁模板固定，前置 outpoint、sequence、satoshi 和 locktime 可变。
- 实际输入代币数量等于输入槽位数量；两个实际输出分别对应 vout 0、1 及输出槽位数量。
- 资产匹配公开语句前缀；后继锁保持父代币的验证器 guard 身份，数量和持有人可变化；两处持有人编码一致。普通路径只接受 active 状态。

父代币的 guard 在真实输入执行时认证输入零的完整验证器锁，持有人 CHECKSIG 认证该输入。证明验证器最后的 CHECKSIG 认证自己的紧凑 preimage。电路不把任意一个宿主回调当成认证结果。

## 尚未解决的协议边界

父交易内容认证并不证明其合法发行；任何人都能复制代币锁。需要合法铸造基例和真实前序证明递归后才能认证来源。本电路还没有这两项，测试父代币明确为合成起点。

当前 guard 固定绑定单个完整验证器锁。不同电路形状会产生不同验证密钥，因此不能直接把 1→2 的输出交给独立 2→1 验证器。此前的固定锁选择可防替换验证器，但不能据此声称完成跨形状生命周期。下一阶段需选择统一有界电路/验证器，或受资产策略认证的多验证器分派，并在递归语句中绑定同一策略。不能仅移除 guard 或改成宿主白名单。

宿主层可处理非零 vout 和独立父交易 MIMO；它的覆盖面不能作为当前固定形状电路的覆盖面。冻结、销毁、源链释放也尚未接入此电路。

## 可复现检查

从仓库根目录运行（沿用交接稿中的独立工具目录）：

```sh
PYTHONPATH=.:projects/groth16/reference:projects/cctp/reference \
  ../cctp-test-tools/venv/bin/python -m unittest -v test_transaction_relation test_actual_split
```

`test_actual_split` 生成真实测试专用 Groth16 证明，执行真实持有人签名，并用 chain-gang 验证两个完整输入。测试 setup 使用公开 toxic waste，不能保障真实资产。

指定 `REGTEST_COOKIE` 和回环 `REGTEST_URL` 时，同一测试挖成熟测试币，建立真实父交易，先要求节点拒绝输出重排，再广播有效拆分并检查入块。`CCTP_REPORT` 可指定保存原交易、父交易、证明、验证密钥、约束数、字节数和区块引用的 JSON 路径。Cookie 仅从文件读取，不写入报告。需要 BSV regtest、txindex 和 Chronicle 激活。

## 本次独立节点结果

Apple Container 中 BSV Node 1.2.3 已接受真实父交易和 1,024 → 640/384 拆分并入块；同一输入仍未花费时，输出重排负例被节点以 -26 / mandatory-script-verify-flag-failed 拒绝。没有启动 Docker。

电路 1,598,409 条约束，完整拆分交易 454,993 字节。这里只记录首条路径数据，不作容量优化结论。18 项宿主／共享回归、原始承诺电路测试、新实际关系电路与完整输入测试均通过。

[结果摘要](../fixtures/actual-split-regtest-summary.json) 记录 txid、区块哈希及拒绝层；[压缩原始材料](../fixtures/actual-split-regtest.json.gz) 包含交易、父交易、证明、验证密钥和公开输入。它们证明该固定形状交易关系在独立节点可执行；合成父代币起点仍不满足合法铸造或递归来源要求。
