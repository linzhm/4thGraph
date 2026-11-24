# 同密钥容量验收

容量配置复用 v3 的铸造状态和两槽连续性电路。普通持有人仍签实际 ForkID ALL。容量交易的 vin 0 验证 Groth16，vin 1 的协同锁一次认证实际 vin 0，代币输入从 vin 2 开始。每个代币输入可只提交自己的签名及小型协同锁材料。窄形状的直接授权仍可消费同一资产。

容量 Script 校验实际输入、父交易序列化、选定 vout、锁模板和 uint64 数量守恒。代币输入按线序 txid 的无符号整数、再按 vout 严格排序。每个父交易独立计算 txid，同一父交易的不同 vout 共用一组原文。父输出区从规范交易字段解析，并核对每个被选槽位。末尾容量回执保存父证明根及经实际执行验证器核实的紧凑上下文片段，下一笔会从真实父输出重建 `hashOutputs` 和父证明摘要。

后继交易确认实际父交易消费了相同的验证器锁。父回执中继承的上下文字段由该锁在父交易入块时与真实预像逐字节核对。钱包验收采用独立全节点的区块和已执行锁证据。

单一父交易直接引用已验证的同密钥证明。不同父交易的摘要按实际组顺序组成固定宽度二叉树，缺位用最后一个摘要填充。Script 从实际摘要重算根的两棵子树，链下用现有两槽电路生成对应证明。可选的字典编码在 Script 内无损重建父交易，再执行原有 txid、上下文和槽位检查。

## 实测记录

两档共父付款分别在独立 Bitcoin SV Node 1.2.3 中入块。每组使用新发行锚、测试签发铸造和一次真实 fanout。钱包验证付款首尾输出及 Merkle 包含，并单列已知花费状态。

| 共父付款 | 准备 fanout 字节 | 付款字节 | 最大输入见证字节 | 付款出证 | 钱包首尾 vout 验收 | 记录 |
|---|---:|---:|---:|---:|---:|---|
| 64→64 | 14,443,527 | 23,646,578 | 20,191,365 | 44.8 秒 | 4.2 / 3.8 秒 | [64 档](../fixtures/v3-capacity-64-shared-regtest-summary.json) |
| 256→256 | 71,897,700 | 119,314,555 | 100,778,618 | 47.8 秒 | 13.7 / 10.6 秒 | [256 档](../fixtures/v3-capacity-256-shared-regtest-summary.json) |

另有一笔 **64 个不同直接父的 64→64** 在独立 BSV Node 1.2.3 高度 417 入块。64 个实际代币 vin 分别消费 64 笔已确认的直接父交易。沿用同一连续性密钥，链下生成 62 份聚合证明，本笔 verifier vin 只验一份最终证明。聚合约 3,697 秒，最终出证约 56 秒。付款为 8,691,107 字节，含本笔验证器与协同资金为 11,663,000 字节，父集合准备交易单列。该次使用字典重建父原文。共父和异父两份付款的 Groth16 推入均为 1,862 字节。 [异父记录](../fixtures/v3-capacity-64-distinct-regtest-summary.json)

实验节点放宽了 Script、栈和交易策略。付款使用隔离 regtest 的费用赞助，当前形状将赞助余量计入费用。摘要保留了实际 satoshi 开销和节点耗时，可用于后续调整找零、见证及公开转发政策。现有两种 64→64 记录均由 Script 认证所携带或重建的直接父交易，零历史增长由新版连续两笔同形状交易另行验收。256 档异父仍待独立节点验收。

## 复现

复用 [连续性测试参数](../recursion/continuity/README.md)，从仓库根目录运行。节点 cookie 与 RPC 使用独立 regtest，`--out` 指向新目录。256 档实测节点的单脚本、交易和栈策略分别为 160,000,000、200,000,000 和 700,000,000 字节。

```sh
PYTHONPATH=.:projects/groth16/reference:projects/cctp/reference:projects/cctp/recursion \
  ../cctp-test-tools/venv/bin/python projects/cctp/recursion/run_capacity_regtest.py \
  --capacity 64 --node-url "$REGTEST_URL" --cookie "$REGTEST_COOKIE" \
  --prover /tmp/cctp-continuity --setup-dir /tmp/cctp-continuity-demo \
  --out /tmp/cctp-capacity-64
```

追加 `--topology distinct` 可在 fanout 后为每个输出生成一笔独立认证转账，再把其证明组合到一笔付款。该路径使用压缩父交易记录和独立资金赞助，适合从干净的 BSV regtest 开始。`progress.json` 在准备、父交易确认和聚合出证各阶段原子更新，最终付款和钱包验收结束后生成 `summary.json`。
