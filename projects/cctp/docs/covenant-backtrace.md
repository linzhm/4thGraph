# 以真实父开口验证两笔连续代币付款

这个隔离配置比较同一组异父 `2→2` 付款的父开口出证。资金与代币见证使用固定线宽。新测试发行锚授权三个真实发行 outpoint，数量分别为 300、200、150 个六位精度最小单位。发行前独立确认一笔创建两个一次性证明验证器输出的资金交易。收款方预配置发行锚、这笔资金的 txid 和验证密钥。付款阶段仅使用各付款人的持有人签名。

## 实际验证关系

| 位置 | 规则 |
|---|---|
| `vin 0` | 节点认证执行中的 ForkID ALL 预像及有序 outpoints。共享锁执行发行、直接前序和本次守恒检查，并验证绑定两份父输出及来源的一份开口证明。 |
| `vin 1/2` | 每个代币锁要求实际 `vin 0` 花费策略批准的验证器资金输出，并验证相应持有人对整笔交易的签名。 |
| `vout 0/1` | 共享锁从收到的数量和公钥重建两份完整的规范 TxOut，匹配当前签名预像的 `hashOutputs`。载体为每枚代币 UTXO 1,000 satoshi。 |

父开口证明读取两笔完整的定稿交易，重算各自的 BSV SHA256d，按规范 CompactSize 解析实际输入及所选 vout。公开摘要认证两笔 `txid:vout`、各自的规范锁身份、数量、持有人及创建它的实际 `vin 0`。批准的 mint 布局只有一个输出。转账布局允许两个指定输出，其实际创建输入必须为同一策略中的已批准验证器。前序直接从真实链上执行本规则，后继按同一格式继续花费。整个父原文只进入链下证明器。

零历史增长的判断依据是固定槽位的见证只含本笔证明、固定字段、签名和当前交易预像。此前花费的长度没有作为数据字段进入本笔见证。试验验证器资金只有两个已批准输出。持续供给应由开放、可认证的资金机制解决。

将溯源放进证明的对照电路也认证同样的父交易字段，另在电路里检查发行锚、mint 槽位量及真实前序验证器。消费锁若选用这种证明，应固定独立的公开声明域、发行锚和新验证密钥。数量守恒和持有人验签仍可在 Script 执行。 [对照约束](../recursion/parentcheckpoint/backtrace.go)

## BSV Node 1.2.3 测量

| | Alice → Bob | Bob → Carol |
|---|---:|---:|
| 入块高度 | 110 | 111 |
| 实际两笔直接父原文，均在链下出证 | 903 + 903 B | 4,075 + 903 B |
| 付款原文 | **4,075 B** | **4,075 B** |
| 链上历史交易原文 | 0 B | 0 B |
| 证明推入 | 1,078 B | 1,078 B |
| Groth16 热会话出证 | 11.46 s | 12.57 s |

两笔的 `scriptSig` 分别为 1,624、376、376 字节。独立的一笔验证器资金交易创建两个各含 **452,660 B** 锁的输出，费用资金原文 **905,397 B**，含两笔付款的总和 **913,547 B**。该合计只计实际专用验证器资金和付款，测试发行、拒绝例和基础 BSV 资金单列。采用固定 70 字节 DER 测试签名与固定 48 字节 Groth16 数字推入，避免编码长度干扰测量。 [实际交易和区块](../fixtures/covenant-backtrace-2x2-regtest.json.xz) · [逐项结果](../fixtures/covenant-backtrace-2x2-summary.json)

第二笔从链上取回第一笔的 `vout 0`，与一笔独立铸造一起花费。节点拒绝用同一真实父证明支付多出一个最小单位的交易，也拒绝用真实开口证明花一个锁、数量和持有人完全相同的伪来源代币。采用当前链视图的第二台节点独立确认收款与转付。 [独立重放](../fixtures/covenant-backtrace-2x2-replay.json) · [收款预配置](../fixtures/covenant-backtrace-2x2-recipient-policy.json)

Groth16 的测试 setup 耗时 357.82 秒，电路 4,811,853 条约束。在首次按标准会话加载参数时，从启动到首次求解约 310 秒。第一次付款后执行非规范数据推入的分支遭 mempool 策略拒绝。修复该分支，重跑仍使用相同的电路、证明密钥和验证密钥。为避免重试时重复验证本地生成的 1 GB 测试证明密钥，在临时程序内预先核对了其 SHA-256，随后用 gnark 的受信参数读取路径重开会话，约 93 秒。仓库的复现命令使用标准验证加载。

## 相同父开口的 STARK 比较

| RISC Zero 3.1.0 | Alice → Bob | Bob → Carol | 每笔宿主收据 | 仅替换证明字段后的付款大小 |
|---|---:|---:|---:|---:|
| Composite | 14.29 s | 14.97 s | 244,366 B | 247,370 B |
| Succinct | 27.70 s | 27.89 s | 223,290 B | 226,294 B |

STARK 计时包含程序执行、证明生成和写出宿主收据。两种编码都由固定 guest 身份与已入块 Groth16 的同一公开摘要独立验真。用唯一输出的铸造父提交 `vout 1` 时，guest 拒绝出证。替换大小使用实际推入和 CompactSize 开销，当前还没有该 STARK 的 BSV 验证器锁和资金交易，所以这两列的字节只衡量付款见证。 [STARK 实测](../fixtures/covenant-backtrace-2x2-stark.json)

将溯源移入电路的配置编译到 **4,845,242** 条约束，比开口电路多 **33,389**。对两笔已入块的实际付款父数据，该配置均可求解。将锁和金额相同的伪来源放入相同槽位时，开口仍成立，增加源身份约束的电路拒绝求解。此次对照覆盖约束求解，消费锁接线、证明参数和节点花费分别验收。

## 复现

从仓库根目录使用装有 chain-gang 的 Python，设置 `PYTHONPATH=.:projects/groth16/reference:projects/cctp/reference:projects/cctp/recursion`。运行节点采用无对等连接的 BSV regtest，启用 txindex，Genesis 和 Chronicle 分别设为高度 1 和 2。创建验证器的交易需要允许约 1 MB 的交易以及相应的脚本策略。

```sh
cctp_run=$(mktemp -d)
(cd projects/cctp/recursion && go build -o "$cctp_run/prover" ./freeze/cmd)
GOMAXPROCS=8 "$cctp_run/prover" -mode setup -profile parent-openings-2x2 -dir "$cctp_run/params"
GOMAXPROCS=8 python3 projects/cctp/recursion/run_covenant_backtrace_regtest.py \
  --node-url "$cctp_rpc" --cookie "$cctp_cookie" --parameters "$cctp_run/params" \
  --prover "$cctp_run/prover" --out "$cctp_run/run"
```

用 [独立重放](../recursion/replay_covenant_backtrace_regtest.py) 的 `--summary`、`--policy`、`--key` 参数指定这一组输出和公开参数，并提供源节点与全新重放节点。STARK 使用与[单父基准](../recursion/parentbinding/risczero/benchmark/README.md)相同的 RISC Zero 3.1.0 工具链，将 guest 构建目标换成 `--bin backtrace-guest`，用 `checkpoint-image` 封装。用 [STARK 比较驱动](../recursion/compare_backtrace_stark.py) 对归档中的实际父交易出证并独立校验与 Groth16 相同的摘要。
