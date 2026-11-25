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

## 将溯源移入 Groth16

`parent-provenance-2x2` 使用独立的声明域和测试密钥。Groth16 认证实际父 `txid:vout`、规范代币锁和数量，并检查铸造是否消费指定发行锚的正确槽位、转账父是否消费批准的验证器。历史连续性依赖这些已确认前序交易实际执行了锁。电路只认证直接父及其来源，未在电路内验证前序 Groth16。当前 Script 认证交易，验持有人签名，做守恒并重建两个实际后继输出。 [电路](../recursion/parentcheckpoint/backtrace.go) · [Script](../recursion/covenant_backtrace.py)

| BSV Node 1.2.3，两笔异父 `2→2` | Script 溯源基线 | Groth16 溯源 |
|---|---:|---:|
| R1CS 约束 | 4,811,853 | 4,845,242 |
| 热会话出证，Alice → Bob | 11.46 s | 14.82 s |
| 热会话出证，Bob → Carol | 12.57 s | 17.36 s |
| 两代付款原文 | 4,075 / 4,075 B | 4,075 / 4,075 B |
| 共用的专用验证器资金交易 | 905,397 B | 904,965 B |
| 两笔付款及专用资金总和 | 913,547 B | 913,115 B |

新版 setup 总耗时 318.55 秒，按标准加载和校验参数的会话首次启动耗时 216.05 秒。两组热会话计时来自分别运行的样本。两代见证均为 `[1624, 376, 376]` 字节，证明推入均为 1,078 字节，直接父和祖先原文占用均为零。Node 在高度 110 和 111 入块。Bob 从节点验证收到的 275 个最小单位，再和另一笔铸造合并转付。第二台节点复核 Bob 和 Carol 的指定收款输出，接纳 Bob 的再支付，拒绝用 Carol 的密钥签名 Bob 的输入。假铸造复制真实锁仍无法出证，复用真证明也被节点拒绝。超发一单位并重签的交易被 Script 拒绝。此路径仍使用两个预确认的验证器输出。 [实测摘要](../fixtures/covenant-provenance-2x2-summary.json) · [独立重放](../fixtures/covenant-provenance-2x2-replay.json) · [交易与区块](../fixtures/covenant-provenance-2x2-regtest.json.xz)

## 开放验证器续补组件

Alice 与 Bob 各自从普通 BSV 钱包输入创建验证器资金及伴随资金，使用同一个公开批准锁模板，无需发行方签名或预登记资金 outpoint。两个持有人输入各自认证实际 `vin 1` 的伴随输出。伴随 Script 从其已认证的交易预像取得实际 `vin 0`，重算披露的资金 txid 并认证所花的 Groth16 锁。节点确认两次真实 Groth16 验证，并拒绝替换验证器、替换伴随输出、错签和改证明。组件使用已归档证明及其固定公开声明，属于资金认证测试。 [组件代码](../recursion/run_open_verifier_funding_regtest.py) · [入块记录](../fixtures/covenant-open-funding-summary.json) · [交易与区块](../fixtures/covenant-open-funding-regtest.json.xz)

| 续补组件 | Alice | Bob |
|---|---:|---:|
| 验证器资金 | 449,910 B | 449,910 B |
| 伴随资金 | 846 B | 846 B |
| 花费原文 | 456,237 B | 456,237 B |
| 花费与两笔专用资金合计 | 906,993 B | 906,993 B |

验证器资金原文还在每笔花费的伴随输入里出现一次。若把同样的披露接进代币付款，后继 Groth16 必须对约 456 KB 的实际父交易重算 txid。以实测组件和当前 4,075 字节付款相比，多约 7,065 个 SHA-256 块。按[既有分块探针](../recursion/parentbinding/README.md)的斜率，单个这样的父交易就约增加 2.49 亿条约束。这是规模外推。现有 4,075 字节布局无法使用这类父交易。开放续补与代币溯源的联合两代验收仍待完成，续补组件两个等长样本也没有发生代币继承。

## 验证器资金的认证中间态

证明从定稿资金原文读取唯一的规范 TxOut，认证输出计数位置、金额和含 CompactSize 的锁字段哈希。程序由标准 SHA-256 IV 算到最后一个整块边界，再以真实总长度填充剩余字节并算出 SHA256d。公开摘要同时承诺资金 `txid:vout`、锁字段哈希、金额、输出边界、总长度、整块长度、中间态和后缀摘要。伴随 Script 对实际 `vin 1` 做 ForkID ALL 交易绑定，从已认证的 prevouts 取 `vin 0`，用锁内批准的锁字段哈希重建同一公开摘要。 [出证关系](../recursion/parentbinding/risczero/benchmark/src/bin/funding-checkpoint-guest.rs) · [Script 与披露编码](../recursion/funding_checkpoint.py)

| 资金认证组件，每笔 | BSV 资金原文 | BSV 中间态对照 |
|---|---:|---:|
| 资金原文进入见证 | 449,910 B | 0 B |
| 中间态、必要字段和后缀 | 0 B | 106 B |
| 花费原文 | 456,237 B | 5,870 B |
| 两笔专用资金及花费 | 906,993 B | 456,687 B |

独立 BSV Node 1.2.3 以写入各自伴随锁的摘要为准确认两个组件花费。它拒绝了锁字节完全相同的另一出资 outpoint，也拒绝了改变中间态后重新签名的花费。另一个组件试验让宿主验证对原开放续补归档中实际 `vin 0` 的 STARK 收据。收据替换到另一真实资金 outpoint、改变 `vout`、锁字段哈希、金额、输出边界、总长度、中间态或后缀都会被宿主拒绝。入块字节表没有计入收据及链上 ZKP 验证器。 [BSV 对照摘要](../fixtures/covenant-funding-checkpoint-control.json) · [BSV 对照交易和区块](../fixtures/covenant-funding-checkpoint-control-regtest.json.xz)

RISC Zero 3.1.0 在 Apple M1 Max 对两笔各 449,910 字节的资金交易出证，分别耗时 **739.97 秒**和 **715.29 秒**。两份 succinct 收据各 **223,290 字节**，宿主验真约 13 毫秒，进程峰值 RSS 约 10.7 GB。非规范 CompactSize 的原文在解析时被拒绝。 [证明结果和公开输入](../fixtures/covenant-funding-checkpoint-stark.json) · [Alice 收据](../fixtures/covenant-funding-checkpoint-stark-alice.receipt.xz) · [Bob 收据](../fixtures/covenant-funding-checkpoint-stark-bob.receipt.xz)

开放续补还需要由代币锁认证实际执行的伴随策略，并使该策略直接检查已证明的摘要。仅把可替换的收据验证器放到另一个自由创建的 UTXO，会再次需要认证那个 UTXO 的真实锁身份。把当前 223 KB 的收据直接放进付款，还会让下一手的父交易超出现有 Groth16 电路的 4,075 B 布局。当前两项试验未组成新的两代代币付款。

## 复现

从仓库根目录使用装有 chain-gang 的 Python，设置 `PYTHONPATH=.:projects/spv-token:projects/groth16/reference:projects/spv-token/reference:projects/spv-token/recursion`。运行节点采用无对等连接的 BSV regtest，启用 txindex，Genesis 和 Chronicle 分别设为高度 1 和 2。创建验证器的交易需要允许约 1 MB 的交易以及相应的脚本策略。

```sh
cctp_run=$(mktemp -d)
(cd projects/spv-token/recursion && go build -o "$cctp_run/prover" ./freeze/cmd)
GOMAXPROCS=8 "$cctp_run/prover" -mode setup -profile parent-openings-2x2 -dir "$cctp_run/params"
GOMAXPROCS=8 python3 projects/spv-token/recursion/run_covenant_backtrace_regtest.py \
  --node-url "$cctp_rpc" --cookie "$cctp_cookie" --parameters "$cctp_run/params" \
  --prover "$cctp_run/prover" --out "$cctp_run/run"
```

用 [独立重放](../recursion/replay_covenant_backtrace_regtest.py) 的 `--summary`、`--policy`、`--key` 参数指定这一组输出和公开参数，并提供源节点与全新重放节点。STARK 使用与[单父基准](../recursion/parentbinding/risczero/benchmark/README.md)相同的 RISC Zero 3.1.0 工具链，将 guest 构建目标换成 `--bin backtrace-guest`，用 `checkpoint-image` 封装。用 [STARK 比较驱动](../recursion/compare_backtrace_stark.py) 对归档中的实际父交易出证并独立校验与 Groth16 相同的摘要。

复跑电路溯源时，将 setup 的 `-profile` 换为 `parent-provenance-2x2`，并使用新的参数目录和全新节点。开放续补组件另用全新节点，交易版本设为 2，继续用 `0x41` 做交易绑定和原生验签。该试验的伴随锁复用签名预像解析构件，依赖 Chronicle 后版本 2 的推入规则。

```sh
python3 projects/spv-token/recursion/run_open_verifier_funding_regtest.py \
  --node-url "$cctp_funding_rpc" --cookie "$cctp_funding_cookie" \
  --proof projects/spv-token/fixtures/covenant-provenance-alice-proof.json \
  --out "$cctp_run/open-funding.json"
```

中间态 BSV 对照另起一个全新节点，并给同一命令加 `--pinned-checkpoint-control`。STARK 使用[同一套 3.1.0 工具链](../recursion/parentbinding/risczero/benchmark/README.md)，构建 guest 时使用 `--bin funding-checkpoint-guest`，再经 `checkpoint-image` 转为 `$cctp_image`。

```sh
python3 projects/spv-token/recursion/compare_funding_checkpoint_stark.py \
  --archive projects/spv-token/fixtures/covenant-open-funding-regtest.json.xz \
  --r0vm "$CCTP_R0VM" --guest "$cctp_image" --verify "$cctp_checkpoint_verify" \
  --lock-field-sha256 fcb1164d3478fc51ab9841a2dfb6dc9b7f7ba39678238ea4867affcac6e881c9 \
  --out "$cctp_run/funding-stark"
```

复核归档收据时，用 `xz -dc` 还原收据，向 `checkpoint-verify` 传入收据路径、结果文件中的 `image_id` 及对应的 `statement_digest`。结果文件的 `receipt_sha256` 对应解压后的字节。
