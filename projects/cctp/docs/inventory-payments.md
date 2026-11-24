# 库存来源认证、额外脚本和连续转账体积

先按每笔交易核算两类成本。第一类是本笔创建和花费专用验证器、协同 UTXO 的字节，以及各持币 vin 为识别它们所重复提交的材料。第二类是转账经过一代后新增的历史字节。独立 BSV Node 1.2.3 的本组试验使用隔离 regtest、测试签发人和放宽的节点策略。所有金额按六位整数最小单位处理，单独统计 satoshi。

## 四个来源，任选两个付款

四笔真实来源交易分别发行 101、203、307、409 个最小单位。第一笔选 0 和 2，支付 300、找零 108。第二组独立选 1 和 3，支付 400、找零 212。两组复用同一份来源材料。第一位收款人拿实际收到的 300，加上原有的 97，单独签名支付 205、找零 192。该转付先于第二组选币入块。B、C、D 各用独立发行锚和相同语义的交易。

| 四叶库存，2→2 | 首笔付款 | 创建专用验证器 | 创建协同输出 | 合计 | 第一笔到直接转付的合计差 |
|---|---:|---:|---:|---:|---:|
| B，来源 Groth16，成员和守恒用 Script | 10,714 B | 453,257 B | 798 B | 464,769 B | +1 B |
| C，来源与付款各一份 Groth16 | 11,558 B | 902,922 B | 798 B | 915,278 B | −2 B |
| D，Script 打开四叶批准清单并验守恒 | 9,765 B | 3,365 B | 797 B | 13,927 B | +1 B |

逐项重建这九笔交易后，上述跨代差额全部来自持有人 DER 签名。三种布局都没有推入所花代币的父交易或更早祖先原文。每个持币输入仍会推入当前协同资金交易、当前 prevouts 和自己的 ForkID preimage。C 的两段通用验证脚本各为 449,730 和 449,742 字节；单份证明见证约 1,078 字节。提前准备验证器 UTXO 可以移走等待，但仍会产生其创建交易。[逐字段核算](../fixtures/inventory-overhead.json) · [B 的原始交易和证明](../fixtures/inventory-b-regtest.json.xz) · [C 的原始交易和证明](../fixtures/inventory-c-regtest.json.xz) · [D 的原始交易](../fixtures/inventory-d-regtest.json.xz)

常驻出证服务下，首笔付款在票据备妥后签好，B 用 1.7 毫秒，C 用 2.60 秒。收款人更新来源材料另用 2.54 和 2.46 秒。这里还要由实验签发人批准新库存和后续验证器。D 在相同批准边界下直接重算四个叶哈希所对应的根，用时不到 1 毫秒。热服务启动、票据交易、节点提交和 regtest 挖块在各摘要里单列。在节点重放中，替换为同锁、同金额的另一个真实验证器，再对新交易签名，B、C 都由协同输入拒绝。上述时长不含公网等待或生产签发服务。[逐输入重放](../fixtures/inventory-guard-replay-regtest-summary.json) [B 摘要](../fixtures/inventory-b-regtest-summary.json) · [C 摘要](../fixtures/inventory-c-regtest-summary.json) · [D 摘要](../fixtures/inventory-d-regtest-summary.json)

## 两次实际 64→64

各自的发行锚准备 128 个独立父交易。三组实测均先隔一个取一个，花 64 个异父 UTXO，再花第一笔的全部 64 个后继。两次的库存宽度、选择位置、输入输出数量、持有人签名编码宽度和资金布局一致。两笔都在独立节点入块。每组还执行一次改量后重新签署的负例。这里使用由发行方批准的库存根和两个预授权协同票据。

| 64→64 布局 | 第一代付款 | 第二代付款 | 每代含专用资金 | 每个持币见证 | 代币父原文字节 |
|---|---:|---:|---:|---:|---:|
| 完整持币 ForkID preimage | 402,029 B | 402,029 B | 431,278 B | 4,288 B | 0 |
| 持币 PUSHTX 使用紧凑 scriptCode，共享验证器 0x61 | 349,487 B | 349,487 B | 378,747 B | 3,445 B | 0 |
| 持币 PUSHTX 紧凑，共享验证器 0x41 按状态重建输出 | 295,095 B | 295,095 B | 319,101 B | 3,445 B | 0 |

紧凑版仍由持有人用 `0x41` 签完整持币锁。固定公钥的交易绑定验签执行在 `OP_CODESEPARATOR` 之后，只需推入带 35 字节 scriptCode 的候选 preimage。64 个持币见证合计减少 53,952 字节。新持币锁本身增加 11 字节，要分别体现在 64 个后继及共享验证器的 Chronicle 输出向量中。计入所有字段后，付款净省 52,542 字节，每代含资金净省 52,531 字节。用于控制比较的 70 字节 DER 仅限测试。[完整预像记录](../fixtures/inventory-e-wide-regtest-summary.json) · [紧凑预像记录](../fixtures/inventory-e-compact-regtest-summary.json)

进一步将共享验证器切到 ForkID ALL。钱包提供 64 份 50 字节后继状态，Script 使用固定模板重建全部有序 TxOut，并核对当前交易的 `hashOutputs`。共享验证器见证从 65,545 降到 11,155 字节，验证器资金交易从 28,463 降到 23,209 字节。持有人对改量或只改后继锁尾部的候选重新签名，节点均拒绝。两笔合法付款在高度 778 和 781 入块。含专用资金每代比初版少 112,177 字节。[0x41 全交易和节点负例](../fixtures/inventory-f-regtest-summary.json) · [0x41 入块原文](../fixtures/inventory-f-regtest.json.xz)

两种紧凑持币布局均有 64 份当前 prevouts 向量，每份 2,376 字节，共 152,064 字节。64 份协同资金交易原文每份 797 字节，共 51,008 字节。两项仅负载就有 203,072 字节。这两项占 295,095 字节最终付款的 68.8%。另有 56,704 字节的后继锁出现在实际输出中。使用 Chronicle 的对照配置还把这些锁带入共享验证器 preimage。它们随本笔输入数量变化。共父与异父使用同一套持币见证规则。单独实测 128 选 64 的成员检查，三种选法的 32 字节兄弟哈希共占 32、2,048 和 1,536 字节，组件试验未计入代币规则。[成员检查节点记录](../fixtures/inventory-multipath-128-regtest-summary.json)

## 信任边界与路线选择

- 旧 v3 已对 64 个不同直接父完成递归 B2G 和入块，付款时由 Script 重新认证父材料。现有树可以在选币确定后预计算中间证明，冷启动仍须承担聚合工作。[旧 64 异父结果](capacity.md)
- B、C 的来源电路证明已批准的四叶清单与库存根的对应关系。D 用 Script 直接打开同一类清单。宽交易则把发行方已批准的库存根写入专用验证器。两组付款的来源和后继范围都由实际交易决定，但**新根的批准权和有限票据仍在测试签发人手里**。不能通过不断给代币锁追加票据来支持无限转账，那会重新引入脚本增长。旧 v3 四个已花费的实际来源另做过全节点创建检查、前序聚合证明复核及新格式来源证明，两套锚的证据分别归档。[四个 v3 来源](../fixtures/inventory-origin-v3-archive.json) · [对应来源证明](../fixtures/inventory-origin-v3-proof.json)
- 对开放的 B2G，适合继续用 zk 认证合法铸造基例、直接父交易及指定 vout、库存根的合法更新。可优先让 Script 做实际 vin 匹配、成员检查、守恒、持有人授权和后继锁校验。将更新证明集中到一次可验证的库存建立或更新交易、供多个付款分摊，是待验证的路线。每笔付款仍必须认证一个来自该次更新的真实 outpoint、一贯的策略和当前可花费性。单纯复制同锁或同根不构成认证。
- 下一次脚本优化以 64 个独立父为基准，先压持币输入里重复的 prevouts 和协同资金，并将所有资金创建计账。开放的库存更新和验证器供给仍须在同一发行锚下跑通连续转账，才能把上述两代的零增量外推到该协议。

## 复现

从仓库根设置 `PYTHONPATH=.:projects/groth16/reference:projects/cctp/reference:projects/cctp/recursion` 并使用装有 chain-gang 的项目虚拟环境。每次运行指定独立 regtest 的回环 RPC、cookie 和一个新的输出目录。发行、资金和签名均为测试夹具。

- B、C、D 使用 [run_inventory_regtest.py](../recursion/run_inventory_regtest.py)。B 提供 `--origin-prover`、`--origin-params` 和 `--warm-provers`，C 追加付款参数与 prover，D 使用 `--direct-origin`。两种电路的测试参数生成见[来源](../recursion/inventoryorigin/README.md)和[付款](../recursion/inventoryprove/README.md)。
- 64→64 使用 [run_inventory_wide_regtest.py](../recursion/run_inventory_wide_regtest.py)。完整预像与 `--compact-holder` 分别运行。第三组同时使用 `--compact-holder --compact-outputs`。每次执行两笔连续付款。完整交易含所有立即父交易，归档可离线检查。[完整预像原文](../fixtures/inventory-e-wide-regtest.json.xz) · [紧凑预像原文](../fixtures/inventory-e-compact-regtest.json.xz)
- [inventory_overhead.py](../recursion/inventory_overhead.py) 可从三份四源原文和三份宽交易原文按角色重建字段并核对字节总数。
