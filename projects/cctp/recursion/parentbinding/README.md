# SHA-256 父交易绑定探针

探针在 BLS12-381 标量域上检验公开 SHA-256 分块从所给起始状态到所给结束状态的转换。每块 64 字节，两个状态各 32 字节，字序遵循 SHA-256。`FromIV` 电路将起点固定为 SHA-256 IV。检查点电路接收上一段的状态，调用方负责核对段间连续性。填充作为分块字节传入。测试使用标准库独立计算完整消息摘要。 [SHA-256 标准](https://csrc.nist.gov/pubs/fips/180-4/upd1/final) · [gnark v0.16.5 压缩构件](https://github.com/Consensys/gnark/blob/v0.16.5/std/permutation/sha2/sha2block.go)

从 `projects/cctp/recursion` 运行。

```sh
GOMAXPROCS=2 go test -count=1 -v ./parentbinding
```

| 完整分块数 | R1CS 约束 | 公开域元素 |
| ---: | ---: | ---: |
| 1 | 166,957 | 128 |
| 2 | 202,231 | 192 |
| 4 | 272,776 | 320 |
| 8 | 413,865 | 576 |

固定 IV 的单块 R1CS 为 166,688 个约束。一次本机运行对 `abc` 的标准填充分块生成并验证了 Groth16 证明。参数生成约 116 秒，出证约 2.17 秒，验证约 2.89 毫秒，运行配置为 `GOMAXPROCS=2`。替换公开分块字节后验证失败。第二个向量从已知中间状态继续计算，得到与标准库相同的摘要，并拒绝被替换的起始状态。

公开起点的 2 到 8 块样本每增加一块约增加 35,272 个约束。归档交易原文有 22,572,492 字节，整块前缀有 352,655 块，沿同一斜率外推约 124.4 亿约束。该外推以单电路内复用查找表为前提，未编译大规模电路。分段证明还会产生分段电路和聚合成本。表中的公开输入是测量接口，实际压缩见证需要隐藏省去的父交易字节，并将其绑定到交易承诺。 [归档父交易前缀](../../docs/parent-binding.md)

接入父交易验证时，独立证明需连续绑定 IV、分块顺序、已处理字节数和最终 SHA-256 填充，并计算第二轮 SHA-256。BSV Script 需要将计算出的 txid 对照实际输入 outpoint，再绑定用于解析 vout、金额、锁和原前序证明声明的字段。当前探针的测试密钥在本地临时生成，现有 continuity 密钥、公开声明和 Script 验证路径均未接入该探针。

### 隐藏段数据

`SHA256Leaf` 将整块原文字节作为私有见证，并公开起末状态各两个大端 uint128 与起始块序号。段长由电路固定。第零块从标准 IV 起算。两块宽度实测为 202,819 条约束及五个公开标量，不含 Gnark 的常量输入。聚合关系需验证相邻段的索引与状态衔接，并认证实际交易字段边界、最终填充和第二重 SHA-256。叶证明只证明该段的状态转换。 [分段电路](sha_leaf.go)

本机用同一组测试参数为两个相邻的 128 字节向量分段出证。参数生成 47.23 秒，两段出证分别为 1.35 和 1.38 秒，原生验证约 2.5 毫秒。复用旧证明并替换其起始块索引被拒绝。该实测是分段组件，完整父交易证明及节点花费另行验收。

```sh
GOMAXPROCS=4 go test -count=1 -v ./parentbinding -run '^TestPrivateSHA256Leaf$'
GOMAXPROCS=4 CCTP_SHA256_LEAF_NATIVE_TEST=1 go test -count=1 -v ./parentbinding -run '^TestPrivateSHA256Leaf$'
```

## 生成父交易中间态

在仓库根目录运行。输入是已序列化的 BSV 父交易原文，钱包应在父交易定稿后生成。

```sh
python3 -m projects.cctp.recursion.parent_prefix parent.hex --out checkpoint.json
python3 -m projects.cctp.recursion.parent_prefix parent.bin --input-format raw
```

用 `-` 接受标准输入。省略 `--out` 时输出到标准输出。JSON 记录 `midstate`、`processed_bytes`、`suffix`、输出计数和各输出在原文中的位置，同时提供两种字序的 `txid`、后缀摘要和 `hash_outputs`。工具按规范 CompactSize 解析 legacy 交易，并核对续算 txid 与直接对交易原文计算的 SHA256d。链上使用这份数据时，需要由证明认证被省略的前缀。 [Python 实现](../parent_prefix.py)

## 有界父检查点验证

独立测试电路接收一笔 332 字节、单输入和两个单字节锁输出的定稿父交易。从 SHA-256 IV 连续计算 256 字节前缀和 76 字节原始后缀，按完整长度填充并重算 txid。公开声明承诺 txid、中间态、已处理长度、真实输出计数位置和数量、后缀哈希及输出向量哈希。Script 用 `0x41` 取得本笔实际 vin0 的父 outpoint，并将证明绑定到实际执行验证器的 vin1 和所选 vout。普通 BLS12-381 Groth16 电路使用独立测试参数，共 548,575 条约束和两个公开域元素。 [电路](../parentcheckpoint/circuit.go) · [Script 绑定](../checkpoint_verifier.py)

从仓库根目录复现。使用无对等连接的 BSV regtest，并配置足以接纳约 455 kB 验证锁的节点策略。`rpc_url` 和 `rpc_cookie` 指向该节点。Python 依赖与其他 CCTP regtest 运行器相同。

```sh
checkpoint_run=$(mktemp -d)
(cd projects/cctp/recursion && go build -o "$checkpoint_run/proof" ./freeze/cmd)
GOMAXPROCS=4 "$checkpoint_run/proof" -mode setup -profile parent-checkpoint -dir "$checkpoint_run/params"
GOMAXPROCS=4 PYTHONPATH=.:projects/groth16/reference:projects/cctp/reference:projects/cctp/recursion \
  python3 projects/cctp/recursion/run_parent_checkpoint_regtest.py \
  --node-url "$rpc_url" --cookie "$rpc_cookie" --prover "$checkpoint_run/proof" \
  --parameters "$checkpoint_run/params" --out "$checkpoint_run/regtest"
```

运行器保留父交易原文、与命令行相同的中间态 JSON、证明和节点验收摘要。BSV Node 1.2.3 在高度 638 确认了 1,560 字节的花费，拒绝四种改动，中间态、后缀、父 txid 及 vout 各一项。实测父披露的 push 从 335 字节降至 111 字节，额外证明见证 1,078 字节，同口径净增 854 字节。验证器资金交易另计 450,847 字节。本机原生出证 6.43 秒，带编译和密钥加载的命令共 105.58 秒。 [原始验收](../../fixtures/parent-checkpoint-regtest-summary.json)

测试父输出使用一次性占位锁，完整 CCTP 绑定仍须认证父验证器资金身份和前序连续性声明，并由代币锁强制消费指定验证器。衡量节省时以真实 Token 父交易为基准，分别核算父披露、证明、验证器资金和持币输入重复的资金见证。

## 真实 Token 父交易的对照

两个测试资产分别从独立发行锚开始，使用同一原生 v2 Token 锁模板。测试入金铸造 640 个最小单位，随后由管理签名冻结和解冻。子交易的 vin0 是策略真正要求的验证器，vin1 是持有人签署的解冻后继。两组都强制输出的数量、持有人、状态、satoshi 和锁逐字节保持一致。原文组在 Script 对完整父原文计算 txid。中间态组从已认证后缀提取同一个输出，再用固定的 Groth16 测试密钥认证真实 txid 和中间态。两个版本对当前交易仍使用 `0x41`。 [Token 实验锁](../token_checkpoint_verifier.py)

回到仓库根目录，在前文配置的节点运行两组。两组分别准备资金，验收摘要保存在各自的 `summary.json`。

```sh
export PYTHONPATH=.:projects/groth16/reference:projects/cctp/reference:projects/cctp/recursion
python3 projects/cctp/recursion/run_token_checkpoint_regtest.py \
  --node-url "$rpc_url" --cookie "$rpc_cookie" --out "$checkpoint_run/token-raw"
GOMAXPROCS=4 "$checkpoint_run/proof" -mode setup -profile parent-checkpoint-token -dir "$checkpoint_run/token-params"
GOMAXPROCS=4 python3 projects/cctp/recursion/run_token_checkpoint_regtest.py \
  --node-url "$rpc_url" --cookie "$rpc_cookie" --out "$checkpoint_run/token-checkpoint" \
  --prover "$checkpoint_run/proof" --parameters "$checkpoint_run/token-params"
```

固定 profile 使用 3,433 字节的原生解冻父交易，省去的父前缀为 1,856 字节，链上披露状态 32 字节及后缀 1,577 字节。已确认的原文组子交易为 8,124 字节，加验证器资金交易合计 9,035 字节。检查点电路约束数为 2,988,852，已对这一组实际入块的原文父交易求解并得到与 Python 一致的公开声明。[原文对照结果](../../fixtures/token-raw-parent-regtest-summary.json)

检查点组的持有人花费也由节点在高度 854 确认。父披露加证明从 3,436 字节降为 2,690 字节，省 746 字节。持币输入仍重复验证器资金，含资金交易的总字节增加至 908,280。原生出证耗时 15.48 秒，完整命令 358.34 秒。节点拒绝改数量、错持有人、中间态和后缀。这个结果覆盖一笔特定形状的原生解冻父交易。 [检查点组链上结果](../../fixtures/token-checkpoint-regtest-summary.json)

两组比较指定 Token vout 的认证和后继约束，测试资产的起点由测试入金签发。v3 版仍需在父绑定证明中约束实际父验证器和前序连续性，并单独测量资金见证重复的成本。
