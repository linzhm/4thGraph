# 原生 P2PK 与 P2PKH 基准

[English](README.md) · [4thGraph](../../README.zh-CN.md) · [项目目录](../README.zh-CN.md)

## 开发入口

**[钱包 SDK 快速上手](docs/sdk.zh-CN.md#quickstart)** · [统一钱包 SDK](../../sdk/README.zh-CN.md#quickstart)

生成 P2PK 或 P2PKH 收款脚本，再用自己的 secp256k1 签名器完成付款。

[协议规范](docs/developer.zh-CN.md#protocol) · [Forth 源码与编译结果](#forth-源码与编译结果) · [安全分析](docs/developer.zh-CN.md#security) · [复现与验证](#复现与验收) · [交易成本](#完整交易与栈测量)

原生 P2PKH 是 4thGraph 的第一个钱包接入示例，也是对照其他签名方案的交易成本基准。P2PK 使用同一个 secp256k1 签名器，把公钥放在输出锁中，供对照输入和输出的成本。两种模板都有可复放的公开向量。

[从 Forth 构建脚本](forth/README.md) · [复现基准](../../docs/benchmark.zh-CN.md)

## Forth 源码与编译结果

Forth 构造词检查收款字段的长度，再拼接锁定脚本字节。两个示例都使用仓库公开夹具中的公钥。

### P2PK

构造词接收 33 字节压缩 secp256k1 公钥。解锁输入提供 `<signature>`。[示例入口](forth/p2pk.fth) · [标准库](../../src/fourthgraph/stdlib/p2pk.fth)

```forth
: p2pk-lock ( bytes -- bytes )
    33 bytes-check-size
    bytes-hex 21 swap bytes-cat bytes-hex ac bytes-cat ;

: p2pk ( bytes -- bytes ) p2pk-lock ;
```

锁定脚本共 35 字节，将公钥压栈后执行 `OP_CHECKSIG`。

```text
0x0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798 OP_CHECKSIG
```

```text
210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac
```

### P2PKH

构造词接收 20 字节公钥 HASH160。解锁输入提供 `<signature> <public key>`。[示例入口](forth/p2pkh.fth) · [标准库](../../src/fourthgraph/stdlib/p2pkh.fth)

```forth
: p2pkh-lock ( bytes -- bytes )
    20 bytes-check-size
    bytes-hex 76a914 swap bytes-cat bytes-hex 88ac bytes-cat ;

: p2pkh ( bytes -- bytes ) p2pkh-lock ;
```

锁定脚本共 25 字节，先核对公钥哈希，再验证签名。

```text
OP_DUP OP_HASH160 0x751e76e8199196d454941c45d1b3a323f1433bd6 OP_EQUALVERIFY OP_CHECKSIG
```

```text
76a914751e76e8199196d454941c45d1b3a323f1433bd688ac
```

### 优化与复现

在 4thGraph 0.2.7 中，每个构造词在 `baseline`、`safe` 和 `stack` 模式下都生成相同的字节码。传入夹具数据求值后，得到上面的 35 字节 P2PK 和 25 字节 P2PKH 锁定脚本，与现有的 `lock_hex` 逐字节一致。钱包在链下执行 Forth 构造词，把得到的字节用作交易输出的锁定脚本。[基准夹具](template/baseline.json)

从仓库根目录运行以下命令，打印两种锁定脚本并查看构造词的 `stack` 优化报告。

```sh
export PYTHONPATH=src:.
forth=projects/p2pk-p2pkh-baseline/forth
python3 "$forth/payments.py" --public-key 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
python3 "$forth/payments.py" --hash160 751e76e8199196d454941c45d1b3a323f1433bd6

for entry in p2pk p2pkh; do
  python3 -m fourthgraph.workflow.protocol "$forth/$entry.fth" --entry "$entry" --optimize stack
done
```

## 使用场景与取舍

接入交易构造器、secp256k1 签名设备或迁移钱包时，可以从这里建立基准。先用公开向量核对序列化，再换成自己的签名器。后续接入其他方案时，沿用同一套收款和付款流程比较差异。

付款请求只提供公钥哈希时，可选择 P2PKH，花费时再提交完整公钥和签名。付款方已取得收款公钥时，可用 P2PK 做对照。在 BIP143 ALL 下，P2PK 每个输出多 10 字节，每个花费输入约少 34 字节。批量出款和多输入归集时，应按输入与输出的实际数量比较。[交易成本](#完整交易与栈测量)

## 复现与验收

从 `projects/p2pk-p2pkh-baseline/reference/` 中使用 Python 3.12、Rust 工具链和 [uv](https://docs.astral.sh/uv/)。

```sh
uv run --no-project --with-requirements requirements.txt python script_lab.py
```

脚本输出上笔交易、花费交易、Script 汇编、十六进制和用例结果。依赖已安装时，可以添加 `--offline`。通过 `cmp - ../template/baseline.json` 与[固定输出](template/baseline.json)比较。样本用公开私钥和合成上一输出，只用于本地重放。

离线示例使用版本 1 的交易和 BIP143 ALL。独立[验收矩阵](reference/acceptance.md)列出 2,880 种完整输入组合、80 个无配对 SINGLE 变更用例和 192 个 Chronicle 激活边界用例。统一测量使用独立的版本 2 交易样本。

## 输入输出取舍

在 BIP143 ALL 夹具中，P2PKH 每个输出锁比 P2PK 少 10 字节，每个解锁约多 34 字节，因为花费者需要携带公钥。两进两出样本分别为 374 和 326 字节，DER 签名编码长度可随样本变化。数据可用于核对钱包的锁定和解锁格式，完整交易的基准判定使用 BSV Node 和 chain-gang。

## 完整交易与栈测量

下表取自提交 `beeb4dd` 的确定性交易夹具，所有完整输入由 BSV Node 1.2.3 和项目固定的 chain-gang 版本验证。节点通过显式提供上一输出执行脚本，默认策略下的入内存池及出块另有复放记录。脚本和交易以字节计。表中按索引列出每个输入或输出的大小，`× n` 表示同样大小重复 n 次。栈数据取第一个输入的成功路径。主栈项数、备用栈项数和两栈载荷分别记录各自达到的峰值，单位为项或字节。栈开销由开发求值器估计，统计栈上数据的字节数。

| 模板与模式 | 输入×输出 | 上一输出锁定 | 解锁 | 新输出锁定 | 整笔 | 主栈 / 备用栈 | 两栈载荷 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `p2pk` · `0x41` | 2×2 | 35 × 2 | 73 × 2 | 35 × 2 | 326 | 2 / 0 | 105 |
| `p2pk` · `0x61` | 2×2 | 35 × 2 | 72 / 73 | 35 × 2 | 325 | 2 / 0 | 104 |
| `p2pkh` · `0x41` | 2×2 | 25 × 2 | 107 × 2 | 25 × 2 | 374 | 4 / 0 | 145 |
| `p2pkh` · `0x61` | 2×2 | 25 × 2 | 107 × 2 | 25 × 2 | 374 | 4 / 0 | 145 |

## 输入输出边际与生命周期

每个边际单元格为 **新增整笔字节（输出锁定脚本 / 输入解锁脚本 / 其余序列化字节）**。其余字节包括金额、outpoint、序列号和 CompactSize 等字段。上一输出脚本列用于说明被花费的锁，该脚本长度属于此前创建 UTXO 的交易。生命周期从原生 P2PKH 入金开始，以原生 P2PKH 退出，周转列在两者之间增加一次项目内转付。

| 模板与模式 | 加输入后 | 加输入成本 | 加输出后 | 加输出成本 | 入金与直接退出 | 含一次周转 |
| --- | --- | --- | --- | --- | --- | --- |
| `p2pk` · `0x41` | 3×2 | 113 (0 / 72 / 41) | 2×3 | 43 (35 / -1 / 9) | 550 | 877 |
| `p2pk` · `0x61` | 3×2 | 113 (0 / 72 / 41) | 2×3 | 45 (35 / 1 / 9) | 549 | 875 |
| `p2pkh` · `0x41` | 3×2 | 146 (0 / 105 / 41) | 2×3 | 34 (25 / 0 / 9) | 598 | 972 |
| `p2pkh` · `0x61` | 3×2 | 146 (0 / 105 / 41) | 2×3 | 33 (25 / -1 / 9) | 599 | 970 |

[统一测量入口与复现口径](../../docs/benchmark.zh-CN.md)

[Compile the Forth locking scripts](forth/README.md).
