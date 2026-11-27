<!-- Generated from manifest.yaml with Copier. -->

# P2PKH-Schnorr v0.16.0

[English](README.md) · [4thGraph](../../README.zh-CN.md) · [项目目录](../README.zh-CN.md) · [版本](versions/index.json)

## 开发入口

**[钱包 SDK 快速上手](docs/sdk.zh-CN.md#quickstart)** · [统一钱包 SDK](../../sdk/README.zh-CN.md#quickstart)

在 BSV 上向 BIP340 x-only 公钥的 HASH160 付款。公钥为 32 字节，所有者哈希为 20 字节，外部签名器返回 64 字节 BIP340 签名。这是一个实验付款模板。[BIP340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)

[协议](docs/spec.zh-CN.md) · [算法与执行](#算法与执行) · [复现方法](#复现方法) · [完整交易与栈测量](#完整交易与栈测量) · [实测数据](versions/v0.16.0/measurements.json)

| 入口 | 用途 |
| --- | --- |
| `bip340-verify ( script -- script )` | 构造独立验签器。执行时接收字节消息、公钥 x 和 y、BIP340 签名及 nonce 点的 y 坐标。 |
| `schnorr-lock ( script bytes -- script )` | 用 20 字节所有者哈希构造付款锁。执行时校验所有者和 BIP340 签名，并把已签摘要绑定到当前输入。 |
| `schnorr-unlock` | 用签名预映像、模式选择值、签名和公开坐标见证构造解锁脚本。 |

## 使用场景与取舍

独立验签器用空消息和变长消息检查 BIP340 签名器互操作。付款封装沿用同一算法，把当前输入签名预映像的 SHA256d 作为 32 字节消息。BIP340 验签、当前输入绑定和节点对已入金交易的接收各有独立的测试。[付款协议](docs/spec.zh-CN.md) · [复现与验证](#复现方法)

两方可用 BIP327 MuSig2 共同出款。锁承诺聚合 x-only 公钥，钱包沿用同一接口提交最终 BIP340 签名。夹具覆盖签名会话中断，并与同样要求双方都签字的原生 `CHECKMULTISIG` 对照。[MuSig2 与原生 2-of-2](docs/threshold-comparison.zh-CN.md)

每个 Schnorr 输出携带 22,515 字节的锁。OTDA ALL 的每个输入见证还包含本笔交易的序列化输出，因此加一个输出的成本随输入数增加。v0.15.0 与 v0.16.0 在一进一出退出到普通 P2PKH 的实测中，BIP143 ALL 均为 416 字节，OTDA ALL 均为 348 字节。锁的缩减体现在创建 Schnorr UTXO 的交易中。[实测记录](versions/v0.16.0/measurements.json)

## 算法与执行

1. 将 BIP340 签名读为 `r || s`。钱包用公开数据推导出公钥点 `P` 和 nonce 点 `R` 的偶数 y 坐标。脚本检查范围、奇偶性和公钥点的曲线方程。
2. 用原始的 `r`、公钥 x 和消息计算 BIP340 标签哈希，再对群阶 `n` 取模，得到挑战 `e`。
3. 计算 `sG − eP`，排除无穷远点，再用域上的同余关系将两个射影坐标与偶数 nonce 点 `R` 比对。坐标见证使脚本无需开方或求逆即可完成比较。

[BIP340 验签](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) · [见证与挑战校验](docs/spec.zh-CN.md) · [Forth 付款示例](reference/schnorr.fth) · [BIP340 标准库源码](../../src/fourthgraph/stdlib/bip340.fth)

### secp256k1 运算

v0.15.0 用满足 `21u⁶ = 1 mod p` 的常数，把 `(X:Y:Z)` 映射为 `(u²X:u³Y:Z)`。这个映射保持群运算，将 `y² = x³ + 7` 变为 `y² = x³ + 1/3`，使完备点加公式更简洁。连续倍点内核在两次倍点后才对 X 坐标取模。挑战哈希仍使用原始 BIP340 坐标。[坐标缩放与倍点](docs/spec.zh-CN.md#坐标缩放)

联合乘法从第 128 位拆分 `s`，并用 secp256k1 自同态 `φ(P) = λP` 将 `k = n − e` 拆为满足 `k1 + λk2 ≡ k mod n` 的两个带符号分量。两者的绝对值均小于 `2¹²⁸`。验签器用 64 个两位窗口联合累加四个分量。v0.16.0 在舍入和重构时复用两个 GLV 格基常数，并将计算挑战时留在栈上的群阶传给分解内核。[联合乘法与上界](docs/spec.zh-CN.md#联合标量乘法) · [共享曲线内核](../../src/fourthgraph/stdlib/secp256k1.fth)

在脚本里需要用运行时标量计算 secp256k1 曲线点的路径可以复用这些内核。当前 PELS Counter 的交易绑定使用公开固定参数 `d = k = 1`。脚本用候选预映像的摘要 `H` 和生成点的固定横坐标 `r` 计算 `s = (H + r) mod n`，做 low-S 归一化和 DER 编码，再交给原生 `OP_CHECKSIG` 执行 ECDSA 验签。v0.15.0 与 v0.16.0 编译的三种 PELS Counter 锁均逐字节一致。[PELS Counter](../pels-counter/README.zh-CN.md) · [固定密钥交易绑定](../../src/fourthgraph/bsv/pushtx.py)

## 复现方法

<a name="复现验收"></a>

在仓库根目录使用 Python 3.12。SDK 复放还用到 Node.js 22、Go 和 Rust/Cargo。测试使用公开夹具密钥、固定版本的 chain-gang 及隔离的 BSV Node regtest。

```sh
bash tools/setup-workspaces.sh
python3.12 -m venv projects/p2pkh-schnorr/workspace/p2pkh-schnorr
projects/p2pkh-schnorr/workspace/p2pkh-schnorr/bin/python -m pip install -r projects/p2pkh-schnorr/reference/requirements.txt
. projects/p2pkh-schnorr/workspace/p2pkh-schnorr/bin/activate
export SCRIPT_LAB_SDK_PYTHON="$VIRTUAL_ENV/bin/python"
```

```sh
PYTHONPATH=src:. python projects/p2pkh-schnorr/reference/generate_template.py --check
PYTHONPATH=src:. bash tools/verify_node.sh --profile raised -- python -m unittest discover -s projects/p2pkh-schnorr/reference
```

```sh
PYTHONPATH="$PWD/tests" REGTEST_CHRONICLE_HEIGHT=5 \
  bash tools/verify_node.sh -- "$SCRIPT_LAB_SDK_PYTHON" -m unittest -v test_secp256k1_library
bash tools/verify_node.sh -- bash sdk/verify_wallet.sh p2pkh-schnorr
```

验收在 libsecp256k1 和两套脚本引擎上核对全部 19 条 BIP340 官方验签向量，并用公开测试数据复算 8 条签名向量。付款用例覆盖 BIP143 与 Chronicle OTDA 有同索引输出时的全部 12 种签名模式，使用交易版本 1 和 2。测试覆盖过时的锁定时间、ALL/NONE/SINGLE 的输出承诺、错误坐标、所有者校验、手续费平衡和 Chronicle 激活。验签器测试覆盖两张查表及无穷远点。曲线测试用独立参考实现核对缩放点运算及 GLV 舍入，并在双引擎上复放正确和错误的结果。[付款测试](reference/test_schnorr.py) · [曲线测试](../../tests/test_secp256k1_library.py)

## 脚本尺寸

| 组件 | v0.15.0 | v0.16.0 |
| --- | ---: | ---: |
| 脚本自带群阶的 GLV 分解 | 182 B | 112 B |
| 群阶由调用者压栈的 GLV 分解 | — | 78 B |
| 独立 BIP340 验签器 | 21,848 B | 21,705 B |
| 完整付款锁 | 22,658 B | 22,515 B |

v0.16.0 的所有者槽位从字节偏移 189 开始。两个版本交替各测 56 次独立验签，chain-gang 中位数分别为 2.547 和 2.505 ms，BSV Node 本地 RPC 中位数分别为 9.567 和 9.584 ms。sCrypt 报告记录 v0.6.0 与旧版验签器的对照，以及同见证布局下与另一份 BIP340 实现的对照。[模板布局及指纹](versions/v0.16.0/layout.json) · [实测记录](versions/v0.16.0/measurements.json) · [sCrypt 对照](docs/scrypt-comparison.zh-CN.md)

## 开发和钱包接入

1. 调用 `createLock`，用 x-only 公钥或其 HASH160 生成收款锁。花费前识别已经核验的入金输出，检查 outpoint 和金额，再批准收款输出及手续费。SDK 默认创建 v0.16.0 输出，支持识别和花费 v0.6.0 至 v0.16.0 的各版本输出。
2. 单输入付款用 `signPayment`，已排好输入输出的交易用 `signInput`。外部签名器将收到的 32 字节作为 BIP340 消息，返回标准 64 字节签名。SDK 用 libsecp256k1 验签并推导两个公开 y 坐标。
3. SDK 将批准的预映像和公开见证交给 Forth 的 `schnorr-unlock`。每个解锁脚本都直接压入完整预映像。锁验证 BIP340 签名后，通过 PUSHTX 和原生 `OP_CHECKSIG` 把摘要绑定到实际输入。

[SDK 快速上手](docs/sdk.zh-CN.md#quickstart) · [付款协议](docs/spec.zh-CN.md) · [当前输入绑定](../../src/fourthgraph/bsv/pushtx.py)

### 从 Forth 构建

用 `REQUIRE stdlib/bip340.fth` 加载独立验签器。付款示例将该验签词与所有者校验、当前输入绑定组合成付款锁。运行上面的模板检查命令即可核对冻结的锁及其布局，用 `--write` 重新生成。[Forth 源码](reference/schnorr.fth) · [版本目录](versions/index.json)

## 完整交易与栈测量

<a name="交易实测"></a>

v0.16.0 夹具花费两个 Schnorr 输出，再创建两个 Schnorr 输出。BSV Node 1.2.3 和固定版本的 chain-gang 通过显式提供上一输出来验证完整输入。栈数据由开发求值器从第一个输入的成功路径取得。主栈项数、备用栈项数和两栈载荷分别取各自的峰值。交易和载荷以字节计。[实测记录](versions/v0.16.0/measurements.json) · [基准口径](../../docs/benchmark.zh-CN.md)

| 模式 | 输入 × 输出 | 上一输出锁定 | 解锁 | 新输出锁定 | 整笔 | 主栈 / 备用栈 | 两栈载荷 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| BIP143 ALL (`0x41`) | 2 × 2 | 22,515 × 2 | 329 × 2 | 22,515 × 2 | 45,806 | 90 / 13 | 3,403 |
| Chronicle OTDA ALL (`0x61`) | 2 × 2 | 22,515 × 2 | 45,321 × 2 | 22,515 × 2 | 135,790 | 90 / 13 | 90,474 |

```sh
PYTHONPATH=src:. bash tools/verify_node.sh -- "$SCRIPT_LAB_SDK_PYTHON" -m fourthgraph.benchmark.run \
  --project p2pkh-schnorr --venvs-dir projects/p2pkh-schnorr/workspace --output projects/p2pkh-schnorr/workspace/build/benchmark
```

在 BSV Node 1.2.3 的默认 regtest 策略下，两种模式的入金、周转和退出均进入内存池并出块。

```sh
PYTHONPATH=src:. bash tools/verify_node.sh --profile default -- "$SCRIPT_LAB_SDK_PYTHON" -m fourthgraph.benchmark.admission \
  p2pkh-schnorr --template v0.16.0 --turnover --output projects/p2pkh-schnorr/workspace/build/admission.json
```

## 输入输出边际与生命周期

每个边际单元格给出相对两进两出的**新增整笔字节（新输出锁定脚本 / 输入解锁脚本 / 其余序列化字节）**。上一输出的锁计入创建该 UTXO 的交易。两个生命周期总量都包括原生 P2PKH 入金与退出，周转列在中间增加一次 Schnorr 输出之间的付款。

| 模式 | 加输入后 | 加输入成本 | 加输出后 | 加输出成本 | 入金与直接退出 | 含一次周转 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| BIP143 ALL (`0x41`) | 3 × 2 | 372 (0 / 329 / 43) | 2 × 3 | 22,526 (22,515 / 0 / 11) | 46,032 | 91,838 |
| Chronicle OTDA ALL (`0x61`) | 3 × 2 | 45,487 (0 / 45,444 / 43) | 2 × 3 | 67,586 (22,515 / 45,056 / 15) | 46,046 | 181,835 |

[统一测量入口与复现口径](../../docs/benchmark.zh-CN.md) · [原生 2-of-2 生命周期对照](docs/threshold-comparison.zh-CN.md)
