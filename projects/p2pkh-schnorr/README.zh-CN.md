<!-- Generated from manifest.yaml with Copier. -->

# P2PKH-Schnorr v0.17.0

[English](README.md) · [4thGraph](../../README.zh-CN.md) · [项目目录](../README.zh-CN.md) · [版本](versions/index.json)

## 开发入口

**[钱包 SDK 快速上手](docs/sdk.zh-CN.md#quickstart)** · [统一钱包 SDK](../../sdk/README.zh-CN.md#quickstart)

在 BSV 上向 BIP340 x-only 公钥的 HASH160 付款。公钥为 32 字节，所有者哈希为 20 字节，外部签名器返回 64 字节 BIP340 签名。这是一个实验付款模板。[BIP340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)

[协议](docs/spec.zh-CN.md) · [算法与执行](#算法与执行) · [复现方法](#复现方法) · [完整交易与栈测量](#完整交易与栈测量) · [实测数据](versions/v0.17.0/measurements.json)

| 入口 | 用途 |
| --- | --- |
| `bip340-verify ( script -- script )` | 构造独立验签器。执行时接收字节消息、公钥 x 和 y、BIP340 签名及 nonce 点的 y 坐标。 |
| `schnorr-lock ( script bytes -- script )` | 用 20 字节所有者哈希构造付款锁。执行时校验所有者和 BIP340 签名，并把已签摘要绑定到当前输入。 |
| `schnorr-unlock` | 用签名预映像、模式选择值、签名和公开坐标见证构造解锁脚本。 |

## 使用场景与取舍

钱包默认使用已发布的 v0.17.0 模板。收款、花费和核验上一输出通过 SDK 完成。[钱包 SDK](docs/sdk.zh-CN.md#quickstart) · [版本目录](versions/index.json)

两方可以用 BIP327 聚合公钥共同授权同一个锁，签名会话由外部签名器管理。[MuSig2 与原生 2-of-2](docs/threshold-comparison.zh-CN.md)

高阶 Forth 实验记录 64 窗口自动构建和构造器的当前复放结果。[OTDA 实测](docs/high-level-forth.zh-CN.md#otda-constructor) · [优化历史](docs/high-level-forth.zh-CN.md#optimization-history)

## 算法与执行

1. 将 BIP340 签名读为 `r || s`，检查坐标范围、纵坐标偶性、公钥点曲线方程和标量范围。
2. 用原始 `r`、x-only 公钥和消息计算 BIP340 标签哈希，再对群阶取模得到 `e`。
3. 用 64 个两位窗口计算 `sG − eP`。检查射影坐标 Z 非零，再比对偶数 nonce 点的两个坐标。

付款封装校验公钥哈希，并把已验证的消息绑定到实际输入。发布版验签器使用坐标缩放、连续倍点和 secp256k1 GLV。[付款协议与曲线公式](docs/spec.zh-CN.md) · [Forth 付款源码](forth/schnorr.fth)

<a name="secp256k1-运算"></a>

在 Script 中执行 secp256k1 点运算的合约可以复用这些曲线内核。[secp256k1 库](../../src/fourthgraph/stdlib/secp256k1.fth)

## 复现方法

<a name="复现验收"></a>

在仓库根目录使用 Python 3.12。SDK 复放还用到 Node.js 24、Go 和 Rust/Cargo。测试使用公开夹具密钥、固定版本的 chain-gang 及隔离的 BSV Node regtest。

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

编译实验提供单独的命令和固定的实测记录。[Forth 构建与复放](docs/high-level-forth.zh-CN.md#replay)

## 脚本尺寸

| 组件 | v0.16.0 | v0.17.0 |
| --- | ---: | ---: |
| 独立 BIP340 验签器 | 21,705 B | 21,625 B |
| 完整付款锁 | 22,515 B | 22,435 B |

所有者槽位从字节偏移 189 开始。实测记录包含 chain-gang 与 BSV Node 对独立验签和两种原生 P2PKH 退出模式的交替测量。sCrypt 报告记录 v0.6.0 与旧版验签器的对照，以及同见证布局下与另一份 BIP340 实现的对照。[模板布局及指纹](versions/v0.17.0/layout.json) · [实测记录](versions/v0.17.0/measurements.json) · [sCrypt 对照](docs/scrypt-comparison.zh-CN.md)

## 开发和钱包接入

用 x-only 公钥或其 HASH160 调用 `createLock`。批准输出和手续费前，核验入金 outpoint、金额和所有者。单输入 BIP143 ALL 付款用 `signPayment`，已组装交易用 `signInput`。签名器接收 32 字节 BIP340 消息并返回 64 字节签名。[SDK 快速上手](docs/sdk.zh-CN.md#quickstart)

<a name="从-forth-构建"></a>

用 `REQUIRE stdlib/bip340.fth` 加载独立验签器。参考付款代码加入所有者校验和交易绑定。[Forth 源码](forth/schnorr.fth) · [版本目录](versions/index.json)

## 完整交易与栈测量

<a name="交易实测"></a>

v0.17.0 原样编码夹具花费两个 Schnorr 输出，再创建两个 Schnorr 输出。BSV Node 1.2.3 和固定版本的 chain-gang 通过显式提供上一输出来验证完整输入。栈数据由开发求值器从第一个输入的成功路径取得。主栈项数、备用栈项数和两栈载荷分别取各自的峰值。交易和载荷以字节计。[实测记录](versions/v0.17.0/measurements.json) · [基准口径](../../docs/benchmark.zh-CN.md)

| 模式 | 输入 × 输出 | 上一输出锁定 | 解锁 | 新输出锁定 | 整笔 | 主栈 / 备用栈 | 两栈载荷 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| BIP143 ALL (`0x41`) | 2 × 2 | 22,435 × 2 | 329 × 2 | 22,435 × 2 | 45,646 | 90 / 13 | 3,401 |
| Chronicle OTDA ALL (`0x61`) | 2 × 2 | 22,435 × 2 | 45,161 × 2 | 22,435 × 2 | 135,310 | 90 / 13 | 90,154 |

```sh
PYTHONPATH=src:. bash tools/verify_node.sh -- "$SCRIPT_LAB_SDK_PYTHON" -m fourthgraph.benchmark.run \
  --project p2pkh-schnorr --venvs-dir projects/p2pkh-schnorr/workspace --output projects/p2pkh-schnorr/workspace/build/benchmark
```

v0.17.0 的同一笔两进两出 OTDA ALL 付款，使用构造器后每个解锁脚本从 45,161 B 降到 4,819 B，整笔交易从 135,310 B 降到 54,626 B，并在默认 regtest 策略下出块。[构造器对照](docs/high-level-forth.zh-CN.md#otda-constructor)

在 BSV Node 1.2.3 的默认 regtest 策略下，两种模式的入金、周转和退出均进入内存池并出块。

```sh
PYTHONPATH=src:. bash tools/verify_node.sh --profile default -- "$SCRIPT_LAB_SDK_PYTHON" -m fourthgraph.benchmark.admission \
  p2pkh-schnorr --template v0.17.0 --turnover --output projects/p2pkh-schnorr/workspace/build/admission.json
PYTHONPATH=src:. bash tools/verify_node.sh --profile default -- "$SCRIPT_LAB_SDK_PYTHON" -m fourthgraph.benchmark.admission \
  p2pkh-schnorr --template v0.17.0-reconstructed --turnover --output projects/p2pkh-schnorr/workspace/build/admission-reconstructed.json
```

## 输入输出边际与生命周期

每个边际单元格给出相对两进两出的**新增整笔字节（新输出锁定脚本 / 输入解锁脚本 / 其余序列化字节）**。上一输出的锁计入创建该 UTXO 的交易。两个生命周期总量都包括原生 P2PKH 入金与退出，周转列在中间增加一次 Schnorr 输出之间的付款。

| 模式 | 加输入后 | 加输入成本 | 加输出后 | 加输出成本 | 入金与直接退出 | 含一次周转 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| BIP143 ALL (`0x41`) | 3 × 2 | 372 (0 / 329 / 43) | 2 × 3 | 22,446 (22,435 / 0 / 11) | 45,872 | 91,518 |
| Chronicle OTDA ALL (`0x61`) | 3 × 2 | 45,327 (0 / 45,284 / 43) | 2 × 3 | 67,346 (22,435 / 44,896 / 15) | 45,886 | 181,195 |

[统一测量入口与复现口径](../../docs/benchmark.zh-CN.md) · [原生 2-of-2 生命周期对照](docs/threshold-comparison.zh-CN.md)
