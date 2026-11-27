# 高阶 Forth BIP340 自动优化实验

[English](high-level-forth.en.md) · [项目介绍](../README.zh-CN.md)

## 环境与输入

实验使用编译器提交 `64624db` 上的 4thGraph 0.2.7、安装了 Schnorr 项目依赖的 Python 3.12、BSV Node 1.2.3，以及提交 `74676b9` 上的 chain-gang 0.13.2。复现命令在仓库根目录执行。[项目环境](../README.zh-CN.md#复现验收)

高阶验签器检查公开见证，计算标签挑战，再求 `sG + (n − e)P`。它用 256 轮二进制循环计算联合乘法，倍点、累加生成点和累加公钥都使用同一条完备射影点加公式。最后排除无穷远点并比对偶数 nonce 点的两个坐标。带符号 Script 余数的范围写在公式声明里，外层验签器在进入点公式前检查不受信的见证字节。[验签 Forth](../experiments/high-level/verifier.fth) · [点运算 Forth](../experiments/high-level/arithmetic.fth)

两个高阶构建使用同一份 Forth、同一个外部签名器和同一份付款封装。封装校验所有者，并把签名绑定到实际的当前输入。每笔测试交易都携带完整的原始签名预映像。手工版 v0.17.0 使用另一套联合乘法算法，包含 GLV、固定基分解和查表窗口。[付款协议](spec.zh-CN.md)

## 构建与复放

使用项目环境中的 Python。

```sh
PYTHONPATH=src:. bash tools/verify_node.sh --profile raised -- \
  "$SCRIPT_LAB_SDK_PYTHON" projects/p2pkh-schnorr/experiments/high-level/compare.py \
  --output workspace/schnorr-high-level --samples 12
```

脚本对比 17 种编译计划，包括禁用可选优化的基线、自动选择和显式优化计划。每份字节不同的产物都在两个引擎里复放 19 条固定 BIP340 向量、8 种错误见证、全部 12 种有同索引输出的付款模式和普通 P2PKH 退出。每笔付款在签名后改动锁定时间都应当被拒绝。输出目录包含编译脚本、带 SHA-256 指纹和引擎结果的对照报告，以及胜出公式的调度轨迹。开启轨迹重新编译必须得到同样的脚本字节。[对照运行脚本](../experiments/high-level/compare.py)

## 测量与证据

| 构建 | 独立验签器 | 付款锁 | 完备点加 |
| --- | ---: | ---: | ---: |
| 高阶 Forth，禁用可选优化 | 432,757 B | 433,567 B | 311 B |
| 高阶 Forth，自动优化 | 217,891 B | 218,701 B | 96 B |
| 手工版 v0.17.0 | 21,625 B | 22,435 B | — |

可选优化将付款锁缩减 **214,866 B（49.6%）**。完备点加每次生成少 215 B，共有 768 处。每轮有两次按位决定是否执行的点加，两条分支都占锁脚本空间。自动优化后的高阶锁体积是 v0.17.0 的 9.75 倍。本次编译器优化在给定算法内简化公式并调度栈访问。[实测记录](../experiments/high-level/measurements.json)

| 完整签名交易 | 高阶基线 | 自动优化 | 手工版 v0.17.0 |
| --- | ---: | ---: | ---: |
| 2×2 BIP143 ALL | 867,914 B | 438,182 B | 45,646 B |
| 2×2 OTDA ALL | 2,602,122 B | 1,312,926 B | 135,310 B |
| 1×1 退出到普通 P2PKH，BIP143 / OTDA | 416 / 348 B | 416 / 348 B | 416 / 348 B |

OTDA ALL 见证包含序列化输出，收款锁变短也会缩短每个输入的签名预映像。2×2 BIP143 夹具中，高阶构建第一个输入的主栈峰值从 62 项降到 44 项，两栈载荷峰值从 3,351 B 降到 1,236 B。栈峰值用开发求值器测量，完整输入由 BSV Node 和 chain-gang 使用对应上一输出独立验证。[栈与交易记录](../experiments/high-level/measurements.json)

每种构建在每个引擎上交替测量 12 次独立验签。高阶基线、自动优化版和 v0.17.0 的 chain-gang 中位数分别是 16.381、11.627 和 3.308 ms。BSV Node 本机 RPC 中位数分别是 132.240、83.314 和 13.953 ms，包含上一输出锁的序列化和传输时间。[交替测量](../experiments/high-level/measurements.json)

<a name="otda-constructor"></a>

## OTDA 构造器

用构造器复放相同的两进两出 OTDA ALL 交易。每个输入只携带一份识别到的模板片段，再按原顺序拼入各输出的金额和所有者哈希。模板内的重复字节用 Script 拼接展开。两种编码的签名器和锁脚本都拿到同一份完整预映像。[预映像构造](../../../src/fourthgraph/bsv/otda_reconstruction.py)

| 构建 | 原样编码交易 | 重建交易 | 重建后每个输入的解锁脚本 |
| --- | ---: | ---: | ---: |
| v0.17.0 | 135,310 B | 54,626 B | 4,819 B |
| 高阶基线 | 2,602,122 B | 880,172 B | 6,458 B |
| 高阶自动优化 | 1,312,926 B | 446,920 B | 4,698 B |

三种构建退出到普通 P2PKH 都用原样见证，整笔 348 B。钱包默认识别已冻结的发布模板。两份高阶构建在实验中接入同一个构造器。复现发布模板的入金和出块时，将项目首页入网复现命令的模板设为 `v0.17.0-reconstructed`。

```sh
PYTHONPATH=src:. bash tools/verify_node.sh --profile raised -- \
  "$SCRIPT_LAB_SDK_PYTHON" projects/p2pkh-schnorr/experiments/high-level/compare_otda.py \
  --output workspace/schnorr-high-level/otda-measurements.json
```

[对照实测](../experiments/high-level/otda-measurements.json)

## 不同交易类型的构造器选择

编译器对同一完整预映像比较原样压栈、整段预映像的重复展开、模板字典和跨模板共享字典。后一个候选可以从先前构建的模板项取出相同前缀或后缀。矩阵包含 54 个场景、87 份不同的签名交易，覆盖归集、批量分发、找零、原生输入输出混用、新旧模板混用、交易版本 1 和 2 的全部 12 种 sighash、同笔交易内不同模式、激活前入金，以及 252/253 个输出的 CompactSize 边界。自动 Forth 版本通过已冻结的哈希复建，发布版作为对照。

| OTDA ALL 场景 | 原样压栈 | 按模板构造 | 编译器选择 |
| --- | ---: | ---: | ---: |
| 三种发布模板加一个原生输出 | 226,887 B | 106,729 B | 99,237 B |
| 自动 Forth 两进两出周转 | 1,312,926 B | 446,920 B | 446,920 B |
| 自动 Forth 与发布模板混用，加一个原生输出 | 724,224 B | 259,686 B | 258,122 B |

两套引擎使用对应上一输出验证每个构建。矩阵记录在每种 sighash 下改动金额、输出顺序、锁定时间或输入序号后的预期结果。复放采用 raised regtest 策略。[矩阵实测](../experiments/high-level/constructor-matrix.json)

```sh
REGTEST_CHRONICLE_HEIGHT=5 PYTHONPATH=src:. bash tools/verify_node.sh --profile raised -- \
  "$SCRIPT_LAB_SDK_PYTHON" projects/p2pkh-schnorr/experiments/high-level/constructor_matrix.py \
  --output workspace/schnorr-high-level/constructor-matrix.json
```

<a name="64-window-lowering"></a>

## 曲线专用的 64 窗口 lowering

第二版高阶算法先将生成点标量分成 `s = s0 + 2^128 s1`，再用 secp256k1 的 GLV 关系 `k = k1 + λk2 mod n` 分解变基标量。四个 128 位分量每次各处理两位，用两张点表查找合成点。64 窗中的每一窗先对累加器倍点两次，再累加两张表各自选出的点。索引零代表无穷远点。高阶 Forth 沿用二进制版的同一条自动生成完备点加公式。固定表由编译器从曲线生成点计算，GLV 分解使用标准库的内核。[联合点乘 lowering](../../../src/fourthgraph/compiler/secp256k1-joint.fth) · [BIP340 验签封装](../experiments/high-level/window-verifier.fth)

| 构建 | 付款锁 | 两进两出 OTDA ALL，使用模板构造器 |
| --- | ---: | ---: |
| 高阶二进制，自动编译 | 218,701 B | 446,920 B |
| 高阶 64 窗，禁用可选优化 | 114,753 B | 264,448 B |
| 高阶 64 窗，自动内联 | 56,414 B | 137,720 B |
| 高阶 64 窗，自动独立编译后链接 | 43,999 B | 107,404 B |
| 手工 v0.17.0 | 22,435 B | 54,626 B |

在自动编译下，切换算法使每个锁少 162,287 B。同一个联合点乘词独立编译后链接，又少 12,415 B。链接版用类型化布局查表和通用点加；手工版用栈上查表、专用倍点和混合点加。这些是同属 64 窗算法的两种实现之间的进一步差别。

表格和实测文件记录了提交 `7882fb7` 中的编译器结果。从该提交的检出目录运行下列命令，可以复现记录中的脚本字节。引入 #109 的共享栈调度改动后，同一复放中禁用可选优化的构建为 113,983 B，自动内联构建为 55,644 B，链接构建仍为 43,999 B。 [实测提交](https://github.com/linzhm/4thGraph/tree/7882fb793b1d354614df9210b59b8c30037f2343) · [PR #109](https://github.com/linzhm/4thGraph/pull/109)

双引擎复放包括固定 BIP340 向量、错误见证、全部 12 种有同索引输出的付款模式、普通输出退出和修改锁定时间。链接版还复用构造器矩阵中的八个自动模板场景，检查输出和输入序号的改动。[实测](../experiments/high-level/window-measurements.json) · [交易矩阵](../experiments/high-level/window-matrix.json)

```sh
PYTHONPATH=src:. bash tools/verify_node.sh --profile raised -- \
  "$SCRIPT_LAB_SDK_PYTHON" projects/p2pkh-schnorr/experiments/high-level/window_compare.py \
  --output workspace/schnorr-high-level/window-measurements.json
REGTEST_CHRONICLE_HEIGHT=5 PYTHONPATH=src:. bash tools/verify_node.sh --profile raised -- \
  "$SCRIPT_LAB_SDK_PYTHON" projects/p2pkh-schnorr/experiments/high-level/window_compare.py \
  --matrix-only --output workspace/schnorr-high-level/window-matrix.json
```

<a name="joint-lowering-candidates"></a>

## 联合点乘候选

四个自动候选使用同一个 BIP340 封装和同一套 64 窗口 GLV 分解。字节表候选提前计算窗口索引，并采用合并倍点和混合点加。栈版使用相同的技术，固定表存仿射点，查表直接使用 `OP_PICK`。缩放栈版进一步使用登记的 `a=0, 3*b=1` 点运算内核。编译器转换输入点坐标，输出恢复为原曲线坐标。[曲线模型选择](../../../docs/optimization-paths.zh-CN.md#坐标模型选择)

| 候选 | 付款锁 | 两进两出 OTDA ALL，使用模板构造器 |
| --- | ---: | ---: |
| `glv-joint-window-2` | 43,999 B | 107,404 B |
| `glv-joint-packed-2` | 33,357 B | 84,302 B |
| `glv-joint-stack-2` | 27,983 B | 74,090 B |
| `glv-joint-scaled-2` | 26,639 B | 71,442 B |
| 手工 v0.17.0 | 22,435 B | 54,626 B |

缩放候选和 v0.17.0 的首窗和后续 63 窗共 18,379 B，逐字节相同。剩余的付款锁差距来自循环外。

| 区段 | v0.17.0 | 缩放候选 | 差值 |
| --- | ---: | ---: | ---: |
| 见证检查和挑战值 | 409 B | 1,593 B | +1,184 B |
| 联合点乘准备 | 2,763 B | 5,486 B | +2,723 B |
| 64 个窗口 | 18,379 B | 18,379 B | 0 B |
| 清理和 nonce 点比较 | 74 B | 371 B | +297 B |
| 所有者和原像绑定 | 810 B | 810 B | 0 B |

变基表构建和解包占其中 2,531 B。编译器候选先建齐次坐标字节表，再把点解包到栈上。手工版直接建立栈条目，并用自同态得到 `2Q` 和 `3Q` 两个行首。高阶 BIP340 封装还会重复解码坐标和拆分签名。两进两出 OTDA 交易里，两份锁和两份构造器各多 4,204 B，整笔交易多 16,816 B。

本节记录提交 7ea588c 的快照，以下命令在该提交上复现对应字节数。[固定源码](https://github.com/linzhm/4thGraph/tree/7ea588cbcfba39ce1099e0034d0b196768c1d1fd)

每个候选均复放固定验签向量、错误见证、12 种成对付款模式、两种普通输出退出及锁定时间篡改。选中的缩放候选也复放构造器矩阵的八个自动场景。[实测](../experiments/high-level/joint-lowerings.json) · [交易矩阵](../experiments/high-level/joint-lowerings-matrix.json)

```sh
PYTHONPATH=src:. bash tools/verify_node.sh --profile raised -- \
  "$SCRIPT_LAB_SDK_PYTHON" projects/p2pkh-schnorr/experiments/high-level/window_compare.py \
  --joint-lowerings --output workspace/schnorr-high-level/joint-lowerings.json
REGTEST_CHRONICLE_HEIGHT=5 PYTHONPATH=src:. bash tools/verify_node.sh --profile raised -- \
  "$SCRIPT_LAB_SDK_PYTHON" projects/p2pkh-schnorr/experiments/high-level/window_compare.py \
  --joint-lowerings --matrix-only --output workspace/schnorr-high-level/joint-lowerings-matrix.json
```

<a name="dataflow-iteration"></a>

## 数据流优化迭代

栈候选直接构建变基表。Forth 用混合点加构建各行，再用自同态把 `2P` 和 `3P` 映射成最后两行的行首。编译器调度类型化的栈布局并选择死值清理方式。批量验签版用原始编码计算挑战值，再通过基础库一起解码六个已验证宽度的字段。[编译器数据流](../../../docs/optimization-paths.zh-CN.md#数据流和返回边界) · [Forth 建表源码](../../../src/fourthgraph/compiler/secp256k1-joint-stack.fth)

| 阶段 | 付款锁 | 两进两出 OTDA ALL，使用模板构造器 |
| --- | ---: | ---: |
| 上轮缩放栈版 | 26,639 B | 71,442 B |
| 直接构建变基表 | 24,465 B | 62,746 B |
| 数据流改写和返回边界清理 | 23,870 B | 60,366 B |
| Forth 批量解码 | 23,484 B | 58,822 B |
| 手工 v0.17.0 | 22,435 B | 54,626 B |

本轮表格和实测文件对应提交 `70d7ec8`。从该提交的检出目录运行下列命令，可复现记录中的脚本字节。引入 #109 的共享栈调度后，数据流构建的付款锁为 23,869 B，重建付款为 60,362 B。批量解码构建的付款锁为 23,482 B，重建付款为 58,814 B。 [实测提交](https://github.com/linzhm/4thGraph/tree/70d7ec80ea4694c7d373f3a2368bb56303907dd1)

最短候选的 18,379 B 窗口循环与手工版逐字节相同。每锁剩余的 1,049 B 包括见证与挑战值处理 392 B、联合点乘准备 549 B、清栈与 nonce 点比较 108 B。每个候选复放 27 个向量与错误见证用例、12 种成对付款模式和两种普通输出退出。选中的候选还复放构造器矩阵的八个场景。[实测](../experiments/high-level/dataflow-measurements.json) · [交易矩阵](../experiments/high-level/dataflow-matrix.json)

```sh
PYTHONPATH=src:. bash tools/verify_node.sh --profile raised -- \
  "$SCRIPT_LAB_SDK_PYTHON" projects/p2pkh-schnorr/experiments/high-level/window_compare.py \
  --joint-lowerings --output workspace/schnorr-high-level/dataflow-measurements.json
REGTEST_CHRONICLE_HEIGHT=5 PYTHONPATH=src:. bash tools/verify_node.sh --profile raised -- \
  "$SCRIPT_LAB_SDK_PYTHON" projects/p2pkh-schnorr/experiments/high-level/window_compare.py \
  --joint-lowerings --matrix-only --output workspace/schnorr-high-level/dataflow-matrix.json
```

<a name="stack-and-model-boundaries"></a>

## 栈和坐标模型边界

栈候选让域模数从仿射映射一直保留到联合建表之后。仿射和齐次坐标转换比较预计算因子与在运行时从单个缩放因子求幂的写法。数据流调度器成组搬运相邻操作数，清理返回序列中夹杂的死值，并融合仅由 `verify` 消费的比较。共享解码库通过倍增和拼接生成重复掩码。[编译器和基础库](../../../docs/optimization-paths.zh-CN.md#数据流和返回边界)

| 构建 | 付款锁 | 两进两出 OTDA ALL，使用模板构造器 |
| --- | ---: | ---: |
| 上轮数据流与批量解码 | 23,484 B | 58,822 B |
| 栈与坐标模型边界优化 | 23,190 B | 57,646 B |
| 手工 v0.17.0 | 22,435 B | 54,626 B |

表格和实测文件对应提交 `e1ee42b`。从该提交的检出目录运行下列命令，可逐字节复现实测脚本。与 `main` 的 `c02df4a` 合并后，选中构建的付款锁为 23,188 B，两进两出的重建交易为 57,638 B。 [实测提交](https://github.com/linzhm/4thGraph/tree/e1ee42b455225934d580d172e562540286c42c56)

18,379 B 的窗口循环与冻结手工版逐字节相同。每锁剩余 755 B，分布在联合点乘准备 441 B、见证和挑战值处理 250 B、清栈和 nonce 点比较 64 B。验签器复放 BIP340 向量、错误见证、12 种成对付款模式和两种普通输出退出。选中候选也通过构造器矩阵的八个场景。[实测](../experiments/high-level/boundary-measurements.json) · [交易矩阵](../experiments/high-level/boundary-matrix.json)

```sh
PYTHONPATH=src:. bash tools/verify_node.sh --profile raised -- \
  "$SCRIPT_LAB_SDK_PYTHON" projects/p2pkh-schnorr/experiments/high-level/window_compare.py \
  --joint-lowerings --output workspace/schnorr-high-level/boundary-measurements.json
REGTEST_CHRONICLE_HEIGHT=5 PYTHONPATH=src:. bash tools/verify_node.sh --profile raised -- \
  "$SCRIPT_LAB_SDK_PYTHON" projects/p2pkh-schnorr/experiments/high-level/window_compare.py \
  --joint-lowerings --matrix-only --output workspace/schnorr-high-level/boundary-matrix.json
```
