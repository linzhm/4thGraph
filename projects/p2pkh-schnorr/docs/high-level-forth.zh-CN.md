# 高阶 Forth BIP340 自动优化实验

[English](high-level-forth.en.md) · [项目首页](../README.zh-CN.md) · [付款协议](spec.zh-CN.md)

本页记录从二进制 Forth 到调优版 64 窗口验签器的编译与交易复放。钱包默认使用已发布的 v0.17.0 模板。[对照与产物哈希](../experiments/high-level/witness-ordinate-check.json) · [钱包接入](sdk.zh-CN.md#quickstart)

[OTDA 构造器](#otda-constructor) · [复放命令](#replay) · [优化历史](#optimization-history)

<a name="otda-constructor"></a>

## OTDA 构造器

下表均使用 OTDA ALL（`0x61`），花费两个 Schnorr 输出并创建两个 Schnorr 输出。每个输入用识别到的模板片段和按顺序排列的输出金额、所有者哈希重建完整签名预映像。重建后的栈值与原样压栈一致。构造器会改变解锁脚本的序列化字节，因此也会改变交易 ID。[构造器实现](../../../src/fourthgraph/bsv/otda_reconstruction.py)

| 构建 | 付款锁 | 构造后整笔交易 | 每个输入的解锁脚本 |
| --- | ---: | ---: | ---: |
| 已发布 v0.17.0 | 22,435 B | 54,626 B | 4,819 B |
| 调优 Forth，合并偶性检查 | 22,434 B | 54,622 B | 4,818 B |

发布模板另有默认 regtest 策略下的入金与出块记录。调优版在 raised regtest 策略下用实验构造器和显式上一输出复放。BSV Node 1.2.3 和 chain-gang 对该构建核对了 8 个构造器场景、46 个扩展场景及 2 个 OTDA SINGLE 配套路径场景。[发布版入网复现](../README.zh-CN.md#交易实测) · [调优版复放摘要](../experiments/high-level/witness-ordinate-check.json)

<a name="不同交易类型的构造器选择"></a>

### 不同交易类型的构造器选择

选择器比较原样压栈、整段重复展开、按模板字典以及共享前后缀的字典。冻结的矩阵有 54 个场景、87 份不同的签名交易，覆盖归集、分发、找零、Schnorr 与原生输入输出混用、新旧模板混用、交易版本 1 和 2 中全部 12 种有同索引输出的 sighash、同笔交易不同模式、激活前入金和 252/253 个输出的 CompactSize 边界。该矩阵用历史二进制 Forth 构建作为自动编译输入。[选择器](../../../src/fourthgraph/compiler/preimage.py) · [冻结矩阵](../experiments/high-level/constructor-matrix.json)

| 历史 OTDA ALL 夹具 | 原样交易 | 按模板构造 | 选用的编码 |
| --- | ---: | ---: | ---: |
| 三种发布模板加一个原生输出 | 226,887 B | 106,729 B | 99,237 B |
| 二进制 Forth 两进两出周转 | 1,312,926 B | 446,920 B | 446,920 B |
| 二进制 Forth、发布模板与原生输出混用 | 724,224 B | 259,686 B | 258,122 B |

<a name="环境与输入"></a>
<a name="构建与复放"></a>
<a name="replay"></a>

## 复放

在仓库根目录使用 Python 3.12 和项目固定的 chain-gang 0.13.2（`74676b9`）。脚本会启动隔离的 BSV Node 1.2.3 regtest。调优版记录使用源码提交 `8f4c5e3` 和 4thGraph 0.2.7。从该提交复现记录中的字节数和哈希。[项目环境](../README.zh-CN.md#复现验收) · [调优版实测](../experiments/high-level/witness-ordinate-check.json)

```sh
PYTHONPATH=src:. bash tools/verify_node.sh --profile raised --   "$SCRIPT_LAB_SDK_PYTHON" projects/p2pkh-schnorr/experiments/high-level/window_compare.py   --joint-lowerings --forth-tuning --output workspace/schnorr-high-level/tuned-measurements.json

REGTEST_CHRONICLE_HEIGHT=5 PYTHONPATH=src:. bash tools/verify_node.sh --profile raised --   "$SCRIPT_LAB_SDK_PYTHON" projects/p2pkh-schnorr/experiments/high-level/window_compare.py   --joint-lowerings --forth-tuning --matrix-only --output workspace/schnorr-high-level/tuned-matrix.json
```

第一条命令编译各候选，并复放独立验签、完整付款和锁定时间篡改，以及两进两出夹具的两种见证编码。第二条命令复放 8 个自动模板构造器场景，检查输出和输入序号的改动。扩展交易的结果另见调优版复放摘要。[对照脚本](../experiments/high-level/window_compare.py) · [交易夹具](../experiments/high-level/constructor_matrix.py)

从 `38616d7` 复现早期二进制编译对照，运行 `compare.py --output workspace/schnorr-high-level --samples 12`。历史构造器对照用 `7bc0538` 的 `compare_otda.py --output workspace/schnorr-high-level/otda-measurements.json`，冻结的 54 场景矩阵用 `9dfc719` 的 `constructor_matrix.py --output workspace/schnorr-high-level/constructor-matrix.json`。矩阵复放同样设置 `REGTEST_CHRONICLE_HEIGHT=5`。[二进制对照脚本](../experiments/high-level/compare.py) · [构造器脚本](../experiments/high-level/compare_otda.py) · [历史实测](../experiments/high-level/otda-measurements.json)

<a name="测量与证据"></a>
<a name="optimization-history"></a>

## 优化历史

早期二进制 Forth 用 256 轮联合点乘计算 BIP340 等式，倍点和点加共用完备齐次公式。自动编译将付款锁从 433,567 B 降到 218,701 B。使用构造器的两进两出 OTDA ALL 从 880,172 B 降到 446,920 B。两个二进制构建和 v0.17.0 的原生 OTDA 退出都使用 348 B 的原样交易。[验签源码](../experiments/high-level/verifier.fth) · [二进制大小与耗时](../experiments/high-level/measurements.json) · [历史构造器实测](../experiments/high-level/otda-measurements.json)

以下各阶段均用同一两进两出 OTDA ALL 构造器夹具。链接给出各构建及对照的原始记录。

<a name="64-window-lowering"></a>
<a name="曲线专用的-64-窗口-lowering"></a>

### 64 窗口 lowering

源码拆分生成点标量和公钥点标量，得到四个 128 位分量。联合点乘词独立编译后链接到验签器。付款锁 43,999 B，整笔交易 107,404 B。 [实测](../experiments/high-level/window-measurements.json)

<a name="joint-lowering-candidates"></a>

### 联合点乘候选

在参考实现、压缩字节表、栈表和缩放栈表四个候选中，缩放栈表生成的锁最小。付款锁 26,639 B，整笔交易 71,442 B。 [实测](../experiments/high-level/joint-lowerings.json)

<a name="dataflow-iteration"></a>

### 数据流优化迭代

直接构表、清理死值和批量解码六个定宽字段，减少窗口循环外围的开销。付款锁 23,484 B，整笔交易 58,822 B。 [实测](../experiments/high-level/dataflow-measurements.json)

<a name="stack-and-model-boundaries"></a>

### 栈和坐标模型边界

调度器成组搬运操作数，并在曲线调用边界复用保留的值。缩放 lowering 比较满足界限的不同形式。付款锁 23,190 B，整笔交易 57,646 B。 [实测](../experiments/high-level/boundary-measurements.json)

<a name="point-comparison-models"></a>

### 点比较的坐标模型

在三种末端比较方法中，把两个仿射点都映到工作坐标模型的锁最小。付款锁 23,161 B，整笔交易 57,530 B。 [实测](../experiments/high-level/model-output-measurements.json)

<a name="source-tuning-for-the-64-window-verifier"></a>

### 64 窗口验签器的 Forth 调优

源码通过显式布局，让见证检查、曲线方程检查和坐标映射共用一个域素数。付款锁 22,992 B，整笔交易 56,854 B。 [实测](../experiments/high-level/forth-tuning-measurements.json)

<a name="sharing-the-endomorphism-at-two-row-starts"></a>

### 两个建表行首共用自同态

一条 Forth 公式计算 2Q 和 3Q 两个射影行首。付款锁 22,940 B，整笔交易 56,646 B。 [实测](../experiments/high-level/table-tuning-measurements.json)

<a name="sharing-beta-across-all-variable-table-row-starts"></a>

### 变基表的三个行首共用 β

映射同时返回 Q，三个行首共用同一个自同态常数。付款锁 22,902 B，整笔交易 56,494 B。 [实测](../experiments/high-level/window-beta-measurements.json)

<a name="packing-the-fixed-base-scalar-directly"></a>

### 固定基标量直接打包

固定基标量编码一次，再按字节切分为两个分量。付款锁 22,855 B，整笔交易 56,306 B。 [实测](../experiments/high-level/fixed-scalar-measurements.json)

<a name="sharing-the-group-order-with-the-glv-split"></a>

### 挑战约减与 GLV 分解共用曲线阶

Forth 验签器把挑战约减使用的群阶传给 GLV 分解。付款锁 22,832 B，整笔交易 56,214 B。 [实测](../experiments/high-level/shared-order-measurements.json)

<a name="scheduling-named-layouts-with-dataflow"></a>

### 让命名布局参与数据流调度

通用调度器沿用布局声明中的值编号，跨布局和多返回值调用安排栈访问。三个变基表行主体各从 348 B 降到 264 B。付款锁 22,465 B，整笔交易 54,746 B。 [实测](../experiments/high-level/layout-dataflow-measurements.json)

<a name="variable-table-row-starts"></a>

### 复用变基表行起点的坐标

secp256k1 库只返回变换后的坐标，曲线 lowering 复用表中已有的仿射 Y 和三个 Z。付款锁 22,436 B，整笔交易 54,630 B。 [实测](../experiments/high-level/row-start-layout.json)

<a name="paired-witness-ordinate-check"></a>

### 合并见证纵坐标的偶性检查

Schnorr Forth 将两个无符号纵坐标分别对 2 取余，再检查余数和。独立奇偶用例覆盖两者均为奇数及各自为奇数。[当前交易大小](#otda-constructor) · [实测](../experiments/high-level/witness-ordinate-check.json)
