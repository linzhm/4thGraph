<!-- Generated from manifest.yaml with Copier. -->

# P2PKH-R1 v0.6.0

[English](README.md) · [4thGraph](../../README.zh-CN.md) · [项目目录](../README.zh-CN.md) · [版本](versions/index.json)

## 开发入口

**[钱包 SDK 快速上手](docs/sdk.zh-CN.md#quickstart)** · [统一钱包 SDK](../../sdk/README.zh-CN.md#quickstart)

P2PKH-R1 让 BSV 钱包接入已有的 P‑256 签名器。输出锁定到收款公钥的 HASH160，花费时提供未压缩公钥和 64 字节的 ECDSA 签名 `r || s`。

[协议](docs/spec.zh-CN.md) · [算法与执行](#算法与执行) · [复现方法](#复现方法) · [完整交易与栈测量](#完整交易与栈测量) · [实测数据](versions/v0.6.0/measurements.json)

| 入口 | 用途 |
| --- | --- |
| `locking_script_from_public_key` | 用未压缩的 P-256 公钥构造选定的钱包模板。 |
| `sign_payment` | 用外部 P-256 摘要签名器为付款授权。 |

## 算法与执行

[协议规范](docs/spec.zh-CN.md) · [安全分析](docs/developer.zh-CN.md#security) · [验收记录](reference/acceptance.md)

付款锁检查公开的公钥与所有者 HASH160 是否匹配，在 Script 中验证 P-256 签名，并将已签摘要绑定到当前输入。[线格式规范](docs/spec.zh-CN.md)

## 复现方法

在编译器实验环境中从仓库根目录运行版本命令。[依赖与复放配置](forth/README.md)

```sh
PYTHONPATH=src:.:projects/p2pkh-r1/reference python projects/p2pkh-r1/forth/msm_experiment.py build --candidate split-5x4-affine-g
PYTHONPATH=src:.:projects/p2pkh-r1/reference bash tools/verify_node.sh --profile raised -- python projects/p2pkh-r1/forth/msm_experiment.py compare --workflow explicit --matrix --candidate v0.5.0 --candidate v0.6.0 --budget 2 --full-budget 2
```

选定的编译器版本和钱包默认模板分别归档。完整复放流程见编译器指南，付款矩阵见验收记录。[编译器实验](forth/README.md) · [付款验收](reference/acceptance.md)

## 开发和钱包接入

### 钱包接入

参考钱包用 **v0.2.0** 创建新输出，也能花费已有的 v0.1.0 输出。统一 SDK 支持 TypeScript、Rust、Go 和 Python。接入已有 P‑256 签名器时，核对设备的摘要接口和签名编码，并跨签名进程持久保存随机数重复检测记录。 [SDK 指南](docs/sdk.zh-CN.md) · [参考钱包](reference/README.md) · [钱包模板](versions/v0.2.0/layout.json)

R1 在入金时创建完整付款锁，收款人可用一次花费付款。Deferred R1 用较小的入金锁，并在独立的交易中启用。 [Deferred 流程](../p2pkh-r1-deferred/README.zh-CN.md)

## 完整交易与栈测量

<a name="version-history"></a>

<a name="forth-探索版"></a>

### 实测结果

#### v0.5.0 → v0.6.0

**v0.6.0** 将 `split-5x4-affine-g` 固定为最新的编译器模板。每个完整锁缩短 **357 B**，BIP143 ALL 付款缩短 **714 B**。OTDA 重建程序增加 148 B，两种 OTDA 付款各缩短 **418 B**。付款均为两进两出。 [冻结产物与哈希](versions/v0.6.0/layout.json) · [构建与复放](forth/README.md)

| 版本 | 编译器构造 | 完整锁 | BIP143 ALL 付款 | OTDA ALL 付款 | OTDA SINGLE 付款 |
| --- | --- | ---: | ---: | ---: | ---: |
| v0.5.0 | `split-5x4` | 41,721 B | 84,212 B | 95,282 B | 95,211 B |
| **v0.6.0** | `split-5x4-affine-g` | **41,364 B** | **83,498 B** | **94,864 B** | **94,793 B** |

两个版本编译同一份调用 `P256.mul2(u,G,v,Q)` 的 Forth，分别给 `G`、`Q` 使用 5 位和 4 位窗口。v0.6.0 的编译器证明固定生成元表的非零项满足 `Z=1`，据此特化 51 处点加，并单独处理零下标。两个版本在上述三种付款模式中都通过了 BSV Node 和独立 chain-gang 的带资金复放，也通过了 R1 验收矩阵。 [高阶源码](forth/msm.fth) · [版本实测数据](versions/v0.6.0/comparison.json) · [验收矩阵](reference/acceptance.md)

<details>
<summary>展开此前的版本迭代</summary>

每行是该轮验收后选定的一个模板。付款均为两进两出。

| 上一轮基线 | 本轮选定模板 | 主要改进 | 完整锁 | BIP143 ALL | OTDA ALL |
| --- | --- | --- | ---: | ---: | ---: |
| — | v0.1.0 | 初版固定锁，OTDA 直接携带原像 | 59,582 B | 119,934 B | 358,194 B |
| v0.1.0 | v0.2.0 | 重排 P‑256 点运算，OTDA 共用曲线内核重建原像 | 46,302 B | 93,374 B | 101,250 B |
| v0.2.0 | Forth v0.3.0 | 从 Forth 生成整锁，缩短 263 处倍点 | 45,776 B | 92,322 B | 100,192 B |
| Forth v0.3.0 | Forth v0.4.0 | 用带范围的公式表达点运算，编译器做等价改写与栈调度 | 42,536 B | 85,842 B | 93,664 B |
| Forth v0.4.0 | v0.5.0（`split-5x4`） | 把双标量乘法留给编译器，用 5 位固定表和 4 位公钥表减少循环点加 | 41,721 B | 84,212 B | 95,282 B |

主线以锁和 BIP143 付款字节数选版。以 OTDA 付款为首要目标时，沿用窗口迭代选出的 `joint-2`，两进两出 OTDA ALL 为 91,692 B。 [窗口复放数据](versions/v0.6.0/comparison.json)

v0.4.0 的 Forth 用命名值写公式，例如先算 `xx = x1*x2` 和 `yy = y1*y2`，再写交叉项。代数上可展开为两个交叉乘积：

```diff
- x1 y1 int+ x2 y2 int+ int* xx int- yy int- let xy
+ x1 y2 int* x2 y1 int* int+ let xy
```

对三个交叉项都这样展开，关闭优化时点加从 392 B 降到 345 B。把这一等价改写加入编译器后，保留原式并开启优化，配合栈调度就能生成 123 B 的点加和 42,536 B 的完整锁。同一份源码关闭优化时，完整锁为 117,775 B。下一轮继续用高阶双标量乘法表达算法，把窗口和固定表特化交给编译器。 [公式源码](forth/r1.fth) · [历史基准](forth/history.md)

</details>
