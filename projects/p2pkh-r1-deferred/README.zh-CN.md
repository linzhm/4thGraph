<!-- Generated from manifest.yaml with Copier. -->

# P2PKH-R1-Deferred v0.3.0

[English](README.md) · [4thGraph](../../README.zh-CN.md) · [项目目录](../README.zh-CN.md) · [版本](versions/index.json)

## 开发入口

**[钱包 SDK 快速上手](docs/sdk.zh-CN.md#quickstart)** · [统一钱包 SDK](../../sdk/README.zh-CN.md#quickstart)

生成入金短锁，在同一索引安排它承诺的 R1 目标输出，再调用 `activate`。启用后的输出按普通 R1 流程花费。

[协议](docs/spec.zh-CN.md) · [算法与执行](#算法与执行) · [复现方法](#复现方法) · [完整交易与栈测量](#完整交易与栈测量)

| 入口 | 用途 |
| --- | --- |
| `activate_input` | 为所选已入金输入及承诺的 R1 目标构造启用见证。 |

## 使用场景与取舍

如果需要批量创建体积较小的入金输出，而且可以在后续出款前集中启用，可以评估 Deferred。每个短锁承诺目标 R1 的所有者、模板和全额金额。任何持有所需数据并能提供手续费的参与方都可构造启用交易。之后花费普通 R1 输出时，仍需所有者签名。

需预算额外一笔交易及手续费来源。每个启用输入与所承诺的 R1 输出同索引时，可以批量启用。确认前，钱包继续跟踪短锁 UTXO。暂时找不到手续费赞助输入时，资金留在短锁里。若用户需要到账即花费，或主要目标是降低总手续费，应和普通 R1 对比从入金到退出的完整成本。[启用成本](#实测交易成本)

## 算法与执行

[协议规范](docs/spec.zh-CN.md) · [安全分析](docs/developer.zh-CN.md#security) · [复现与验证](#开发与复现) · [交易成本](#实测交易成本)

Deferred 将生成完整 R1 锁定脚本的成本推迟到启用阶段。v0.3.0 入金短锁为 1,085 字节，承诺等额的 46,302 字节 P2PKH-R1 v0.2.0 目标输出。已有短锁按原承诺启用。[Deferred 模板](versions/v0.3.0/template.hex) · [R1 目标模板](../p2pkh-r1/versions/v0.2.0/template.hex)

### 启用与后续付款

1. 使用 `funding_output` 或 `funding_output_from_owner_hash` 生成入金输出。接收时核对短锁、金额和两项目标承诺。统一客户端通过 `template` 返回短锁版本，通过 `targetTemplate` 返回承诺的 R1 版本。
2. 将启用输入和目标输出放在同一索引，再调用 `activate_input`。手续费赞助方需要签自己的输入。BIP143 SINGLE 直接分支的解锁为 160 字节。双检查分支另带所选模式的摘要，解锁为 197 字节。全部 12 种启用签名类型都要求同索引输出存在。
3. 启用完成后，使用普通 R1 钱包和签名器花费该输出。符合条件的后续付款可以使用 Chronicle OTDA 重建。

启用解锁已经通过 BIP143 SINGLE 携带目标输出的承诺，双检查分支另带一个摘要。完整 R1 目标锁占用启用交易的实际输出。

## 复现方法

在安装了项目依赖的 Python 环境中，从仓库根目录运行版本命令。

```sh
python -m pip install -r projects/p2pkh-r1-deferred/reference/requirements.txt
```

```sh
PYTHONPATH=src:.:projects/p2pkh-r1/reference python projects/p2pkh-r1-deferred/reference/generate_vectors.py
bash projects/p2pkh-r1-deferred/reference/verify.sh
```

### 开发与复现

详见[协议规范](docs/spec.zh-CN.md)、[钱包 SDK](docs/sdk.zh-CN.md)、[模板布局](versions/v0.3.0/layout.json)、[启用向量](versions/v0.3.0/activation-single.json)、[十二种模式向量](versions/v0.3.0/sighash-modes.json)和[验收矩阵](reference/acceptance.md)。

## 脚本尺寸

### 4thGraph Forth 对照

高阶 Forth 源码覆盖完整启用检查，包括 BIP143 SINGLE 同索引输出承诺、可选的 BIP143 或 OTDA 摘要、固定密钥签名构造和两处原生签名检查。三种构建使用同一份有栈类型声明的源码，编译器为 `3133da7` 基线上的 4thGraph 0.2.7。[Forth 源码](reference/deferred-activation.fth) · [编译报告](versions/v0.3.0/forth-results.json)

| 构建 | 入金短锁 | 入金交易 | 入金及 BIP143 ALL 启用 | 首个启用输入主栈 / 备用栈峰值项数 |
| --- | ---: | ---: | ---: | ---: |
| 已发布 v0.2.0 汇编 | 1,435 B | 2,953 B | 96,116 B | 7 / 34 |
| Forth `baseline` | 1,185 B | 2,453 B | 95,616 B | 10 / 1 |
| Forth `safe` | 1,087 B | 2,257 B | 95,420 B | 10 / 1 |
| v0.3.0 Forth `stack` | **1,085 B** | **2,253 B** | **95,416 B** | 10 / 1 |

样例入金含两个短锁和一个赞助输出，启用后得到相同的两个 46,302 字节 R1 目标锁。`stack` 每个短锁节省 350 字节，两笔交易合计节省 700 字节。四种构建的启用交易均为 BIP143 SINGLE 直接路径 93,089 字节、BIP143 ALL 或 OTDA ALL 路径 93,163 字节。开发求值器测得 BIP143 ALL 路径的两栈合计载荷峰值分别为汇编 359 字节、Forth 360 字节。[样例和数据](versions/v0.3.0/forth-results.json)

Forth 逐层分半并拼接来反转 32 字节数据，缩小了基础构建。`safe` 利用字节长度的非负范围，省去两处 DER 长度减法的 64 位回绕逻辑。`stack` 再通过栈调度在每处各省 1 字节。BSV Node 和固定版本的 chain-gang 均通过了适用的启用验收矩阵。[验证范围](reference/acceptance.md)

Python 入金函数、CLI 和钱包 SDK 默认生成 v0.3.0 短锁。需要生成旧版公钥哈希短锁时，在 CLI 中传入 `--template v0.2.0`，或在 SDK 中指定 `template: "v0.2.0"`。CLI 的 `--optimize` 可直接按指定模式编译 Forth 源码。

在仓库根目录运行以下命令即可生成详细报告及四份锁定脚本。

```sh
PYTHONPATH=src:. python projects/p2pkh-r1-deferred/reference/compare_forth.py \
  --output-dir projects/p2pkh-r1-deferred/workspace/forth
```

## 完整交易与栈测量

### 实测交易成本

v0.3.0 基准用两个短锁输入和一个手续费赞助输入，产生两个 R1 v0.2.0 输出。新增一对启用时，同时增加输入与同索引目标。只增输出时，由赞助输入额外支付。表中单位均为序列化字节。

| 启用模式 | 3 进 2 出 | 新增一对启用 | 新增输出 | 入金、启用和退出 | 含一次周转 |
| --- | ---: | ---: | ---: | ---: | ---: |
| BIP143 ALL | 93,260 | 46,550 | 46,312 | 96,425 | 189,800 |
| OTDA ALL | 93,260 | 46,551 | 46,313 | 96,440 | 197,689 |

两个启用输入的解锁各为 197 字节。开发求值器测得首个 BIP143 ALL 启用输入的主栈峰值为 10 项，备用栈峰值为 1 项，两栈载荷峰值为 360 字节。BIP143 ALL 与 OTDA ALL 的实际入金、启用和退出均在采用 raised 策略配置的本地 regtest 入块。[基准与复放命令](../../docs/benchmark.zh-CN.md)
