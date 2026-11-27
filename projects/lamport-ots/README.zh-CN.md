<!-- Generated from manifest.yaml with Copier. -->

# Lamport OTS（SHA-256） v0.1.0

[English](README.md) · [4thGraph](../../README.zh-CN.md) · [项目目录](../README.zh-CN.md) · [版本](versions/index.json)

## 开发入口

**[钱包 SDK 快速上手](docs/sdk.zh-CN.md#quickstart)** · [统一钱包 SDK](../../sdk/README.zh-CN.md#quickstart)

Lamport OTS 用独立秘密值的 SHA-256 承诺授权 BSV 交易输入。固定重量研究候选将承诺锁的花费证明从 16,384 字节降至 11,264 字节，原始签名从 8,192 字节降至 4,096 字节。[签名设计](docs/subset.zh-CN.md) · [协议规范（英文）](docs/spec.md)

[协议](docs/developer.zh-CN.md) · [算法与执行](#算法与执行) · [复现方法](#复现方法) · [完整交易与栈测量](#完整交易与栈测量) · [实测数据](versions/v0.1.0/measurements.json)

| 入口 | 用途 |
| --- | --- |
| `locking_script` | 用所选的密钥表示生成全公钥或公钥承诺付款锁。 |
| `subset_locking_script` | 用对应的有序公钥创建固定重量候选锁。 |
| `sign_spend` | 将所选输入绑定到交易并调用外部一次性签名器。 |

## 算法与执行

**v0.2.0 候选版**可在 SDK 中显式选择，版本目录固定了 6,525 字节的锁模板和 871 字节的 OTDA 重建程序。[v0.2.0 清单](versions/v0.2.0/manifest.json) · [测量数据](versions/v0.2.0/measurements.json)

全公钥锁嵌入有序的 Lamport 公钥。公钥承诺锁保存其 SHA-256 摘要，并在花费时检查见证提供的完整公钥。交易绑定校验实际输入。[协议规范（英文）](docs/spec.md)

固定重量候选将每个摘要字节映射到 11 个槽位中的 4 个。改签不同摘要至少需要一个尚未公开的槽位。候选使用独立的密钥格式，每个输出使用独立生成的新密钥。[签名格式与安全前提](docs/subset.zh-CN.md)

## 复现方法

从仓库根目录使用项目固定的 Python 环境。

```sh
python3.12 -m venv projects/lamport-ots/workspace/venv
. projects/lamport-ots/workspace/venv/bin/activate
python -m pip install -r projects/lamport-ots/reference/requirements.txt
```

```sh
PYTHONPATH=src:. python projects/lamport-ots/reference/measure.py --benchmark
bash projects/lamport-ots/reference/verify.sh
```

在仓库根目录使用独立的 Python 3.12 环境。向量密钥均为公开测试数据。

```sh
python -m unittest discover -s projects/lamport-ots/reference -p test_lamport.py -v
python -m unittest discover -s projects/lamport-ots/reference -p test_acceptance.py -v
python projects/lamport-ots/reference/measure.py --committed-costs
```

macOS 用 Apple Container 运行 `bash projects/lamport-ots/reference/verify_apple.sh`，Linux 运行 `bash projects/lamport-ots/reference/verify.sh` 进行 BSV Node 复放。[验证记录（英文）](docs/validation.md) · [原始 ALL 向量](versions/v0.1.0/vector.json) · [通用签名模式向量](versions/v0.1.0/universal-vectors.json) · [v0.1.0 测量清单](versions/v0.1.0/measurements.json)

在 BSV Node 默认 regtest 交易策略下，两种 Forth 模板及启用重建的紧凑模板均完成入金、一次周转和退出。两种 ALL 模式的各阶段均已入池并入块。[逐阶段结果与复现命令（英文）](docs/validation.md#funded-regtest)

固定重量候选通过两种 ALL 模式的直接退出和一次周转复放。在默认交易策略下，10 笔交易全部入池并入块。[双引擎及入池入块结果（英文）](docs/validation.md#fixed-weight-candidate-replay)

## 开发和钱包接入

### 构建付款

每个新输出使用独立密钥，找零也一样。钱包保存完整有序公钥，外部签名器在释放首次签名前持久记录密钥已消耗。签名前核对入金 outpoint、金额、锁定脚本及所需确认数。重播时使用原已签交易，签名状态无法确认的密钥按已消耗处理。[钱包 SDK 快速上手](docs/sdk.zh-CN.md#quickstart) · [开发指南](docs/developer.zh-CN.md) · [安全与恢复（英文）](docs/security.md)

## 完整交易与栈测量

<a name="输入输出取舍"></a>

<a name="输入输出边际与生命周期"></a>

### 选择付款模板

下表采用普通 BIP143 ALL（`0x41`）和 Chronicle OTDA ALL（`0x61`）。两进两出交易花费两个同模板输出，再创建两个同模板的新输出。单位为字节。

| 模板 | 输出锁 | 每个 BIP143 ALL 解锁 | BIP143 ALL 两进两出 | OTDA ALL 两进两出 |
| --- | ---: | ---: | ---: | ---: |
| `full-key`（默认） | 22,780 | 8,357 | 62,392 | 153,436 |
| `committed-key` | 7,746 | 16,549 | 48,708 | 79,616 |
| `committed-key-forth`（实验） | 7,042 | 16,549 | 47,300 | 75,392 |
| `committed-key-forth-compact`（实验） | 6,830 | 16,549 | 46,876 | 74,120 |
| `committed-key-forth-v0.2.0`（候选） | 6,525 | 16,549 | 46,266 | 72,290 |
| `committed-key-forth-subset`（研究） | 8,003 | 11,429 | 38,982 | 70,918 |

全公钥格式花费到普通输出时，每个输入的成本较低。经典承诺格式只在锁中保存有序公钥的 SHA-256，每个输入多携带 8,192 字节以重建公钥。OTDA ALL 还会在每个输入的签名原文中序列化本笔交易的输出，缩短输出锁同时也缩短签名原文。[边际成本与生命周期（英文）](docs/optimization.md#transaction-and-lifecycle-costs)

Chronicle v2 交易可显式启用 OTDA 原文重建。当两个输出均使用紧凑模板时，OTDA ALL 两进两出从 **74,120 降至 48,830 字节**。[重建机制与钱包选项（英文）](docs/optimization.md#otda-unlocking-reconstruction)

两个输出使用 v0.2.0 并启用重建时，同一交易形状为 **48,106 字节**。[v0.2.0 设计（英文）](docs/optimization.md#version-020-candidate)

固定重量候选开启重建后，OTDA ALL 两进两出为 **41,920 字节**。在任一 ALL 模式下，两输入直接退出到原生 P2PKH 均比 v0.2.0 少 **10,240 字节**。[固定重量候选尺寸（英文）](docs/optimization.md#fixed-weight-candidate)

参考实现支持 BIP143 与 Chronicle OTDA 的 ALL、NONE、SINGLE 及 ANYONECANPAY 共十二种组合，默认使用 BIP143 ALL。无配对 SINGLE 不承诺任何输出，参考 API 要求调用方显式批准。旧版两项见证的 BIP143 ALL 付款锁仍可花费。分离摘要验证器仅供测试，同一证明可以被复制到另一笔交易。[线格式与脚本规范（英文）](docs/spec.md) · [验收范围（英文）](docs/acceptance.md)
