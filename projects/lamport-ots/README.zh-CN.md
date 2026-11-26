# Lamport OTS（SHA-256）

[English](README.md) · [4thGraph](../../README.zh-CN.md) · [项目目录](../README.zh-CN.md) · [版本](versions/index.json)

Lamport OTS 将 8,192 字节的一次性签名绑定到 BSV 当前交易输入。v0.1.0 开发基线包含全公钥和公钥承诺付款锁。Forth 重建先把公钥承诺锁从 7,746 字节降至 7,042 字节，再通过压缩交易绑定降至 6,830 字节。[协议规范（英文）](docs/spec.md) · [Forth 设计与测量（英文）](docs/optimization.md)

<a name="输入输出取舍"></a>
<a name="完整交易与栈测量"></a>
<a name="输入输出边际与生命周期"></a>

## 选择付款模板

下表采用普通 BIP143 ALL（`0x41`）和 Chronicle OTDA ALL（`0x61`）。两进两出交易花费两个同模板输出，再创建两个同模板的新输出。单位为字节。

| 模板 | 输出锁 | 每个 BIP143 ALL 解锁 | BIP143 ALL 两进两出 | OTDA ALL 两进两出 |
| --- | ---: | ---: | ---: | ---: |
| `full-key`（默认） | 22,780 | 8,357 | 62,392 | 153,436 |
| `committed-key` | 7,746 | 16,549 | 48,708 | 79,616 |
| `committed-key-forth`（实验） | 7,042 | 16,549 | 47,300 | 75,392 |
| `committed-key-forth-compact`（实验） | 6,830 | 16,549 | 46,876 | 74,120 |

全公钥格式花费到普通输出时，每个输入的成本较低。承诺格式只在锁中保存有序公钥的 SHA-256，每个输入多携带 8,192 字节以重建公钥。OTDA ALL 还会在每个输入的签名原文中序列化本笔交易的输出，缩短输出锁同时也缩短签名原文。[边际成本与生命周期（英文）](docs/optimization.md#transaction-and-lifecycle-costs)

Chronicle v2 交易可显式启用 OTDA 原文重建。当两个输出均使用紧凑模板时，OTDA ALL 两进两出从 **74,120 降至 48,830 字节**。[重建机制与钱包选项（英文）](docs/optimization.md#otda-unlocking-reconstruction)

参考实现支持 BIP143 与 Chronicle OTDA 的 ALL、NONE、SINGLE 及 ANYONECANPAY 共十二种组合，默认使用 BIP143 ALL。无配对 SINGLE 不承诺任何输出，参考 API 要求调用方显式批准。旧版两项见证的 BIP143 ALL 付款锁仍可花费。分离摘要验证器仅供测试，同一证明可以被复制到另一笔交易。[线格式与脚本规范（英文）](docs/spec.md) · [验收范围（英文）](docs/acceptance.md)

## 构建付款

每个新输出使用独立密钥，找零也一样。钱包保存完整有序公钥，外部签名器在释放首次签名前持久记录密钥已消耗。签名前核对入金 outpoint、金额、锁定脚本及所需确认数。重播时使用原已签交易，签名状态无法确认的密钥按已消耗处理。[钱包 SDK 快速上手](docs/sdk.zh-CN.md#quickstart) · [开发指南](docs/developer.zh-CN.md) · [安全与恢复（英文）](docs/security.md)

## 复现方法

在仓库根目录使用独立的 Python 3.12 环境。向量密钥均为公开测试数据。

```sh
python3.12 -m venv projects/lamport-ots/workspace/venv
. projects/lamport-ots/workspace/venv/bin/activate
python -m pip install -r projects/lamport-ots/reference/requirements.txt
python -m unittest discover -s projects/lamport-ots/reference -p test_lamport.py -v
python -m unittest discover -s projects/lamport-ots/reference -p test_acceptance.py -v
python projects/lamport-ots/reference/measure.py --committed-costs
```

macOS 用 Apple Container 运行 `bash projects/lamport-ots/reference/verify_apple.sh`，Linux 运行 `bash projects/lamport-ots/reference/verify.sh` 进行 BSV Node 复放。[验证记录（英文）](docs/validation.md) · [原始 ALL 向量](versions/v0.1.0/vector.json) · [通用签名模式向量](versions/v0.1.0/universal-vectors.json) · [v0.1.0 测量清单](versions/v0.1.0/measurements.json)

在 BSV Node 默认 regtest 交易策略下，两种 Forth 模板及启用重建的紧凑模板均完成入金、一次周转和退出。两种 ALL 模式的各阶段均已入池并入块。[逐阶段结果与复现命令（英文）](docs/validation.md#funded-regtest)
