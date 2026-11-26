# Lamport OTS（SHA-256）

[English](README.md) · [4thGraph](../../README.zh-CN.md) · [项目目录](../README.zh-CN.md)

## 开发入口

**[钱包 SDK 快速上手](docs/sdk.zh-CN.md#quickstart)** · [统一钱包 SDK](../../sdk/README.zh-CN.md#quickstart)

选择完整公钥锁或公钥承诺锁，接入能在返回签名前持久化一次性密钥消费记录的签名器。

[协议规范](docs/developer.zh-CN.md#protocol) · [安全分析](docs/developer.zh-CN.md#security) · [复现与验证](#复现方法) · [交易成本](#完整交易与栈测量)

Lamport OTS 是 v0.1 开发基线，使用 SHA-256 在 Bitcoin Script 中验证一次性签名。私钥和公钥各为 16,384 字节，原始签名为 8,192 字节。每组密钥只用于一个 UTXO 并只签一次。完整的付款构造还将签名绑定到当前交易输入。

## 使用场景与取舍

Lamport 适合研究 SHA‑256 一次性签名如何影响入金和花费成本。完整公钥模板把按序排列的公钥放在锁里。承诺模板每个输出节省 15,034 字节，但普通 ForkID 解锁增加 8,192 字节。因此，多输出分发和多输入归集可能适合不同的模板。[输入输出取舍](#输入输出取舍)

每个新输出都使用新 Lamport 密钥，找零也一样。钱包保留按序排列的公钥及持久化的密钥消耗记录。广播延迟或失败时，可保留原签名交易用于重播。如果恢复后无法确认密钥的签名状态，按已消耗处理。[钱包接入](docs/sdk.zh-CN.md)

## 模板、使用与规范

- `locking_script(public_key)` 生成 22,780 字节的全公钥付款锁。ForkID 普通解锁为 8,357 字节。默认付款使用 `0x41`，参考实现同时支持 ForkID 与 Chronicle OTDA 的 ALL、NONE、SINGLE 及 ANYONECANPAY 组合。
- `committed_locking_script(public_key)` 生成 7,746 字节的公钥承诺候选锁。解锁时在常规签名外提供每对哈希中另一侧的值，钱包必须保有完整有序公钥。每个普通 ForkID 解锁比全公钥格式增加 8,192 字节。
- `locking_script(public_key, transaction=False)` 只检查指定摘要，供测试签名算法使用。接收真实付款使用有交易绑定的模板。

钱包先认证入金交易的 outpoint、金额和所需确认，再将已批准的输出、找零和手续费交给 `sign_payment` 或 `sign_spend`。外部签名器接收 32 字节摘要并返回原始签名，必须先持久化一次性密钥的占用状态。找零使用新密钥，恢复旧备份时停用使用状态不确定的密钥。参考 `OneTimeSigner` 只记录当前进程中的状态。 [协议规范](docs/spec.md) · [钱包安全要求](docs/security.md) · [参考实现](reference/payment.py)

## 复现方法

在仓库根目录使用独立 Python 环境。向量密钥为公开测试数据。

```sh
python -m pip install -r projects/lamport-ots/reference/requirements.txt
python -m unittest discover -s projects/lamport-ots/reference -p test_lamport.py -v
bash projects/lamport-ots/reference/verify.sh
```

macOS 可使用 `bash projects/lamport-ots/reference/verify_apple.sh`。单项尺寸见[测量清单](template/measurement.json)，验收范围见[用例矩阵](docs/acceptance.md)和[验证记录](docs/validation.md)，可用[十二种模式向量](template/universal-vectors.json)核对编码。

可用同一项目的测量脚本复现组件尺寸和公钥承诺候选的交易成本。

```sh
python projects/lamport-ots/reference/measure.py --benchmark
python projects/lamport-ots/reference/measure.py --committed-costs
```

## 输入输出取舍

公钥承诺每个输出省 15,034 字节，但普通解锁每个输入多 8,192 字节。ForkID ALL 两进两出由 62,392 降到 48,708 字节，新增输入却由 8,400 增到 16,592 字节。OTDA ALL 的原文会随输出尺寸增大，因此缩短输出也会缩短每个输入。若入金和退出采用不同费率，应分别计算两阶段，而不是只看锁与解锁的字节和。

## 完整交易与栈测量

下表取自提交 `beeb4dd` 的确定性交易夹具，所有完整输入由 BSV Node 1.2.3 和项目固定的 chain-gang 版本验证。节点通过显式提供上一输出执行脚本，默认策略下的入内存池及出块另有复放记录。脚本和交易以字节计。表中按索引列出每个输入或输出的大小，`× n` 表示同样大小重复 n 次。栈数据取第一个输入的成功路径。主栈项数、备用栈项数和两栈载荷分别记录各自达到的峰值，单位为项或字节。栈开销由开发求值器估计，统计栈上数据的字节数。

| 模板与模式 | 输入×输出 | 上一输出锁定 | 解锁 | 新输出锁定 | 整笔 | 主栈 / 备用栈 | 两栈载荷 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `full-key` · `0x41` | 2×2 | 22,780 × 2 | 8,357 × 2 | 22,780 × 2 | 62,392 | 7 / 34 | 8,515 |
| `full-key` · `0x61` | 2×2 | 22,780 × 2 | 53,879 × 2 | 22,780 × 2 | 153,436 | 7 / 34 | 99,556 |
| `committed-key` · `0x41` | 2×2 | 7,746 × 2 | 16,549 × 2 | 7,746 × 2 | 48,708 | 7 / 34 | 16,707 |
| `committed-key` · `0x61` | 2×2 | 7,746 × 2 | 32,003 × 2 | 7,746 × 2 | 79,616 | 7 / 34 | 47,611 |

## 输入输出边际与生命周期

每个边际单元格为 **新增整笔字节（输出锁定脚本 / 输入解锁脚本 / 其余序列化字节）**。其余字节包括金额、outpoint、序列号和 CompactSize 等字段。上一输出脚本列用于说明被花费的锁，该脚本长度属于此前创建 UTXO 的交易。生命周期从原生 P2PKH 入金开始，以原生 P2PKH 退出，周转列在两者之间增加一次项目内转付。

| 模板与模式 | 加输入后 | 加输入成本 | 加输出后 | 加输出成本 | 入金与直接退出 | 含一次周转 |
| --- | --- | --- | --- | --- | --- | --- |
| `full-key` · `0x41` | 3×2 | 8,400 (0 / 8,357 / 43) | 2×3 | 22,791 (22,780 / 0 / 11) | 62,617 | 125,010 |
| `full-key` · `0x61` | 3×2 | 54,045 (0 / 54,002 / 43) | 2×3 | 68,381 (22,780 / 45,586 / 15) | 62,631 | 216,068 |
| `committed-key` · `0x41` | 3×2 | 16,592 (0 / 16,549 / 43) | 2×3 | 7,757 (7,746 / 0 / 11) | 48,933 | 97,641 |
| `committed-key` · `0x61` | 3×2 | 32,169 (0 / 32,126 / 43) | 2×3 | 23,271 (7,746 / 15,514 / 11) | 48,948 | 128,564 |

[统一测量入口与复现口径](../../docs/benchmark.zh-CN.md)
