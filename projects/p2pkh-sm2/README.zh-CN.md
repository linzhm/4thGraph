# P2PKH-SM2 v1.0.0

[English](README.md) · [BSV Script Lab](../../README.zh-CN.md)

付款方可以用收款人未压缩 SM2 公钥的 HASH160 锁定一笔 BSV 输出。花费时，
持有人公开该公钥，并为当前输入提供一次 SM2 签名。Bitcoin Script 使用 SM3 计算 SM2
用户标识摘要 ZA 和消息摘要，然后验证 SM2 签名，并通过 PUSHTX 和原生
`OP_CHECKSIG` 将授权绑定到实际的花费交易。

## 开发入口

[协议规范](docs/developer.zh-CN.md#protocol) · [安全分析](docs/developer.zh-CN.md#security) · [验证与测量](docs/developer.zh-CN.md#validation) · [SDK 与参考接口](docs/developer.zh-CN.md#sdk)

## 发布基线

v1.0.0 是首个公开版本。脚本生成器和 Python 钱包使用模板编号 `1` 标识本版的
基准锁定脚本。

| 项目 | 取值 |
| --- | --- |
| 收款标识 | 65 字节公钥 `04 \|\| X_BE32 \|\| Y_BE32` 的 HASH160 |
| SM2 用户标识 | 固定的 ASCII 字符串 `1234567812345678` |
| 锁定脚本 | 144,925 字节 |
| 解锁脚本 | ForkID 为 291 字节，无配对输出的 OTDA SINGLE 为 294 字节，其他 OTDA 模式的长度随交易变化 |
| 解锁栈 | 签名预映像、未压缩公钥，以及 64 字节的 `r \|\| s` 签名 |
| 交易签名模式 | ForkID 和 Chronicle OTDA 均支持 ALL、NONE、SINGLE，每种模式均可选用 ANYONECANPAY |

[发布页](https://github.com/linzhm/bsv-script-lab/releases/tag/p2pkh-sm2-v1.0.0)
对应的源码包含[模板布局](template/layout.json)、[SM2 标准向量](template/sm2-standard.json)、
[完整付款向量](template/spend-all.json)和 [16 个签名预映像](template/sighash-modes.json)。

## 生成锁定脚本

在仓库根目录运行下面的命令。示例中的哈希仅供演示，创建实际输出时请换成收款人的
公钥 HASH160。

```sh
cd projects/p2pkh-sm2/reference
python3 generate_lock.py --owner-hash160 000102030405060708090a0b0c0d0e0f10111213
python3 generate_lock.py --owner-hash160 000102030405060708090a0b0c0d0e0f10111213 --format raw > scriptPubKey.bin
```

第一条命令输出模板编号、脚本字节数和该收款脚本的 SHA-256。第二条命令将锁定脚本的
原始字节写入文件。也可以通过 `--public-key` 提供未压缩的收款公钥，生成器会先验证
公钥，再计算其哈希。

## 签署并验证付款

单输入付款可用 `sign_payment`，它使用 ForkID ALL（`0x41`）。交易已构造好时，
可用 `sign_input` 为不同输入分别选择签名模式。签署 OTDA 输入时，请提供实际花费时
的 Chronicle 激活状态。钱包调用外部签名器，验证返回的签名后再构造解锁脚本。
[协议规范](docs/spec.zh-CN.md) · [Python 参考实现与节点测试](reference/README.zh-CN.md)

钱包适配器支持 GB/T 35275-2026 `SignedData` 中由单个签名者直接对消息生成的
SM2 签名。封装的外层 `SignedData.version = 1`，内层 `SignerInfo.version = 2`。
Python 和 Rust 命令行签名器均使用专用测试密钥。[SignedData 接入指南](reference/README.zh-CN.md#signeddata-付款接入)
· [Python 测试签名器](reference/interop/python-signer/README.zh-CN.md)
· [Rust 测试签名器](reference/interop/rust-signer/README.zh-CN.md)

## 开发复现与输入输出分析

在仓库根目录启动 Linux 节点复放。测试环境需要 Python 3.12、Rust 和支持 SM2、SM3 的 OpenSSL。

```sh
cd projects/p2pkh-sm2/reference
python -m pip install -r requirements.txt
bash verify.sh
```

接入 SignedData 的钱包通过可信配置固定签名公钥和完整的 DER 颁发者与序列号。签名前核对被花费的 outpoint、金额、确认数和收款锁。国标封装由链下适配器处理，解锁脚本带的是提取后的原始签名。

两进两出时，ForkID ALL 的解锁为 291 字节。OTDA ALL 把两个完整输出放进每个输入的签名原文，解锁增至 290,109 字节。新增第三个输出时，除 144,925 字节的输出锁本身外，两个已有输入的解锁也会变长。下表分项列出这些开销。项目发布版本是 `v1.0.0`，付款模板编号为 `1`。交易版本和 SignedData 的两层版本值分别按各自的编码规则处理。

## 完整交易与栈测量

下表取自提交 `beeb4dd` 的确定性交易夹具，所有完整输入由 BSV Node 1.2.3 和项目固定的 chain-gang 版本验证。节点通过显式提供上一输出执行脚本，默认策略下的入内存池及出块另有复放记录。脚本和交易以字节计。表中按索引列出每个输入或输出的大小，`× n` 表示同样大小重复 n 次。栈数据取第一个输入的成功路径。主栈项数、备用栈项数和两栈载荷分别记录各自达到的峰值，单位为项或字节。栈开销由开发求值器估计，统计栈上数据的字节数。

| 模板与模式 | 输入×输出 | 上一输出锁定 | 解锁 | 新输出锁定 | 整笔 | 主栈 / 备用栈 | 两栈载荷 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `v1.0.0` · `0x41` | 2×2 | 144,925 × 2 | 291 × 2 | 144,925 × 2 | 290,554 | 122 / 133 | 4,147 |
| `v1.0.0` · `0x61` | 2×2 | 144,925 × 2 | 290,109 × 2 | 144,925 × 2 | 870,194 | 122 / 133 | 580,080 |

## 输入输出边际与生命周期

每个边际单元格为 **新增整笔字节（输出锁定脚本 / 输入解锁脚本 / 其余序列化字节）**。其余字节包括金额、outpoint、序列号和 CompactSize 等字段。上一输出脚本列用于说明被花费的锁，该脚本长度属于此前创建 UTXO 的交易。生命周期从原生 P2PKH 入金开始，以原生 P2PKH 退出，周转列在两者之间增加一次项目内转付。

| 模板与模式 | 加输入后 | 加输入成本 | 加输出后 | 加输出成本 | 入金与直接退出 | 含一次周转 |
| --- | --- | --- | --- | --- | --- | --- |
| `v1.0.0` · `0x41` | 3×2 | 334 (0 / 291 / 43) | 2×3 | 144,938 (144,925 / 0 / 13) | 290,780 | 581,334 |
| `v1.0.0` · `0x61` | 3×2 | 290,277 (0 / 290,232 / 45) | 2×3 | 434,814 (144,925 / 289,876 / 13) | 290,794 | 1,160,988 |

[统一测量入口与复现口径](../../shared/benchmark.zh-CN.md)
