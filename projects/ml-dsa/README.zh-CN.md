<!-- Generated from manifest.yaml with Copier. -->

# 纯模式 ML-DSA-44 v0.1.0

[English](README.md) · [4thGraph](../../README.zh-CN.md) · [项目目录](../README.zh-CN.md) · [版本](versions/index.json)

## 开发入口

**[钱包 SDK 快速上手](docs/sdk.zh-CN.md#quickstart)** · [统一钱包 SDK](../../sdk/README.zh-CN.md#quickstart)

用原始 ML-DSA-44 公钥生成付款锁，再用纯模式和空上下文签署付款消息。

[协议](docs/developer.zh-CN.md) · [算法与执行](#算法与执行) · [复现方法](#复现方法) · [完整交易与栈测量](#完整交易与栈测量)

| 入口 | 用途 |
| --- | --- |
| `fips204.verify(public_key, message, signature, context=...)` | Python 纯模式消息验签 |
| `script.verify_message_script(public_key, message_bytes, context=...)` | 生成固定公钥、消息长度和上下文的消息验签脚本 |
| `script.locking_script(public_key)` | 生成绑定当前花费输入的付款锁 |

## 使用场景与取舍

验证 FIPS 204 签名器互操作，或测量大脚本资源限制时，可以评估纯模式 ML‑DSA‑44。实验可先跑独立的算法合规向量，再用相同类型的公钥及专用付款签名器验证付款封装。付款封装把 32 字节的付款消息交给纯模式 ML‑DSA‑44，使用空上下文。公钥和签名校验、交易绑定，以及节点接收策略应各自核验。[复现与验证](#复现方法)

实测夹具的固定公钥付款锁约为 926 kB。如果计划对这种输出实际入金，应先在目标节点或矿工环境验证脚本大小、整笔交易上限及验证策略。[出块测量方法](../../docs/benchmark.zh-CN.md)

## 算法与执行

[协议规范](docs/developer.zh-CN.md#protocol) · [安全分析](docs/developer.zh-CN.md#security) · [复现与验证](#复现方法) · [交易成本](#完整交易与栈测量)

ML-DSA-44 是 v0.1.0 开发基线，采用 FIPS 204 纯模式编码。公钥为 1,312 字节，签名为 2,420 字节。编译器预计算与公钥相关的矩阵和多项式，执行时校验签名编码、响应范数和提示值，再计算挑战和验证方程。 [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)

挑战采样遵循 FIPS 204 附录 C 表 3 的 221 字节上限，耗尽时验签失败。消息验签和付款绑定分别有测试向量。 [采样实现](reference/challenge_script.py) · [确定性向量](versions/v0.1.0/deterministic.json)

## 复现方法

从仓库根目录使用 Python 3.12、OpenSSL 3.5 或更新版本及固定的 Chronicle 依赖。

```sh
python -m pip install -r tools/requirements-chronicle.txt
```

```sh
PYTHONPATH=src:. python -m unittest discover -s projects/ml-dsa/reference -p test_signature_script.py
PYTHONPATH=src:. bash tools/verify_node.sh --profile raised -- python -m unittest discover -s projects/ml-dsa/reference -p test_payment.py
```

在仓库根目录使用 Python 3.12 和 OpenSSL 3.5 或以上版本。OpenSSL 夹具使用公开测试种子。

```sh
python -m unittest discover -s projects/ml-dsa/reference -p test_mldsa.py -v
python projects/ml-dsa/reference/check_chain_gang.py -v
python projects/ml-dsa/reference/test_shake_script.py -v
python projects/ml-dsa/reference/test_signature_script.py -v
python projects/ml-dsa/reference/test_challenge_script.py -v
python projects/ml-dsa/reference/test_payment.py -v
```

测试覆盖 80 条 Wycheproof 标准验签用例、15 条 NIST ACVP 外部纯模式向量及 640 个付款判定组合。详见[统一节点回归](../../docs/chronicle-regression.md)。Linux 节点重放使用统一入口的脚本策略配置。

将三个环境变量设为本地语料文件后，可以通过以下命令单独重放。若系统的 OpenSSL 版本较低，可以用
`ML_DSA_OPENSSL` 指向支持 ML-DSA 的可执行文件。

```sh
python projects/ml-dsa/reference/check_wycheproof.py "$WYCHEPROOF_VECTORS"
PYTHONPATH=src:. python projects/ml-dsa/reference/check_acvp.py "$ACVP_PROMPT" "$ACVP_EXPECTED"
```

[固定 Wycheproof 语料](https://github.com/C2SP/wycheproof/blob/8e7fa6f87e6993d7b613cf48b46512a32df8084a/testvectors_v1/mldsa_44_standard_verify_test.json) · [NIST ACVP 验签语料](https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ML-DSA-sigVer-FIPS204)

## 脚本尺寸

### 输入输出取舍

单独的确定性样本的付款锁是 926,403 字节，BIP143 ALL 解锁是 2,588 字节。公钥的固定值参与脚本编译，不同交易样本的锁定长度可略有变化。两进两出时，OTDA ALL 每个输入都带本笔的输出字节，整笔达到 5,563,725 字节。有符号余数 NTT 实验把固定公钥验证方程从 500,794 缩到 452,154 字节。这个值是运算组件的尺寸，付款脚本的实测值见下表。

| 运算组件 | 规范实现 | 有符号余数实验 |
|---|---:|---:|
| NTT | 46,134 字节 | 38,454 字节 |
| 逆 NTT | 43,500 字节 | 40,940 字节 |
| 固定公钥验证方程 | 500,794 字节 | 452,154 字节 |

## 开发和钱包接入

1. 调用 `locking_script(public_key)` 生成付款输出。钱包保存经认证的完整公钥，并用该公钥重新生成锁来核对实际上一输出。签名前核对 outpoint、金额、确认数和预期收款输出。
2. 单输入付款用 `sign_payment`，已排好输入输出的交易逐输入调用 `sign_spend`。付款支持 BIP143 与 Chronicle OTDA 的十二种签名模式，无配对 OTDA SINGLE 使用伴随绑定。
3. 外部签名器把收到的 32 字节作为纯模式的消息，使用空上下文并返回 2,420 字节签名。钱包验签后构造解锁脚本。通用消息验签可另行指定上下文和消息长度。

[付款接口](reference/payment.py) · [付款验收矩阵](reference/payment-acceptance.md) · [验证绑定实现](../../src/fourthgraph/bsv/pushtx.py)

## 完整交易与栈测量

下表取自提交 `beeb4dd` 的确定性交易夹具，所有完整输入由 BSV Node 1.2.3 和项目固定的 chain-gang 版本验证。节点通过显式提供上一输出执行脚本，默认策略下的入内存池及出块另有复放记录。脚本和交易以字节计。表中按索引列出每个输入或输出的大小，`× n` 表示同样大小重复 n 次。栈数据取第一个输入的成功路径。主栈项数、备用栈项数和两栈载荷分别记录各自达到的峰值，单位为项或字节。栈开销由开发求值器估计，统计栈上数据的字节数。ML-DSA-44 的两行暂无栈值，求值器在 `OP_GREATERTHANOREQUAL` 处停止。

| 模板与模式 | 输入×输出 | 上一输出锁定 | 解锁 | 新输出锁定 | 整笔 | 主栈 / 备用栈 | 两栈载荷 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `pure-ml-dsa-44` · `0x41` | 2×2 | 926,412 × 2 | 2,588 × 2 | 926,410 / 926,414 | 1,858,122 | — / — | — |
| `pure-ml-dsa-44` · `0x61` | 2×2 | 926,421 / 926,413 | 1,855,385 × 2 | 926,416 / 926,413 | 5,563,725 | — / — | — |

## 输入输出边际与生命周期

每个边际单元格为 **新增整笔字节（输出锁定脚本 / 输入解锁脚本 / 其余序列化字节）**。其余字节包括金额、outpoint、序列号和 CompactSize 等字段。上一输出脚本列用于说明被花费的锁，该脚本长度属于此前创建 UTXO 的交易。生命周期从原生 P2PKH 入金开始，以原生 P2PKH 退出，周转列在两者之间增加一次项目内转付。

| 模板与模式 | 加输入后 | 加输入成本 | 加输出后 | 加输出成本 | 入金与直接退出 | 含一次周转 |
| --- | --- | --- | --- | --- | --- | --- |
| `pure-ml-dsa-44` · `0x41` | 3×2 | 2,627 (-4 / 2,588 / 43) | 2×3 | 926,418 (926,405 / 0 / 13) | 1,858,346 | 3,716,464 |
| `pure-ml-dsa-44` · `0x61` | 3×2 | 1,855,545 (-2 / 1,855,502 / 45) | 2×3 | 2,779,266 (926,409 / 1,852,844 / 13) | 1,858,363 | 7,422,076 |

[统一测量入口与复现口径](../../docs/benchmark.zh-CN.md)
