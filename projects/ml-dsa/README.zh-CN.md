# 纯模式 ML-DSA-44

[English](README.md) · [4thGraph](../../README.zh-CN.md) · [项目目录](../README.zh-CN.md) · [版本](versions/index.json)

## 开发入口

**[钱包 SDK 快速上手](docs/sdk.zh-CN.md#quickstart)** · [统一钱包 SDK](../../sdk/README.zh-CN.md#quickstart)

用原始 ML-DSA-44 公钥生成付款锁，再用纯模式和空上下文签署付款消息。

[协议规范](docs/developer.zh-CN.md#protocol) · [安全分析](docs/developer.zh-CN.md#security) · [复现与验证](#复现方法) · [交易成本](#完整交易与栈测量)

当前版本为 v0.6.0，采用 FIPS 204 纯模式编码。公钥为 1,312 字节，签名为 2,420 字节。编译器预计算与公钥相关的矩阵和多项式，执行时校验签名编码、响应范数和提示值，再计算挑战和验证方程。 [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)

| 入口 | 用途 |
|---|---|
| `fips204.verify(public_key, message, signature, context=...)` | Python 纯模式消息验签 |
| `script.verify_message_script(public_key, message_bytes, context=...)` | 生成固定公钥、消息长度和上下文的消息验签脚本 |
| `script.locking_script(public_key)` | 生成绑定当前花费输入的付款锁 |

挑战采样遵循 FIPS 204 附录 C 表 3 的 221 字节上限，耗尽时验签失败。消息验签和付款绑定分别有测试向量。 [采样实现](reference/challenge_script.py) · [确定性向量](versions/v0.1.0/deterministic.json)

## 使用场景与取舍

验证 FIPS 204 签名器互操作，或测量大脚本资源限制时，可以评估纯模式 ML‑DSA‑44。实验可先跑独立的算法合规向量，再用相同类型的公钥及专用付款签名器验证付款封装。付款封装把 32 字节的付款消息交给纯模式 ML‑DSA‑44，使用空上下文。公钥和签名校验、交易绑定，以及节点接收策略应各自核验。[复现与验证](#复现方法)

实测夹具的固定公钥付款锁约为 322 kB。如果计划对这种输出实际入金，应先在目标节点或矿工环境验证脚本大小、整笔交易上限及验证策略。[出块测量方法](../../docs/benchmark.zh-CN.md)

## 开发和钱包接入

1. 调用 `locking_script(public_key)` 生成新版付款输出，并保存经认证的完整公钥。钱包可用同一公钥识别和花费此前六版锁。用 `locking_script(public_key, legacy=True)` 可复现最初的 v0.1.0 锁。签名前核对 outpoint、金额、确认数和预期收款输出。
2. 单输入付款用 `sign_payment`，已排好输入输出的交易逐输入调用 `sign_spend`。付款支持 BIP143 与 Chronicle OTDA 的十二种签名模式，无配对 OTDA SINGLE 使用伴随绑定。
3. 外部签名器把收到的 32 字节作为纯模式的消息，使用空上下文并返回 2,420 字节签名。钱包验签后构造解锁脚本。通用消息验签可另行指定上下文和消息长度。

[付款接口](reference/payment.py) · [付款验收矩阵](reference/payment-acceptance.md) · [验证绑定实现](../../src/fourthgraph/bsv/pushtx.py)

## 复现方法

在仓库根目录使用 Python 3.12 和 OpenSSL 3.5 或以上版本。OpenSSL 夹具使用公开测试种子。

```sh
python -m pip install -r tools/requirements-chronicle.txt
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

## 脚本大小

下表用相同夹具比较编译后的 Script 字节数。公钥内容会使锁的长度略有变化，OTDA ALL 的每个输入还会携带整笔交易的输出。

| 组件 | PR #68 基线 | 紧凑版 `879b52c` | v0.2.0 | v0.3.0 | v0.4.0 | v0.5.0 | v0.6.0 |
|---|---:|---:|---:|---:|---:|---:|---:|
| 固定公钥验证方程 | 500,794 | 310,198 | 257,122 | 137,874 | 137,874 | 137,874 | 124,849 |
| 签名解码 | 62,723 | 46,392 | 36,152 | 36,152 | 28,224 | 28,224 | 28,224 |
| SampleInBall（221 字节预算） | 70,229 | 63,701 | 61,101 | 61,101 | 61,101 | 45,211 | 43,512 |
| 应用提示并编码高位 | 89,687 | 66,135 | 66,135 | 66,135 | 31,087 | 31,087 | 31,087 |
| 独立 Keccak-f[1600] 置换（小端 lane） | 25,097 | 21,833 | 20,533 | 20,533 | 20,533 | 12,588 | 12,588 |
| SHAKE256（832 字节输入、32 字节输出） | 176,542 | 153,694 | 144,594 | 144,594 | 144,594 | 88,979 | 81,821 |
| 当前输入绑定 | 718 | 718 | 718 | 718 | 718 | 506 | 506 |
| 完整付款锁 | 926,403 | 663,284 | 586,981 | 467,733 | 424,757 | 345,095 | **322,447** |
| 单输入 BIP143 ALL 解锁 | 2,588 | 2,588 | 2,588 | 2,588 | 2,588 | 2,588 | 2,588 |

Forth 付款入口用上游 `889ff6e` 以 `stack` 模式编译。v0.5.0 按五个 lane 一行执行 Keccak 的 θ 和 χ。θ 用位掩码隔离跨 lane 的移位，ρ 和 π 按单个 lane 执行。付款锁的十次置换共省 79,450 字节，共享紧凑输入绑定再省 212 字节。[Forth 入口](reference/payment-lock.fth) · [v0.4.0 测量](versions/v0.4.0/measurements.json) · [v0.5.0 测量](versions/v0.5.0/measurements.json)

v0.6.0 把每组四个系数保留在栈顶，连续执行相邻两层 NTT 蝶形。根据变换的幅值上界选取模数的整数倍作为偏移，使每个打包系数的符号位保持为零。这两项共省 13,025 字节。SHAKE 在多次置换之间保持内部 lane 为大端，只在吸收和挤出时转换字节序，再省 9,623 字节。[v0.6.0 测量](versions/v0.6.0/measurements.json)

## 完整交易与栈测量

BSV Node 1.2.3 和项目固定的 chain-gang 版本用显式提供的上一输出验证了新版锁的完整交易。表中大小以字节计，按输入和输出顺序排列，`× n` 表示相同大小重复 n 次。开发求值器缺少所需的比较指令，暂无栈峰值。v0.5.0 的两进两出夹具在 BIP143 ALL 和 OTDA ALL 下分别为 695,482 和 2,075,766 字节。

| 模板与模式 | 输入×输出 | 上一输出锁定 | 解锁 | 新输出锁定 | 整笔 | 主栈 / 备用栈 | 两栈载荷 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `pure-ml-dsa-44` · `0x41` | 2×2 | 322,445 / 322,447 | 2,588 × 2 | 322,444 × 2 | 650,186 | — / — | — |
| `pure-ml-dsa-44` · `0x61` | 2×2 | 322,451 / 322,443 | 647,436 × 2 | 322,437 / 322,443 | 1,939,878 | — / — | — |

## 输入输出边际与生命周期

每个边际单元格为 **新增整笔字节（输出锁定脚本 / 输入解锁脚本 / 其余序列化字节）**。其余字节包括金额、outpoint、序列号和 CompactSize 等字段。上一输出脚本列用于说明被花费的锁，该脚本长度属于此前创建 UTXO 的交易。生命周期从原生 P2PKH 入金开始，以原生 P2PKH 退出，周转列在两者之间增加一次项目内转付。

| 模板与模式 | 加输入后 | 加输入成本 | 加输出后 | 加输出成本 | 入金与直接退出 | 含一次周转 |
| --- | --- | --- | --- | --- | --- | --- |
| `pure-ml-dsa-44` · `0x41` | 3×2 | 2,635 (4 / 2,588 / 43) | 2×3 | 322,451 (322,438 / 0 / 13) | 650,419 | 1,300,598 |
| `pure-ml-dsa-44` · `0x61` | 3×2 | 647,588 (-4 / 647,547 / 45) | 2×3 | 967,359 (322,440 / 644,906 / 13) | 650,431 | 2,590,301 |

[统一测量入口与复现口径](../../docs/benchmark.zh-CN.md)
